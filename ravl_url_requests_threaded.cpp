// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_url_requests_threaded.h"

namespace ravl
{
  ThreadedURLRequestTracker::ThreadedURLRequestTracker(bool verbose) :
    URLRequestTracker(verbose)
  {}

  URLRequestSetId ThreadedURLRequestTracker::submit(
    std::vector<URLRequest>&& rs, std::function<void(Responses&&)> callback)
  {
    URLRequestSetId id = request_sets.size();
    std::vector<TrackedRequest>* treq_set = nullptr;

    if (rs.empty())
      throw std::runtime_error("url request set is empty");

    std::lock_guard<std::mutex> guard(mtx);

    // Set up
    auto it_ok = request_sets.emplace(id, std::vector<TrackedRequest>());
    if (!it_ok.second)
      throw std::bad_alloc();

    treq_set = &it_ok.first->second;
    for (URLRequest& r : rs)
      treq_set->emplace_back(std::move(r));

    // Start
    for (size_t i = 0; i < treq_set->size(); i++)
    {
      TrackedRequest& treq = treq_set->at(i);
      treq.t = std::make_shared<std::thread>(
        [&treq, v = verbose]() { treq.request.start(v); });
    }

    return id;
  }

  bool ThreadedURLRequestTracker::is_complete(const URLRequestSetId& id) const
  {
    const std::vector<TrackedRequest>* request_set = nullptr;
    {
      std::lock_guard<std::mutex> guard(mtx);
      auto rit = request_sets.find(id);
      if (rit == request_sets.end())
        throw std::runtime_error("request set not found");
      request_set = &rit->second;
    }

    for (const auto& r : *request_set)
      if (!r.request.is_complete())
        return false;

    return true;
  }

  std::vector<URLResponse> ThreadedURLRequestTracker::collect(
    const URLRequestSetId& id)
  {
    std::vector<TrackedRequest>* request_set = nullptr;
    std::vector<URLResponse> responses;

    {
      std::lock_guard<std::mutex> guard(mtx);
      auto rit = request_sets.find(id);
      if (rit == request_sets.end())
        throw std::runtime_error("request set not found");
      request_set = &rit->second;
    }

    for (size_t i = 0; i < request_set->size(); i++)
    {
      auto& r = (*request_set)[i];

      if (r.t)
        r.t->join();

      if (!r.request.is_complete())
        throw std::runtime_error("not complete");

      auto rsp = r.request.collect();
      if (!rsp)
        throw std::runtime_error("missing url response");

      responses.emplace_back(std::move(*rsp));
    }

    return responses;
  }
}
