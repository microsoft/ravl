// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_url_requests_threaded.h"

namespace ravl
{
  ThreadedURLRequestTracker::ThreadedURLRequestTracker(bool verbose) :
    URLRequestTracker(verbose)
  {}

  URLRequestSetId ThreadedURLRequestTracker::submit(
    std::vector<URLRequest>&& rs)
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

    auto rit_ok =
      response_sets.emplace(id, std::vector<URLResponse>(rs.size()));
    if (!rit_ok.second)
      throw std::bad_alloc();

    // Start
    for (size_t i = 0; i < treq_set->size(); i++)
    {
      TrackedRequest& treq = treq_set->at(i);
      treq.t =
        std::make_shared<std::thread>([this, &treq, i, id, v = verbose]() {
          std::vector<URLResponse>* response_set = nullptr;
          {
            std::lock_guard<std::mutex> guard(mtx);
            auto rit = response_sets.find(id);
            if (rit == response_sets.end())
              throw std::runtime_error("invalid url request id");
            response_set = &rit->second;
          }
          (*response_set)[i] = treq.request.execute(v);
        });
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

    for (auto& r : *request_set)
      if (r.t)
        r.t->join();
    return true;
  }

  std::vector<URLResponse> ThreadedURLRequestTracker::collect(
    const URLRequestSetId& id)
  {
    std::lock_guard<std::mutex> guard(mtx);
    auto rit = response_sets.find(id);
    if (rit == response_sets.end())
      throw std::runtime_error("no such response set");
    std::vector<URLResponse> r;
    r.swap(rit->second);
    response_sets.erase(id);
    return r;
  }
}
