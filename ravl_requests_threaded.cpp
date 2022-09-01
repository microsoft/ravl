// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_requests_threaded.h"

namespace ravl
{
  ThreadedRequestTracker::ThreadedRequestTracker() : RequestTracker() {}

  bool ThreadedRequestTracker::when_completed(
    std::vector<Request>&& rs, std::function<bool(std::vector<Response>&&)>&& f)
  {
    ThreadedRequestTracker::RequestSetId id = request_sets.size();
    std::vector<Response> responses;

    try
    {
      std::vector<TrackedRequest>* treq_set = nullptr;

      {
        std::lock_guard<std::mutex> guard(mtx);

        // Set up
        auto it_ok = request_sets.emplace(id, std::vector<TrackedRequest>());
        if (!it_ok.second)
          throw std::bad_alloc();

        treq_set = &it_ok.first->second;
        for (Request& r : rs)
          treq_set->emplace_back(std::move(r));

        auto rit_ok =
          response_sets.emplace(id, std::vector<Response>(rs.size()));
        if (!rit_ok.second)
          throw std::bad_alloc();

        // Start
        for (size_t i = 0; i < treq_set->size(); i++)
        {
          TrackedRequest& treq = treq_set->at(i);
          treq.t = std::make_shared<std::thread>(
            [&treq]() { treq.response = treq.request(); });
        }
      }

      // Wait for all threads to join
      wait(id);

      {
        std::lock_guard<std::mutex> guard(mtx);

        auto rit = response_sets.find(id);
        for (auto treq : *treq_set)
          responses.emplace_back(std::move(treq.response));
        response_sets.erase(rit);
      }

      // Consume responses
      return f(std::move(responses));
    }
    catch (const std::exception& ex)
    {
      response_sets.erase(id);
      return false;
    }
  }

  void ThreadedRequestTracker::wait(const RequestSetId& id)
  {
    auto& rs = request_sets.at(id);
    for (auto& r : rs)
    {
      if (r.t)
        r.t->join();
    }
  }
}
