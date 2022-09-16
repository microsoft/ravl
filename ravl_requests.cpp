// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_requests.h"

#include <stdexcept>
#include <thread>
#include <vector>

namespace ravl
{
  SynchronousRequestTracker::SynchronousRequestTracker(bool verbose) :
    RequestTracker(verbose)
  {}

  bool SynchronousRequestTracker::when_completed(
    std::vector<Request>&& rs, std::function<bool(std::vector<Response>&&)>&& f)
  {
    SynchronousRequestTracker::RequestSetId id = request_sets.size();
    std::vector<Response> responses;

    try
    {
      // Set up
      request_sets.emplace(id, rs);
      response_sets.emplace(id, std::vector<Response>(rs.size()));

      // Start
      auto rsit = request_sets.find(id);
      for (size_t i = 0; i < rsit->second.size(); i++)
      {
        auto& req = rsit->second.at(i);
        auto& rsps = response_sets[id][i];
        rsps = req.execute(verbose);
      }

      wait(id);

      auto rit = response_sets.find(id);
      rit->second.swap(responses);
      response_sets.erase(rit);
    }
    catch (const std::exception& ex)
    {
      return false;
    }

    // Consume responses
    return f(std::move(responses));
  }

  void SynchronousRequestTracker::wait(const RequestSetId& id)
  {
    // Synchronous in this version, so no waiting here.
  }
}