// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_url_requests.h"

#include <stdexcept>
#include <thread>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{
  SynchronousURLRequestTracker::SynchronousURLRequestTracker(bool verbose) :
    URLRequestTracker(verbose)
  {}

  URLRequestSetId SynchronousURLRequestTracker::submit(
    std::vector<URLRequest>&& rs)
  {
    URLRequestSetId id = request_sets.size();

    // Set up
    request_sets.emplace(id, rs);
    response_sets.emplace(id, std::vector<URLResponse>(rs.size()));

    // Start
    auto rsit = request_sets.find(id);
    for (size_t i = 0; i < rsit->second.size(); i++)
    {
      auto& request = rsit->second.at(i);
      response_sets[id][i] = request.execute(verbose);

      if (response_sets[id][i].code != 200)
        throw std::runtime_error(
          fmt::format("unexpected HTTP status {}", response_sets[id][i].code));
    }

    return id;
  }

  bool SynchronousURLRequestTracker::is_complete(
    const URLRequestSetId& id) const
  {
    return true;
  }

  std::vector<URLResponse> SynchronousURLRequestTracker::collect(
    const URLRequestSetId& id)
  {
    auto rit = response_sets.find(id);
    if (rit == response_sets.end())
      throw std::runtime_error("no such response set");
    std::vector<URLResponse> r;
    rit->second.swap(r);
    response_sets.erase(rit);
    return r;
  }
}