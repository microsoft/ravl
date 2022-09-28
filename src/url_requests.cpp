// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/url_requests.h"

#include <chrono>
#include <stdexcept>
#include <thread>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

namespace ravl
{
  SynchronousURLRequestTracker::SynchronousURLRequestTracker(
    size_t request_timeout, bool verbose) :
    URLRequestTracker(request_timeout, verbose)
  {}

  URLRequestSetId SynchronousURLRequestTracker::submit(
    URLRequests&& rs, std::function<void(URLResponses&&)>&& callback)
  {
    URLRequestSetId id = request_sets.size();
    size_t sz = rs.size();

    request_sets.emplace(id, std::move(rs));
    auto [rit, ok] = response_sets.emplace(id, URLResponses(sz));

    if (!ok)
      throw std::bad_alloc();

    auto rsit = request_sets.find(id);
    for (size_t i = 0; i < rsit->second.size(); i++)
    {
      auto& request = rsit->second.at(i);
      URLResponse response = request.execute(request_timeout, verbose);
      response_sets[id][i] = response;

      if (response.status != 200)
        throw std::runtime_error(
          fmt::format("unexpected HTTP status {}", response.status));
    }

    URLResponses r;
    r.swap(rit->second);
    callback(std::move(r));
    response_sets.erase(rit);

    return id;
  }

  bool SynchronousURLRequestTracker::is_complete(
    const URLRequestSetId& id) const
  {
    return true;
  }
}