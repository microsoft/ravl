// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_url_requests.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ravl
{
  class ThreadedURLRequestTracker : public URLRequestTracker
  {
  public:
    ThreadedURLRequestTracker(bool verbose = false);
    virtual ~ThreadedURLRequestTracker() = default;

    virtual URLRequestSetId submit(std::vector<URLRequest>&& rs) override;

    virtual bool is_complete(const URLRequestSetId& id) const override;

    virtual std::vector<URLResponse> collect(
      const URLRequestSetId& id) override;

  protected:
    class TrackedRequest
    {
    public:
      TrackedRequest(URLRequest&& req) : request(req) {}
      virtual ~TrackedRequest() = default;

      URLRequest request;
      std::shared_ptr<std::thread> t;
    };

    typedef std::unordered_map<URLRequestSetId, std::vector<TrackedRequest>>
      RequestSets;
    typedef std::unordered_map<URLRequestSetId, std::vector<URLResponse>>
      ResponseSets;

    mutable std::mutex mtx;
    RequestSets request_sets;
    ResponseSets response_sets;
  };
}
