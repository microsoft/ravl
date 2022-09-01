// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_requests.h"

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
  class ThreadedRequestTracker : public RequestTracker
  {
  public:
    ThreadedRequestTracker();
    virtual ~ThreadedRequestTracker() = default;

    virtual bool when_completed(
      std::vector<Request>&& rs,
      std::function<bool(std::vector<Response>&&)>&& f) override;

    virtual void wait(const RequestSetId& id) override;

  protected:
    class TrackedRequest
    {
    public:
      TrackedRequest(Request&& req) : request(req) {}
      virtual ~TrackedRequest() = default;

      Request request;
      Response response;
      std::shared_ptr<std::thread> t;
    };

    std::mutex mtx;
    std::unordered_map<RequestSetId, std::vector<TrackedRequest>> request_sets;
    std::unordered_map<RequestSetId, std::vector<Response>> response_sets;
  };
}
