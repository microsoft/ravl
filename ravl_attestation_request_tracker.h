// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_options.h"
#include "ravl_url_requests.h"

#include <map>
#include <mutex>
#include <string>

namespace ravl
{
  class Attestation;

  class AttestationRequestTracker
  {
  public:
    AttestationRequestTracker() = default;
    virtual ~AttestationRequestTracker() = default;

    typedef size_t RequestID;
    typedef bool Result;

    enum RequestState
    {
      SUBMITTED = 0,
      WAITING_FOR_ENDORSEMENTS,
      HAVE_ENDORSEMENTS,
      FINISHED,
      ERROR
    };

    RequestID submit(
      const Options& options,
      std::shared_ptr<const Attestation> attestation,
      std::shared_ptr<URLRequestTracker> request_tracker = nullptr);

    RequestState state(RequestID id) const
    {
      auto rit = requests.find(id);
      if (rit == requests.end())
        return ERROR;
      else
        return rit->second.state;
    }

    Result result(RequestID id) const;

    void erase(RequestID id);

    RequestID advance(RequestID id);

  protected:
    struct Request
    {
      RequestState state = ERROR;
      Options options;
      std::shared_ptr<const Attestation> attestation;
      Result result = false;
      std::optional<URLRequestSetId> request_set_id = std::nullopt;
      std::shared_ptr<URLRequestTracker> url_request_tracker;
    };

    std::mutex requests_mtx;
    std::map<RequestID, Request> requests;
    std::shared_ptr<URLRequestTracker> request_tracker;
    RequestID next_request_id = 0;

    bool prepare_endorsements(Request& request);
    void verify(Request& request);

    RequestID advance(RequestID id, Request& req);
  };
}
