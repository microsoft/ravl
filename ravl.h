// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_attestation.h"
#include "ravl_options.h"

#include <map>
#include <memory>
#include <mutex>

namespace ravl
{
  /// Tracker for asynchronous attestation verification
  class AttestationRequestTracker
  {
  public:
    AttestationRequestTracker();

    virtual ~AttestationRequestTracker();

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
      std::shared_ptr<URLRequestTracker> url_request_tracker = nullptr);

    RequestID submit(
      const Options& options,
      std::shared_ptr<const Attestation> attestation,
      std::function<void(RequestID)> callback,
      std::shared_ptr<URLRequestTracker> url_request_tracker = nullptr);

    RequestState state(RequestID id) const;
    RequestID advance(RequestID id);
    bool finished(RequestID id) const;
    Result result(RequestID id) const;
    void erase(RequestID id);

  protected:
    void* implementation;
  };

  /// Synchronized verification (including endorsement download).
  bool verify(
    std::shared_ptr<const Attestation> attestation,
    const Options& options,
    std::shared_ptr<URLRequestTracker> request_tracker = nullptr);

  /// Entirely synchronous verification (including endorsement download).
  bool verify_sync(
    std::shared_ptr<const Attestation> attestation, const Options& options);
}
