// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_attestation.h"
#include "ravl_url_requests.h"

#include <memory>
#include <optional>

namespace ravl
{
  class URLRequestTracker;

  namespace sgx
  {
    class Attestation : public ravl::Attestation
    {
    public:
      Attestation(
        const std::vector<uint8_t>& evidence,
        const std::vector<uint8_t>& endorsements) :
        ravl::Attestation(Source::SGX, evidence, endorsements)
      {}

      virtual ~Attestation() = default;

      virtual std::optional<URLRequestSetId> prepare_endorsements(
        const Options& options,
        std::function<void(size_t)> callback,
        std::shared_ptr<URLRequestTracker> request_tracker) const override;

      virtual bool verify(
        const Options& options,
        const std::optional<std::vector<URLResponse>>& url_response_set)
        const override;
    };
  }
}
