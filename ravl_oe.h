// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl.h"
#include "ravl_sgx.h"
#include "ravl_url_requests.h"

#include <memory>

namespace ravl
{
  class URLRequestTracker;

  namespace oe
  {
    class Claims : public ravl::Claims
    {
    public:
      Claims() : ravl::Claims(Source::OPEN_ENCLAVE) {}

      virtual ~Claims() = default;

      std::shared_ptr<sgx::Claims> sgx_claims;
      std::vector<uint8_t> custom_claims;
    };

    class Attestation : public ravl::Attestation
    {
    public:
      Attestation(
        const std::vector<uint8_t>& evidence,
        const std::vector<uint8_t>& endorsements) :
        ravl::Attestation(Source::OPEN_ENCLAVE, evidence, endorsements)
      {}

      virtual std::optional<URLRequests> prepare_endorsements(
        const Options& options,
        std::shared_ptr<URLRequestTracker> request_tracker =
          nullptr) const override;

      virtual std::shared_ptr<ravl::Claims> verify(
        const Options& options,
        const std::optional<URLResponses>& url_response_set) const override;

    protected:
      mutable std::shared_ptr<ravl::Attestation> sgx_attestation;
      mutable std::vector<uint8_t> custom_claims;
    };
  }
}
