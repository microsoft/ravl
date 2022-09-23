// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl.h"
#include "ravl_url_requests.h"

#include <memory>
#include <optional>

namespace ravl
{
  class URLRequestTracker;

  namespace sev_snp
  {
    class Attestation : public ravl::Attestation
    {
    public:
      Attestation(
        const std::vector<uint8_t>& evidence,
        const std::vector<uint8_t>& endorsements) :
        ravl::Attestation(Source::SEV_SNP, evidence, endorsements)
      {}

      virtual std::optional<URLRequests> prepare_endorsements(
        const Options& options,
        std::shared_ptr<URLRequestTracker> request_tracker) const override;

      virtual bool verify(
        const Options& options,
        const std::optional<URLResponses>& url_response_set) const override;
    };
  }
}
