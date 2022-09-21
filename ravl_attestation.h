// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_options.h"
#include "ravl_url_requests.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ravl
{
  class URLRequestTracker;

  enum class Source : uint8_t
  {
    SGX = 0,
    SEV_SNP = 1,
    OPEN_ENCLAVE = 2,
    UNKNOWN = UINT8_MAX
  };

  class Attestation
  {
  public:
    Attestation() : source(Source::UNKNOWN) {}

    Attestation(
      Source source,
      const std::vector<uint8_t>& evidence,
      const std::vector<uint8_t>& endorsements);

    Attestation(const Attestation&) = default;
    Attestation(Attestation&&) = default;

    virtual ~Attestation() {}

    Source source;
    std::vector<uint8_t> evidence;
    std::vector<uint8_t> endorsements;

    /// Function to prepare network requests for endorsements
    virtual std::optional<URLRequestSetId> prepare_endorsements(
      const Options& options,
      std::shared_ptr<URLRequestTracker> request_tracker) const = 0;

    /// Function to verify the attestation (with all endorsements present either
    /// in the attestation or in the url_response_set).
    virtual bool verify(
      const Options& options,
      const std::vector<URLResponse>& url_response_set) const = 0;

    operator std::string() const;

    Attestation& operator=(const Attestation& other) = default;
  };

  std::shared_ptr<Attestation> parse_attestation(
    const std::string& json_string);
}
