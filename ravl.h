// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_attestation_request_tracker.h"
#include "ravl_options.h"

#include <algorithm>
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

    Attestation(const std::string& json_string);

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

    virtual bool verify(
      const Options& options,
      std::shared_ptr<URLRequestTracker> request_tracker = nullptr);

    operator std::string() const;

    Attestation& operator=(const Attestation& other) = default;
  };

} // namespace ravl
