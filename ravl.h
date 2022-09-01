// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_options.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ravl
{
  class RequestTracker;

  enum class Source : uint8_t
  {
    SGX = 0,
    SEV_SNP = 1,
    OPEN_ENCLAVE = 2
  };

  class Attestation
  {
  public:
    Attestation(const std::string& json_string);

    Attestation(
      Source source,
      const std::vector<uint8_t>& evidence,
      const std::vector<uint8_t>& endorsements);

    virtual ~Attestation() = default;

    Source source;
    std::vector<uint8_t> evidence;
    std::vector<uint8_t> endorsements;

    virtual bool verify(
      const Options& options,
      std::shared_ptr<RequestTracker> request_tracker = nullptr);

    operator std::string() const;
  };

} // namespace ravl
