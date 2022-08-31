// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ravl
{

  enum class Source : uint8_t
  {
    SGX = 0,
    SEV_SNP = 1,
    OPEN_ENCLAVE = 2
  };

  struct Options
  {
    bool ignore_time = false;
    std::optional<time_t> verification_time = std::nullopt;
    bool fresh_endorsements = false;
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

    virtual bool verify(const Options& opt);

    operator std::string() const;
  };

} // namespace ravl
