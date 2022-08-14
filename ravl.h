// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <stdexcept>
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

  class Attestation
  {
  public:
    Attestation(const std::string& json_string);

    virtual ~Attestation() = default;

    Source source;
    std::vector<uint8_t> evidence;
    std::vector<uint8_t> endorsements;

    virtual bool verify();
  };

} // namespace ravl
