// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "crypto_options.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace ravl
{
  struct Options
  {
    /// Certificate validation options
    crypto::CertificateValidationOptions certificate_validation;

    /// Downloads new endorsements
    bool fresh_endorsements = false;

    /// Downloads a new root CA certificate
    bool fresh_root_ca_certificate = false;

    /// Sets the root CA certificate to use (overrides fresh_endorsements and
    /// fresh_root_ca_certificate)
    std::optional<std::vector<uint8_t>> root_ca_certificate_pem = std::nullopt;
  };
}
