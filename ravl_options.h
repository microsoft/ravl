// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_crypto_options.h"

#include <cstdint>
#include <optional>
#include <string>

namespace ravl
{
  struct Options
  {
    /// Verbosity
    uint8_t verbosity = 0;

    /// Certificate validation options
    crypto::CertificateValidationOptions certificate_verification;

    /// Downloads new endorsements
    bool fresh_endorsements = false;

    /// Downloads a new root CA certificate
    bool fresh_root_ca_certificate = false;

    /// Optional root CA certificate (overrides fresh_endorsements and
    /// fresh_root_ca_certificate; PEM format)
    std::optional<std::string> root_ca_certificate = std::nullopt;

    /// Optional URL template for cached endorsements
    std::optional<std::string> endorsement_cache_url_template = std::nullopt;
  };
}
