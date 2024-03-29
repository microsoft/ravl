// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "crypto_options.h"

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

    /// Check that the root CA certificate has the platform manufacturer's
    /// public key (intended for debugging only)
    bool check_root_certificate_manufacturer_key = true;

    /// Optional URL template for cached Intel SGX endorsements (DCAP)
    std::optional<std::string> sgx_endorsement_cache_url_template =
      std::nullopt;

    /// Optional URL template for cached AMD SEV/SNP endorsements
    std::optional<std::string> sev_snp_endorsement_cache_url_template =
      std::nullopt;

    /// Timeout for HTTP requests (in seconds; 0 = no limit)
    size_t http_timeout = 90;

    /// Maximum number of attempts for HTTP requests
    size_t http_max_attempts = 5;

    /// Accept historical attestations where SVNs may be smaller than for fresh
    /// attestations
    bool historical = false;

    /// Partial verification: only critical fields in the attestation (e.g. when
    /// TCB info and others have been verified previously)
    bool partial = false;
  };
}
