// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_oe.h"

#include "openenclave/bits/result.h"

#include <iostream>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <stdexcept>

static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

namespace ravl
{
  namespace oe
  {
    bool verify(const Attestation& a)
    {
      if (oe_verifier_initialize() != OE_OK)
        throw std::runtime_error("failed to initialize Open Enclave verifier");

      std::vector<oe_policy_t> policies;

      oe_claim_t* claims = nullptr;
      size_t claims_size = 0;

      oe_result_t r = oe_verify_evidence(
        &sgx_remote_uuid,
        a.evidence.data(),
        a.evidence.size(),
        a.endorsements.size() > 0 ? a.endorsements.data() : nullptr,
        a.endorsements.size(),
        policies.data(),
        policies.size(),
        &claims,
        &claims_size);

      if (oe_free_claims(claims, claims_size) != OE_OK)
        throw std::runtime_error("failed to free Open Enclave claims");

      if (oe_verifier_shutdown() != OE_OK)
        throw std::runtime_error("failed to initialize Open Enclave verifier");

      return r == OE_OK;
    }
  }
}
