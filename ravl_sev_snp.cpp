// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_sev_snp.h"

#include "ravl.h"

#include <stdexcept>

namespace ravl
{
  namespace sev_snp
  {
    bool verify(
      const Attestation& a,
      const Options& opt,
      std::shared_ptr<RequestTracker> tracker)
    {
      throw std::runtime_error("not implemented yet");
    }
  }
}