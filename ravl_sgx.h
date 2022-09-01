// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl.h"

#include <memory>

namespace ravl
{
  class RequestTracker;

  namespace sgx
  {
    bool verify(
      const Attestation& a,
      const Options& opt,
      std::shared_ptr<RequestTracker> = nullptr);
  }
}
