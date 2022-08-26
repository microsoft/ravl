// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl.h"

namespace ravl
{
  namespace sgx
  {
    bool verify(const Attestation& a, const Options& opt);
  }
}
