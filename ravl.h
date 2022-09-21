// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl_attestation.h"
#include "ravl_options.h"

#include <memory>

namespace ravl
{
  /// Synchronous verification of attestations (including endorsement download).
  bool verify(
    std::shared_ptr<const Attestation> attestation,
    const Options& options,
    std::shared_ptr<URLRequestTracker> request_tracker = nullptr);
}
