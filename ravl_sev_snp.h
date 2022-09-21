// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "ravl.h"
#include "ravl_url_requests.h"

#include <memory>
#include <optional>

namespace ravl
{
  class URLRequestTracker;

  namespace sev_snp
  {
    std::optional<URLRequestSetId> prepare_endorsements(
      const Attestation& a,
      const Options& options,
      std::shared_ptr<URLRequestTracker> request_tracker);

    bool verify(
      const Attestation& attestation,
      const Options& options,
      const std::vector<URLResponse>& url_response_set);
  }
}
