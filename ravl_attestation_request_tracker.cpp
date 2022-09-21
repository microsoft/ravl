// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_attestation_request_tracker.h"

#include "ravl.h"
#include "ravl_sgx.h"
#include "ravl_util.h"

#ifdef HAVE_OPEN_ENCLAVE
#  include "ravl_oe.h"
#endif

#ifdef HAVE_SEV_SNP
#  include "ravl_sev_snp.h"
#endif

#include <nlohmann/json.hpp>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace nlohmann;

namespace ravl
{

  AttestationRequestTracker::RequestID AttestationRequestTracker::submit(
    const Options& options,
    std::shared_ptr<const Attestation> attestation,
    std::shared_ptr<URLRequestTracker> request_tracker)
  {
    auto request_id = next_request_id++;

    requests[request_id] = {
      RequestState::SUBMITTED, options, attestation, false, 0, request_tracker};

    return request_id;
  }

  AttestationRequestTracker::Result AttestationRequestTracker::result(
    RequestID id) const
  {
    auto rit = requests.find(id);
    if (rit == requests.end())
      throw std::runtime_error("no such attestation verification request");
    if (rit->second.state != FINISHED)
      throw std::runtime_error("attestation verification request not finished");
    return rit->second.result;
  }

  void AttestationRequestTracker::erase(RequestID id)
  {
    auto rit = requests.find(id);
    if (rit != requests.end())
      requests.erase(rit);
  }

  AttestationRequestTracker::RequestID AttestationRequestTracker::advance(
    RequestID id, Request& req)
  {
    switch (req.state)
    {
      case ERROR:
        throw std::runtime_error("verification request failed");
      case SUBMITTED:
        if (!prepare_endorsements(req))
          req.state = HAVE_ENDORSEMENTS;
        else
          req.state = WAITING_FOR_ENDORSEMENTS;
        break;
      case WAITING_FOR_ENDORSEMENTS:
        if (
          !req.request_set_id ||
          req.url_request_tracker->is_complete(*req.request_set_id))
          req.state = HAVE_ENDORSEMENTS;
        break;
      case HAVE_ENDORSEMENTS:
        verify(req);
        req.state = FINISHED;
        break;
      case FINISHED:
      default:
        break;
    }

    return req.state;
  }

  AttestationRequestTracker::RequestID AttestationRequestTracker::advance(
    RequestID id)
  {
    auto rit = requests.find(id);
    return advance(id, rit->second);
  }

  bool AttestationRequestTracker::prepare_endorsements(Request& request)
  {
    if (!request.attestation)
      throw std::runtime_error("no attestation to verify");

    const auto& attestation = *request.attestation;
    const auto& options = request.options;
    auto request_tracker = request.url_request_tracker;

    if (options.verbosity > 0)
    {
      json j;
      to_json(j, attestation.source);
      log(fmt::format("* Verifying attestation from {}", j.dump()));

      log("- Options", 2);
      if (options.fresh_endorsements)
        log("- Fresh endorsements", 4);
      if (options.fresh_root_ca_certificate)
        log("- Fresh root CA certificate", 4);
      if (options.root_ca_certificate)
        log("- Custom root CA certificate", 4);
      if (
        options.certificate_verification.ignore_time ||
        options.certificate_verification.verification_time)
      {
        log("- Certificate verification", 4);
        if (options.certificate_verification.ignore_time)
          log("- Ignore certificate times", 6);
        if (options.certificate_verification.verification_time)
          log("- Use custom certificate verification time", 6);
      }
    }

    try
    {
      request.request_set_id =
        request.attestation->prepare_endorsements(options, request_tracker);
    }
    catch (std::exception& ex)
    {
      if (options.verbosity > 0)
        log(fmt::format("  - verification failed: {}", ex.what()));
      throw std::runtime_error(
        fmt::format("attestation verification failed: {}", ex.what()));
    }

    return request.request_set_id.has_value();
  }

  void AttestationRequestTracker::verify(Request& request)
  {
    if (!request.attestation)
      throw std::runtime_error("no attestation to verify");

    auto& attestation = *request.attestation;
    const auto& options = request.options;
    auto request_tracker = request.url_request_tracker;

    bool r = false;

    std::vector<URLResponse> responses;

    if (request.request_set_id)
      responses = request.url_request_tracker->collect(*request.request_set_id);

    try
    {
      r = attestation.verify(options, responses);
    }
    catch (std::exception& ex)
    {
      if (options.verbosity > 0)
        log(fmt::format("  - verification failed: {}", ex.what()));
      throw std::runtime_error(
        fmt::format("attestation verification failed: {}", ex.what()));
    }

    if (options.verbosity > 0)
      log(fmt::format("  - verification successful"));

    request.result = r;
  }
}