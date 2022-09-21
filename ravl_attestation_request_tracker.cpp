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
    const Attestation& attestation,
    std::shared_ptr<URLRequestTracker> request_tracker)
  {
    auto request_id = next_request_id++;

    requests[request_id] = {
      RequestState::SUBMITTED,
      options,
      std::make_shared<Attestation>(attestation),
      false,
      0,
      request_tracker};

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

    request.request_set_id = std::nullopt;

    try
    {
      switch (attestation.source)
      {
        case Source::SGX:
#ifdef HAVE_SGX
          request.request_set_id = ravl::sgx::prepare_endorsements(
            attestation, options, request_tracker);
#else
          throw std::runtime_error(
            "ravl was compiled without support for SGX attestations");
#endif
          break;
        case Source::SEV_SNP:
#ifdef HAVE_SEV_SNP
          request.request_set_id = ravl::sev_snp::prepare_endorsements(
            attestation, options, request_tracker);
#else
          throw std::runtime_error(
            "ravl was compiled without support for SEV/SNP attestations");
#endif
          break;
        case Source::OPEN_ENCLAVE:
#ifdef HAVE_OPEN_ENCLAVE
          request.request_set_id = ravl::oe::prepare_endorsements(
            attestation, options, request_tracker);
#else
          throw std::runtime_error(
            "ravl was compiled without support for Open Enclave attestations");
#endif
          break;
        default:
          throw std::runtime_error(
            "unsupported attestation source '" +
            std::to_string((unsigned)attestation.source) + "'");
          break;
      };
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

    const auto& attestation = *request.attestation;
    const auto& options = request.options;
    auto request_tracker = request.url_request_tracker;

    bool r = false;

    std::vector<URLResponse> responses;

    if (request.request_set_id)
      responses = request.url_request_tracker->collect(*request.request_set_id);

    try
    {
      switch (attestation.source)
      {
        case Source::SGX:
#ifdef HAVE_SGX
          r = ravl::sgx::verify(attestation, options, responses);
#else
          throw std::runtime_error("ravl was compiled without SGX support");
#endif
          break;
        case Source::SEV_SNP:
#ifdef HAVE_SEV_SNP
          r = ravl::sev_snp::verify(attestation, options, responses);
#else
          throw std::runtime_error("ravl was compiled without SEV/SNP support");
#endif
          break;
        case Source::OPEN_ENCLAVE:
#ifdef HAVE_OPEN_ENCLAVE
          r = ravl::oe::verify(attestation, options, responses);
#else
          throw std::runtime_error(
            "ravl was compiled without Open Enclave support");
#endif
          break;
        default:
          throw std::runtime_error(
            "unsupported attestation source '" +
            std::to_string((unsigned)attestation.source) + "'");
          break;
      };
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