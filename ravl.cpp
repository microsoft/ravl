// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl.h"

#include "ravl_crypto.h"
#include "ravl_sgx.h"
#include "ravl_url_requests.h"
#include "ravl_util.h"

#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <ratio>
#include <thread>

#ifdef HAVE_OPEN_ENCLAVE
#  include "ravl_oe.h"
#endif

#ifdef HAVE_SEV_SNP
#  include "ravl_sev_snp.h"
#endif

#ifdef HAVE_OPENSSL
#  include <openssl/evp.h>
#else
#  error "TODO: base64 encoding, etc, without OpenSSL"
#endif

#define FMT_HEADER_ONLY
#include <fmt/format.h>

using namespace nlohmann;

namespace ravl
{
  using namespace crypto;

  NLOHMANN_JSON_SERIALIZE_ENUM(
    Source,
    {
      {Source::SGX, "sgx"},
      {Source::SEV_SNP, "sevsnp"},
      {Source::OPEN_ENCLAVE, "openenclave"},
    })

  static AttestationRequestTracker attestation_request_tracker;

  std::shared_ptr<Attestation> parse_attestation(const std::string& json_string)
  {
    json j = json::parse(json_string);

    try
    {
      std::shared_ptr<Attestation> r = nullptr;
      auto source = j.at("source").get<Source>();
      auto evidence = from_base64(j.at("evidence").get<std::string>());
      std::vector<uint8_t> endorsements;

      if (j.contains("endorsements"))
      {
        auto e = j.at("endorsements").get<std::string>();
        endorsements = from_base64(e);
      }

      switch (source)
      {
        case Source::SGX:
#ifdef HAVE_SGX
          r = std::make_shared<sgx::Attestation>(evidence, endorsements);
#else
          throw std::runtime_error(
            "ravl was compiled without support for SGX attestations");
#endif
          break;
        case Source::SEV_SNP:
#ifdef HAVE_SEV_SNP
          r = std::make_shared<sev_snp::Attestation>(evidence, endorsements);
#else
          throw std::runtime_error(
            "ravl was compiled without support for SEV/SNP attestations");
#endif
          break;
        case Source::OPEN_ENCLAVE:
#ifdef HAVE_OPEN_ENCLAVE
          r = std::make_shared<oe::Attestation>(evidence, endorsements);
#else
          throw std::runtime_error(
            "ravl was compiled without support for Open Enclave attestations");
#endif
          break;
        default:
          throw std::runtime_error(
            "unsupported attestation source '" +
            std::to_string((unsigned)source) + "'");
          break;
      };

      return r;
    }
    catch (std::exception& ex)
    {
      throw std::runtime_error(
        fmt::format("attestation parsing failed: {}", ex.what()));
    }

    return nullptr;
  }

  Attestation::Attestation(
    Source source,
    const std::vector<uint8_t>& evidence,
    const std::vector<uint8_t>& endorsements) :
    source(source),
    evidence(evidence),
    endorsements(endorsements)
  {}

  Attestation::operator std::string() const
  {
    nlohmann::json j;
    j["source"] = source;
    j["evidence"] = to_base64(evidence);
    if (!endorsements.empty())
    {
      j["endorsements"] = to_base64(endorsements);
    }
    return j.dump();
  }

  class AttestationRequestTrackerImpl
  {
  public:
    using RequestID = AttestationRequestTracker::RequestID;
    using RequestState = AttestationRequestTracker::RequestState;
    using Result = AttestationRequestTracker::Result;

    struct Request
    {
      AttestationRequestTracker::RequestState state = RequestState::ERROR;
      Options options;
      std::shared_ptr<const Attestation> attestation;
      AttestationRequestTracker::Result result = false;
      std::optional<URLRequestSetId> request_set_id = std::nullopt;
      std::shared_ptr<URLRequestTracker> url_request_tracker;
    };

    std::mutex requests_mtx;
    std::map<AttestationRequestTracker::RequestID, Request> requests;
    std::shared_ptr<URLRequestTracker> url_request_tracker;
    AttestationRequestTracker::RequestID next_request_id = 0;

    RequestID submit(
      const Options& options,
      std::shared_ptr<const Attestation> attestation,
      std::shared_ptr<URLRequestTracker> request_tracker)
    {
      auto request_id = next_request_id++;

      requests[request_id] = {
        RequestState::SUBMITTED,
        options,
        attestation,
        false,
        0,
        request_tracker};

      return request_id;
    }

    RequestState state(RequestID id) const
    {
      auto rit = requests.find(id);
      if (rit == requests.end())
        return RequestState::ERROR;
      else
        return rit->second.state;
    }

    RequestID advance(RequestID id, Request& req)
    {
      switch (req.state)
      {
        case RequestState::ERROR:
          throw std::runtime_error("verification request failed");
        case RequestState::SUBMITTED:
          if (!prepare_endorsements(req))
            req.state = RequestState::HAVE_ENDORSEMENTS;
          else
            req.state = RequestState::WAITING_FOR_ENDORSEMENTS;
          break;
        case RequestState::WAITING_FOR_ENDORSEMENTS:
          if (
            !req.request_set_id ||
            req.url_request_tracker->is_complete(*req.request_set_id))
            req.state = RequestState::HAVE_ENDORSEMENTS;
          break;
        case RequestState::HAVE_ENDORSEMENTS:
          verify(req);
          req.state = RequestState::FINISHED;
          break;
        case RequestState::FINISHED:
          break;
        default:
          throw std::runtime_error("unexpected request state");
      }

      return req.state;
    }

    bool finished(RequestID id) const
    {
      return state(id) == RequestState::FINISHED;
    }

    Result result(RequestID id) const
    {
      auto rit = requests.find(id);
      if (rit == requests.end())
        throw std::runtime_error("no such attestation verification request");
      if (rit->second.state != RequestState::FINISHED)
        throw std::runtime_error(
          "attestation verification request not finished");
      return rit->second.result;
    }

    void erase(RequestID id)
    {
      auto rit = requests.find(id);
      if (rit != requests.end())
        requests.erase(rit);
    }

    AttestationRequestTracker::RequestID advance(RequestID id)
    {
      auto rit = requests.find(id);
      return advance(id, rit->second);
    }

    bool prepare_endorsements(Request& request)
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

    void verify(Request& request)
    {
      if (!request.attestation)
        throw std::runtime_error("no attestation to verify");

      auto& attestation = *request.attestation;
      const auto& options = request.options;
      auto request_tracker = request.url_request_tracker;

      bool r = false;

      std::vector<URLResponse> responses;

      if (request.request_set_id)
        responses =
          request.url_request_tracker->collect(*request.request_set_id);

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
  };

  AttestationRequestTracker::AttestationRequestTracker()
  {
    implementation = new AttestationRequestTrackerImpl();
  }

  AttestationRequestTracker::~AttestationRequestTracker()
  {
    delete static_cast<AttestationRequestTrackerImpl*>(implementation);
  }

  AttestationRequestTracker::RequestID AttestationRequestTracker::submit(
    const Options& options,
    std::shared_ptr<const Attestation> attestation,
    std::shared_ptr<URLRequestTracker> url_request_tracker)
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->submit(options, attestation, url_request_tracker);
  }

  AttestationRequestTracker::RequestState AttestationRequestTracker::state(
    RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->state(id);
  }

  bool AttestationRequestTracker::finished(RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->finished(id);
  }

  AttestationRequestTracker::Result AttestationRequestTracker::result(
    RequestID id) const
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->result(id);
  }

  void AttestationRequestTracker::erase(RequestID id)
  {
    static_cast<AttestationRequestTrackerImpl*>(implementation)->erase(id);
  }

  AttestationRequestTracker::RequestID AttestationRequestTracker::advance(
    RequestID id)
  {
    return static_cast<AttestationRequestTrackerImpl*>(implementation)
      ->advance(id);
  }

  bool verify(
    std::shared_ptr<const Attestation> attestation,
    const Options& options,
    std::shared_ptr<URLRequestTracker> url_request_tracker)
  {
#ifndef HAVE_SGX
    if (attestation.source == Source::SGX)
      throw std::runtime_error(
        "ravl was compiled without support for SGX attestations");
#endif
#ifndef HAVE_SEV_SNP
    if (attestation.source == Source::SEV_SNP)
      throw std::runtime_error(
        "ravl was compiled without support for SEV/SNP attestations");
#endif
#ifndef HAVE_OPEN_ENCLAVE
    if (attestation.source == Source::OPEN_ENCLAVE)
      throw std::runtime_error(
        "ravl was compiled without support for Open Enclave attestations");
#endif

    if (!url_request_tracker)
      url_request_tracker = std::make_shared<SynchronousURLRequestTracker>();

    auto id = attestation_request_tracker.submit(
      options, attestation, url_request_tracker);

    auto state = attestation_request_tracker.advance(id);
    while (state != AttestationRequestTracker::FINISHED &&
           state != AttestationRequestTracker::ERROR)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      state = attestation_request_tracker.advance(id);
    }

    if (state == AttestationRequestTracker::ERROR)
      throw std::runtime_error("error");

    auto r = attestation_request_tracker.result(id);
    attestation_request_tracker.erase(id);
    return r;
  }

  bool verify_sync(
    std::shared_ptr<const Attestation> attestation, const Options& options)
  {
#ifndef HAVE_SGX
    if (attestation.source == Source::SGX)
      throw std::runtime_error(
        "ravl was compiled without support for SGX attestations");
#endif
#ifndef HAVE_SEV_SNP
    if (attestation.source == Source::SEV_SNP)
      throw std::runtime_error(
        "ravl was compiled without support for SEV/SNP attestations");
#endif
#ifndef HAVE_OPEN_ENCLAVE
    if (attestation.source == Source::OPEN_ENCLAVE)
      throw std::runtime_error(
        "ravl was compiled without support for Open Enclave attestations");
#endif

    auto url_request_tracker = std::make_shared<SynchronousURLRequestTracker>();
    auto rs = attestation->prepare_endorsements(options, url_request_tracker);
    std::optional<std::vector<URLResponse>> url_response_set = std::nullopt;
    if (rs)
      url_response_set = url_request_tracker->collect(*rs);
    return attestation->verify(options, url_response_set);
  }
}