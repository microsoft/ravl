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

  Attestation::Attestation(const std::string& json_string)
  {
    json j = json::parse(json_string);
    source = j.at("source").get<Source>();
    evidence = from_base64(j.at("evidence").get<std::string>());
    if (j.contains("endorsements"))
    {
      auto e = j.at("endorsements").get<std::string>();
      endorsements = from_base64(e);
    }
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

  bool Attestation::verify(
    const Options& options,
    std::shared_ptr<URLRequestTracker> url_request_tracker)
  {
    if (!url_request_tracker)
      url_request_tracker = std::make_shared<SynchronousURLRequestTracker>();

    auto id =
      attestation_request_tracker.submit(options, *this, url_request_tracker);

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
};