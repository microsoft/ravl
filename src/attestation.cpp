// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/attestation.h"

#include "ravl/crypto.h"
#include "ravl/oe.h"
#include "ravl/sev_snp.h"
#include "ravl/sgx.h"

#include <nlohmann/json.hpp>

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

  std::string to_string(Source src)
  {
    json j;
    to_json(j, src);
    return j.dump();
  }

  static nlohmann::json attestation_json(
    const Attestation& a, bool base64 = true)
  {
    nlohmann::json j;
    j["source"] = a.source;
    if (base64)
      j["evidence"] = to_base64(a.evidence);
    else
      j["evidence"] = a.evidence;
    if (!a.endorsements.empty())
    {
      if (base64)
        j["endorsements"] = to_base64(a.endorsements);
      else
        j["endorsements"] = a.endorsements;
    }
    return j;
  }

  Attestation::operator std::string() const
  {
    return attestation_json(*this).dump();
  }

  static std::shared_ptr<Attestation> parse(const json& j, bool base64 = true)
  {
    try
    {
      std::shared_ptr<Attestation> r = nullptr;
      auto source = j.at("source").get<Source>();
      std::vector<uint8_t> evidence;
      if (base64)
        evidence = from_base64(j.at("evidence").get<std::string>());
      else
        evidence = j.at("evidence").get<std::vector<uint8_t>>();
      std::vector<uint8_t> endorsements;

      if (j.contains("endorsements"))
      {
        if (base64)
          endorsements = from_base64(j.at("endorsements").get<std::string>());
        else
          endorsements = j.at("endorsements").get<std::vector<uint8_t>>();
      }

      switch (source)
      {
        case Source::SGX:
          r = std::make_shared<sgx::Attestation>(evidence, endorsements);
          break;
        case Source::SEV_SNP:
          r = std::make_shared<sev_snp::Attestation>(evidence, endorsements);
          break;
        case Source::OPEN_ENCLAVE:
          r = std::make_shared<oe::Attestation>(evidence, endorsements);
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

  std::shared_ptr<Attestation> parse_attestation(const std::string& json_string)
  {
    return parse(json::parse(json_string));
  }

  std::vector<uint8_t> Attestation::cbor()
  {
    auto aj = attestation_json(*this, false);
    return nlohmann::json::to_cbor(aj);
  }

  std::shared_ptr<Attestation> parse_attestation_cbor(
    const std::vector<uint8_t>& cbor)
  {
    return parse(nlohmann::json::from_cbor(cbor), false);
  }
}