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
}