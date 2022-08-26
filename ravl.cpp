// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl.h"

#include <nlohmann/json.hpp>

#ifdef HAVE_SGX_SDK
#  include "ravl_sgx.h"
#endif

#ifdef HAVE_OPEN_ENCLAVE
#  include "ravl_oe.h"
#  ifndef HAVE_SGX_SDK
#    define USE_OE_VERIFIER
#  endif
#endif

#ifdef HAVE_SEV_SNP
#  include "ravl_sev_snp.h"
#endif

#ifdef HAVE_OPENSSL
#  include <openssl/evp.h>
#else
#  error "TODO: base64 encoding, etc, without OpenSSL"
#endif

using namespace nlohmann;

namespace ravl
{
  NLOHMANN_JSON_SERIALIZE_ENUM(
    Source,
    {
      {Source::SGX, "sgx"},
      {Source::SEV_SNP, "sevsnp"},
      {Source::OPEN_ENCLAVE, "openenclave"},
    })

  std::string to_base64(const uint8_t* data, size_t size)
  {
    unsigned char buf[2 * size];
    int n = EVP_EncodeBlock(buf, data, size);
    return std::string((char*)buf, n);
  }

  std::string to_base64(const std::vector<uint8_t>& bytes)
  {
    return to_base64(bytes.data(), bytes.size());
  }

  std::vector<uint8_t> from_base64(const std::string& b64)
  {
    unsigned char buf[2 * b64.size()];
    int n = EVP_DecodeBlock(buf, (unsigned char*)b64.data(), b64.size());
    return std::vector<uint8_t>(buf, buf + n);
  }

  Attestation::Attestation(const std::string& json_string)
  {
    json j = json::parse(json_string);
    source = j.at("source").get<Source>();
    evidence = from_base64(j.at("evidence").get<std::string>());
    endorsements = from_base64(j.at("endorsements").get<std::string>());
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
    j["endorsements"] = to_base64(endorsements);
    return j.dump();
  }

  bool Attestation::verify(const Options& options)
  {
    switch (source)
    {
      case Source::SGX:
#ifdef HAVE_SGX_SDK
        return ravl::sgx::verify(*this, options);
#else
        throw std::runtime_error(
          "ravl was compiled without support for SGX support");
#endif
        break;
      case Source::SEV_SNP:
#ifdef HAVE_SEV_SNP
        return ravl::sev_snp::verify(*this, options);
#else
        throw std::runtime_error(
          "ravl was compiled without support for SEV/SNP support");
#endif
        break;
      case Source::OPEN_ENCLAVE:
#ifdef HAVE_OPEN_ENCLAVE
        return ravl::oe::verify(*this, options);
#else
        throw std::runtime_error(
          "ravl was compiled without support for Open Enclave support");
#endif
        break;
      default:
        throw std::runtime_error(
          "unsupported attestation source '" +
          std::to_string((unsigned)source) + "'");
        break;
    };

    return false;
  }
};