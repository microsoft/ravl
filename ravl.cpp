// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl.h"

#include <nlohmann/json.hpp>

#ifdef HAVE_OPEN_ENCLAVE
#  include "ravl_oe.h"
#endif

#ifdef HAVE_OPENSSL
#  include <openssl/evp.h>
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
  }

  bool Attestation::verify()
  {
    switch (source)
    {
      case Source::SGX:
        throw std::runtime_error("not implemented yet");
        break;
      case Source::SEV_SNP:
        throw std::runtime_error("not implemented yet");
        break;
      case Source::OPEN_ENCLAVE:
#ifdef HAVE_OPEN_ENCLAVE
        return ravl::oe::verify(*this);
#else
        throw std::runtime_error(
          "ravl was compiled without support for Open Enclave attestation");
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