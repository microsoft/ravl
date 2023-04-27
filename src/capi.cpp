// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl/capi.h"

#include "ravl/attestation.h"
#include "ravl/options.h"

#include <stddef.h>
#include <stdint.h>
#include <string>

std::string last_exception_message_string;
const char* last_exception_message = NULL;

ravl::Options cpp_options(const ravl_options_t* options)
{
  ravl::Options r;
  if (options)
  {
    r.certificate_verification.ignore_time =
      options->certificate_verification_.ignore_time;
    if (options->certificate_verification_.verification_time)
      r.certificate_verification.verification_time =
        *options->certificate_verification_.verification_time;
    r.fresh_endorsements = options->fresh_endorsements;
    r.fresh_root_ca_certificate = options->fresh_root_ca_certificate;
    if (options->root_ca_certificate)
      r.root_ca_certificate = std::string(options->root_ca_certificate);
    r.check_root_certificate_manufacturer_key =
      options->check_root_certificate_manufacturer_key;
    if (options->sgx_endorsement_cache_url_template)
      r.sgx_endorsement_cache_url_template =
        std::string(options->sgx_endorsement_cache_url_template);
    if (options->sev_snp_endorsement_cache_url_template)
      r.sev_snp_endorsement_cache_url_template =
        std::string(options->sev_snp_endorsement_cache_url_template);
    r.http_timeout = options->http_timeout;
    r.http_max_attempts = options->http_max_attempts;
    r.historical = options->historical;
  }
  return r;
}

#ifdef __cplusplus
extern "C"
{
#endif

  ravl_status_t verify_attestation_json(
    const char* json, size_t size, const ravl_options_t* options)
  {
    try
    {
      std::string vjson = {json, json + size};
      auto att = ravl::parse_attestation(vjson);
      auto claims = att->verify(cpp_options(options));
      last_exception_message_string = "";
      last_exception_message = NULL;
      return RAVL_OK;
    }
    catch (const std::exception& e)
    {
      last_exception_message_string = e.what();
      last_exception_message = last_exception_message_string.data();
      return RAVL_ERROR;
    }
    catch (...)
    {
      last_exception_message_string = "caught unknown exception";
      last_exception_message = last_exception_message_string.data();
      return RAVL_ERROR;
    }
  }

  ravl_status_t verify_attestation_cbor(
    const uint8_t* cbor, size_t size, const ravl_options_t* options)
  {
    try
    {
      std::vector<uint8_t> vcbor = {cbor, cbor + size};
      auto att = ravl::parse_attestation_cbor(vcbor);
      auto claims = att->verify(cpp_options(options));
      last_exception_message_string = "";
      last_exception_message = NULL;
      return RAVL_OK;
    }
    catch (const std::exception& e)
    {
      last_exception_message_string = e.what();
      last_exception_message = last_exception_message_string.data();
      return RAVL_ERROR;
    }
    catch (...)
    {
      last_exception_message_string = "caught unknown exception";
      last_exception_message = last_exception_message_string.data();
      return RAVL_ERROR;
    }
  }

#ifdef __cplusplus
}
#endif
