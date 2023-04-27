// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

  extern const char* last_exception_message;

  typedef struct ravl_options_t_
  {
    uint8_t verbosity;

    struct
    {
      int ignore_time;
      time_t* verification_time;
    } certificate_verification_;

    int fresh_endorsements;
    int fresh_root_ca_certificate;
    const char* root_ca_certificate;
    int check_root_certificate_manufacturer_key;
    const char* sgx_endorsement_cache_url_template;
    const char* sev_snp_endorsement_cache_url_template;
    size_t http_timeout;
    size_t http_max_attempts;
    int historical;
  } ravl_options_t;

  typedef enum
  {
    RAVL_OK = 0,
    RAVL_ERROR = 1
  } ravl_status_t;

  ravl_status_t verify_attestation_json(
    const char* json, size_t size, const ravl_options_t* options);

  ravl_status_t verify_attestation_cbor(
    const uint8_t* cbor, size_t size, const ravl_options_t* options);

#ifdef __cplusplus
}
#endif