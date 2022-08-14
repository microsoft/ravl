// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "oe_enclave_u.h"

#include <cstdio>
#include <cstdlib>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include <openssl/evp.h>
#include <string>

static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

std::string base64(uint8_t* data, size_t size)
{
  unsigned char buf[2 * size];
  int n = EVP_EncodeBlock(buf, data, size);
  return std::string((char*)buf, n);
}

oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
{
  oe_enclave_t* enclave = NULL;

  oe_result_t result = oe_create_oe_enclave_enclave(
    enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

  if (result != OE_OK)
    printf(
      "Host: oe_create_oe_enclave_enclave failed: %s\n", oe_result_str(result));
  else
    printf("Host: Enclave successfully created.\n");

  return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
  oe_terminate_enclave(enclave);
}

int attest(const oe_uuid_t* format_id, oe_enclave_t* enclave)
{
  oe_result_t result = OE_OK;
  int ret = 1;
  optional_parameters_t optional_parameters = {0};
  evidence_t evidence = {0};
  endorsements_t endorsements = {0};
  data_t data = {0};

  result =
    get_optional_parameters(enclave, &ret, format_id, &optional_parameters);

  if ((result != OE_OK) || (ret != 0))
  {
    printf("Host: get_optional_parameters failed. %s\n", oe_result_str(result));
    if (ret == 0)
      ret = 1;
    goto exit;
  }

  result = get_evidence_with_data(
    enclave,
    &ret,
    format_id,
    &optional_parameters,
    &data,
    &evidence,
    &endorsements);

  if ((result != OE_OK) || (ret != 0))
  {
    printf("Host: get_evidence_with_data failed. %s\n", oe_result_str(result));
    if (ret == 0)
      ret = 1;
    goto exit;
  }

  printf("{\n");
  printf("  \"source\": \"openenclave\",\n");
  printf(
    "  \"evidence\": \"%s\",\n",
    base64(evidence.buffer, evidence.size).c_str());
  printf(
    "  \"endorsements\": \"%s\"\n",
    endorsements.buffer && endorsements.size > 0 ?
      base64(endorsements.buffer, endorsements.size).c_str() :
      "");
  // printf("  \"ext\": { \"format_id\": \"%s\" } },\n",
  // (char*)&format_id->b[0]);
  printf("}\n");

  ret = 0;

exit:
  free(evidence.buffer);
  free(endorsements.buffer);
  free(optional_parameters.buffer);
  return ret;
}

int main(int argc, const char* argv[])
{
  oe_enclave_t* enclave = NULL;
  oe_result_t result = OE_OK;
  int ret = 1;
  oe_uuid_t* format_id = nullptr;

  if (argc != 2)
  {
    printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
    return 1;
  }

  // if (strcmp(argv[1], "sgxlocal") == 0)
  // {
  //   format_id = &sgx_local_uuid;
  // }
  // if (strcmp(argv[1], "sgxremote") == 0)
  format_id = &sgx_remote_uuid;

  enclave = create_enclave(argv[1], OE_ENCLAVE_FLAG_DEBUG);
  if (enclave == NULL)
  {
    goto exit;
  }

#ifdef __linux__
  if (getenv("SGX_AESM_ADDR"))
  {
    printf("Host: environment variable SGX_AESM_ADDR is set\n");
  }
  else
  {
    printf("Host: environment variable SGX_AESM_ADDR is not set\n");
  }
#endif

  ret = attest(format_id, enclave);

exit:

  if (enclave)
    terminate_enclave(enclave);

  return ret;
}
