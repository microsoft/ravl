// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "enclave_u.h"
#include "sgx_quote.h"
#include "sgx_report.h"

#include <cstdio>
#include <cstdlib>
//#include <openssl/evp.h>
#include <sgx_eid.h>
#include <sgx_error.h>
#include <sgx_quote_3.h>
#include <sgx_uae_epid.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_urts.h>
#include <string>

// std::string base64(uint8_t* data, size_t size)
// {
//   unsigned char buf[2 * size];
//   int n = EVP_EncodeBlock(buf, data, size);
//   return std::string((char*)buf, n);
// }

// oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags)
// {
//   oe_enclave_t* enclave = NULL;

//   oe_result_t result = oe_create_oe_enclave_enclave(
//     enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

//   if (result != OE_OK)
//     printf("oe_create_oe_enclave_enclave failed: %s\n",
//     oe_result_str(result));

//   return enclave;
// }

// void terminate_enclave(oe_enclave_t* enclave)
// {
//   oe_terminate_enclave(enclave);
// }

sgx_status_t make_quote(
  sgx_target_info_t* target_info, const sgx_report_t* report)
{
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  sgx_epid_group_id_t gid = {0};
  sgx_att_key_id_t att_key_id = {0};

  // uint32_t num_key_ids = 0;
  // status = sgx_get_supported_att_key_id_num(&num_key_ids);

  // if (status != SGX_SUCCESS)
  //   return status;

  // sgx_att_key_id_ext_t* att_key_id_list =
  //   (sgx_att_key_id_ext_t*)malloc(sizeof(sgx_att_key_id_ext_t) *
  //   num_key_ids);

  // status = sgx_get_supported_att_key_ids(att_key_id_list, num_key_ids);

  // if (status != SGX_SUCCESS)
  //   return status;

  // status =
  //   sgx_select_att_key_id((uint8_t*)att_key_id_list, num_key_ids,
  //   &att_key_id);

  status = sgx_select_att_key_id(NULL, 0, &att_key_id);

  if (status != SGX_SUCCESS)
    return status;

  // get pub key size
  uint64_t pub_key_id_size = 0;
  status = sgx_init_quote_ex(&att_key_id, target_info, &pub_key_id_size, NULL);

  if (status != SGX_SUCCESS)
    return status;

  uint8_t* pub_key_id = (uint8_t*)malloc(pub_key_id_size);
  status =
    sgx_init_quote_ex(&att_key_id, target_info, &pub_key_id_size, pub_key_id);

  if (status != SGX_SUCCESS)
    return status;

  uint32_t quote_size = 0;
  status = sgx_get_quote_size_ex(&att_key_id, &quote_size);

  if (status != SGX_SUCCESS)
    return status;

  // sgx_report_t qe_report;
  // sgx_quote_nonce_t nonce = {
  //   0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

  uint8_t* quote_buffer = (uint8_t*)calloc(1, quote_size);
  sgx_qe_report_info_t qe_report_info = {0};

  status =
    sgx_get_quote_ex(report, &att_key_id, NULL, quote_buffer, quote_size);

  if (status != SGX_SUCCESS)
    return status;

  return SGX_SUCCESS;
}

sgx_status_t attest(sgx_enclave_id_t enclave_id)
{
  sgx_status_t status = SGX_ERROR_UNEXPECTED;
  int ret = 1;
  //   optional_parameters_t optional_parameters = {0};
  uint8_t data[] = {0, 1, 2, 3};
  uint8_t evidence[1024];
  uint8_t endorsements[1024];
  //   data_t data = {0};

  // sgx_status_t status = get_evidence_with_data(
  //   enclave_id,
  //   &ret,
  //   data,
  //   sizeof(data),
  //   evidence,
  //   sizeof(evidence),
  //   endorsements,
  //   sizeof(endorsements));

  uint8_t report_buffer[1024];
  sgx_status_t ret_status;
  sgx_target_info_t target_info;

  status = sgx_get_target_info(enclave_id, &target_info);

  if (status != SGX_SUCCESS)
    return status;

  sgx_report_data_t report_data = {0};

  status = get_report(
    enclave_id,
    &ret_status,
    &target_info,
    &report_data,
    report_buffer,
    sizeof(report_buffer));

  if ((status != SGX_SUCCESS) || (ret_status != SGX_SUCCESS))
  {
    printf("get_report failed. 0x%04x (%d)\n", status, ret_status);
    if (ret == 0)
      ret = 1;
    goto exit;
  }

  status = make_quote(&target_info, (sgx_report_t*)report_buffer);

  if (status != SGX_SUCCESS)
  {
    printf("make_quote failed. 0x%04x\n", status);
    if (ret == 0)
      ret = 1;
    goto exit;
  }

  printf("{\n");
  printf("  \"source\": \"sgx\",\n");
  // printf(
  //   "  \"evidence\": \"%s\",\n",
  //   base64(evidence.buffer, evidence.size).c_str());
  // printf(
  //   "  \"endorsements\": \"%s\"\n",
  //   endorsements.buffer && endorsements.size > 0 ?
  //     base64(endorsements.buffer, endorsements.size).c_str() :
  //     "");
  printf("}\n");

  //   ret = 0;

exit:
  //   free(evidence.buffer);
  //   free(endorsements.buffer);
  //   free(optional_parameters.buffer);
  //   return ret;

  return SGX_SUCCESS;
}

int main(int argc, const char* argv[])
{
  if (argc != 2)
  {
    printf("Usage: %s ENCLAVE_PATH\n", argv[0]);
    return 1;
  }

  uint8_t* quote = (uint8_t*)malloc(sizeof(sgx_quote_t) + 32);

  sgx_enclave_id_t enclave_id = 0;
  sgx_status_t ret =
    sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &enclave_id, NULL);
  if (ret != SGX_SUCCESS)
    goto exit;

  // #ifdef __linux__
  //   if (getenv("SGX_AESM_ADDR"))
  //   {
  //     printf("Host: environment variable SGX_AESM_ADDR is set\n");
  //   }
  //   else
  //   {
  //     printf("Host: environment variable SGX_AESM_ADDR is not set\n");
  //   }
  // #endif

  ret = attest(enclave_id);

  if (ret != 0)
    goto exit;

exit:

  // if (enclave)
  //   terminate_enclave(enclave);

  return ret;
}
