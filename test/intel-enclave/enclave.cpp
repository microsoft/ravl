// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//#include "enclave_args.h"
#include "enclave_t.h"

#include <cstdint>
#include <sgx_error.h>
#include <sgx_key_exchange.h>
#include <sgx_quote.h>
#include <sgx_report.h>
#include <sgx_uae_quote_ex.h>
#include <sgx_utils.h>
#include <string.h>

const char* enclave_name = "ravl-test-enclave";

sgx_status_t get_report(
  const sgx_target_info_t* target_info,
  const sgx_report_data_t* report_data,
  uint8_t* report_buffer,
  size_t report_buffer_size)
{
  sgx_status_t status = SGX_ERROR_UNEXPECTED;

  sgx_report_t report;
  status = sgx_create_report(target_info, report_data, &report);

  if (report_buffer_size < sizeof(report))
    status = SGX_ERROR_UNEXPECTED;

  memcpy(report_buffer, &report, sizeof(report));

  return status;
}
