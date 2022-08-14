// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "oe_enclave_args.h"
#include "oe_enclave_t.h"

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/report.h>
#include <openenclave/enclave.h>
#include <string>

#define ENCLAVE_SECRET_DATA_SIZE 16

uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] = {
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

const char* enclave_name = "ravl-test-enclave";

int get_optional_parameters(
  const oe_uuid_t* format_id, optional_parameters_t* optional_parameters)
{
  uint8_t* optional_parameters_buffer = nullptr;
  size_t optional_parameters_size = 0;
  int ret = 1;

  try
  {
    if (oe_verifier_initialize() != OE_OK)
      return 1;

    if (
      oe_verifier_get_format_settings(
        format_id, &optional_parameters_buffer, &optional_parameters_size) !=
      OE_OK)
      return 1;

    if (optional_parameters_buffer && optional_parameters_size)
    {
      optional_parameters->buffer = (uint8_t*)malloc(optional_parameters_size);
      if (optional_parameters->buffer == nullptr)
        return OE_OUT_OF_MEMORY;
      memcpy(
        optional_parameters->buffer,
        optional_parameters_buffer,
        optional_parameters_size);
      optional_parameters->size = optional_parameters_size;
      oe_verifier_free_format_settings(optional_parameters_buffer);
    }
    else
    {
      optional_parameters->buffer = nullptr;
      optional_parameters->size = 0;
    }
  }
  catch (std::exception& ex)
  {
    return 43;
  }

  return 0;
}

bool generate_attestation_evidence(
  const oe_uuid_t* format_id,
  uint8_t* optional_parameters,
  size_t optional_parameters_size,
  uint8_t* data,
  size_t data_size,
  uint8_t** evidence,
  size_t* evidence_size,
  uint8_t** endorsements,
  size_t* endorsements_size)
{
  uint8_t* custom_claims_buffer = nullptr;
  size_t custom_claims_buffer_size = 0;

  char custom_claim1_name[] = "some_name";
  char custom_claim1_value[] = "some_value";

  oe_claim_t custom_claims[2] = {
    {.name = custom_claim1_name,
     .value = (uint8_t*)custom_claim1_value,
     .value_size = sizeof(custom_claim1_value)}};

  if (oe_attester_initialize() != OE_OK)
    return false;

  if (
    oe_serialize_custom_claims(
      custom_claims, 1, &custom_claims_buffer, &custom_claims_buffer_size) !=
    OE_OK)
    return false;

  if (
    oe_get_evidence(
      format_id,
      0,
      custom_claims_buffer,
      custom_claims_buffer_size,
      optional_parameters,
      optional_parameters_size,
      evidence,
      evidence_size,
      endorsements,
      endorsements_size) != OE_OK)
    return false;

  return true;
}

int get_evidence_with_data(
  const oe_uuid_t* format_id,
  optional_parameters_t* optional_parameters,
  data_t* data,
  evidence_t* evidence,
  endorsements_t* endorsements)
{
  int ret = 1;

  uint8_t* evidence_buffer = nullptr;
  size_t evidence_size = 0;
  uint8_t* endorsements_buffer = nullptr;
  size_t endorsements_size = 0;

  try
  {
    if (!generate_attestation_evidence(
          format_id,
          !optional_parameters ? NULL : optional_parameters->buffer,
          !optional_parameters ? 0 : optional_parameters->size,
          !data ? NULL : data->buffer,
          !data ? 0 : data->size,
          &evidence_buffer,
          &evidence_size,
          &endorsements_buffer,
          &endorsements_size))
    {
      goto exit;
    }

    if (evidence)
    {
      evidence->buffer = (uint8_t*)malloc(evidence_size);
      if (evidence->buffer == nullptr)
      {
        ret = OE_OUT_OF_MEMORY;
        goto exit;
      }

      memcpy(evidence->buffer, evidence_buffer, evidence_size);
      evidence->size = evidence_size;
      oe_free_evidence(evidence_buffer);
    }

    if (endorsements)
    {
      endorsements->buffer = (uint8_t*)malloc(endorsements_size);
      if (endorsements->buffer == nullptr)
      {
        ret = OE_OUT_OF_MEMORY;
        goto exit;
      }

      memcpy(endorsements->buffer, endorsements_buffer, endorsements_size);
      endorsements->size = endorsements_size;
      oe_free_endorsements(endorsements_buffer);
    }

    ret = 0;
  }
  catch (std::exception& ex)
  {
    ret = 42;
  }

exit:
  if (ret != 0)
  {
    if (evidence_buffer)
      oe_free_evidence(evidence_buffer);
    if (endorsements_buffer)
      oe_free_evidence(endorsements_buffer);
    if (evidence)
    {
      free(evidence->buffer);
      evidence->size = 0;
    }
    if (endorsements)
    {
      free(endorsements->buffer);
      endorsements->size = 0;
    }
  }

  return ret;
}
