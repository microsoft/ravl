// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_oe.h"

#include "openenclave/bits/attestation.h"
#include "openenclave/bits/sgx/sgxtypes.h"
#include "ravl.h"

#ifdef USE_OE_VERIFIER
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/attestation/verifier.h>
#  include <openenclave/bits/attestation.h>
#  include <openenclave/bits/evidence.h>
#  include <openenclave/bits/result.h>
#else
#  include <openenclave/attestation/sgx/evidence.h>
#  include <openenclave/common/attest_plugin.h>
#  include <openenclave/endorsements.h>
#  include <openenclave/internal/report.h>
#endif

#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>

static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

// From SGX SDK/library headers
typedef struct _sgx_ql_qve_collateral_t
{
  union
  {
    uint32_t
      version; ///< 'version' is the backward compatible legacy representation
    struct
    { ///< For PCS V1 and V2 APIs, the major_version = 1 and minor_version = 0
      ///< and
      uint16_t major_version; ///< the CRLs will be formatted in PEM. For PCS V3
                              ///< APIs, the major_version = 3 and the
      uint16_t
        minor_version; ///< minor_version can be either 0 or 1. minor_verion of
                       ///< 0 indicates the CRL’s are formatted in Base16
                       ///< encoded DER.  A minor version of 1 indicates the
                       ///< CRL’s are formatted in raw binary DER.
    };
  };
  uint32_t tee_type; ///<  0x00000000: SGX or 0x00000081: TDX
  char* pck_crl_issuer_chain;
  uint32_t pck_crl_issuer_chain_size;
  char* root_ca_crl; /// Root CA CRL
  uint32_t root_ca_crl_size;
  char* pck_crl; /// PCK Cert CRL
  uint32_t pck_crl_size;
  char* tcb_info_issuer_chain;
  uint32_t tcb_info_issuer_chain_size;
  char* tcb_info; /// TCB Info structure
  uint32_t tcb_info_size;
  char* qe_identity_issuer_chain;
  uint32_t qe_identity_issuer_chain_size;
  char* qe_identity; /// QE Identity Structure
  uint32_t qe_identity_size;
} sgx_ql_qve_collateral_t;

namespace ravl
{
  namespace oe
  {
    template <typename T>
    void put(const T& t, const uint8_t* data, size_t& pos)
    {
      for (size_t i = 0; i < sizeof(T); i++)
        data[pos + i] = (t >> (8 * (sizeof(T) - i - 1))) & 0xFF;
      pos += sizeof(T);
    }

    template <typename T>
    void put(const T& t, std::vector<uint8_t>& data)
    {
      for (size_t i = 0; i < sizeof(T); i++)
        data.push_back((t >> (8 * (sizeof(T) - i - 1))) & 0xFF);
    }

    bool verify(const Attestation& a, const Options& options)
    {
#ifdef USE_OE_VERIFIER
      if (oe_verifier_initialize() != OE_OK)
        throw std::runtime_error("failed to initialize Open Enclave verifier");

      std::vector<oe_policy_t> policies;

      oe_claim_t* claims = nullptr;
      size_t claims_size = 0;

      oe_result_t r = oe_verify_evidence(
        &sgx_remote_uuid,
        a.evidence.data(),
        a.evidence.size(),
        a.endorsements.size() > 0 ? a.endorsements.data() : nullptr,
        a.endorsements.size(),
        policies.data(),
        policies.size(),
        &claims,
        &claims_size);

      if (oe_free_claims(claims, claims_size) != OE_OK)
        throw std::runtime_error("failed to free Open Enclave claims");

      if (oe_verifier_shutdown() != OE_OK)
        throw std::runtime_error("failed to initialize Open Enclave verifier");

      return r == OE_OK;
#else
      if (a.evidence.empty())
        throw std::runtime_error("No evidence to verify");

      bool with_plugin_header = false;

      if (with_plugin_header)
      {
        const oe_attestation_header_t* evidence_header =
          (oe_attestation_header_t*)a.evidence.data();
        const oe_attestation_header_t* endorsements_header = nullptr;

        if (a.evidence.size() < sizeof(oe_attestation_header_t))
          throw std::runtime_error(
            "Unknown evidence format: too small to contain attestation format "
            "header");
        if (evidence_header->version != OE_ATTESTATION_HEADER_VERSION)
          throw std::runtime_error("Unsupported evidence format version");
        if (
          a.evidence.size() >
          (evidence_header->data_size + sizeof(oe_attestation_header_t)))
          throw std::runtime_error(
            "Unsupported evidence format: excess evidence data");
        if (
          memcmp(
            &evidence_header->format_id, &sgx_remote_uuid, sizeof(oe_uuid_t)) !=
          0)
          throw std::runtime_error(
            "Unsupported evidence format: only OE_FORMAT_UUID_SGX_ECDSA is "
            "supported");

        if (a.endorsements.size() > 0)
        {
          endorsements_header = (oe_attestation_header_t*)a.endorsements.data();

          if (a.endorsements.size() < sizeof(oe_attestation_header_t))
            throw std::runtime_error(
              "Unknown endorsements format: too small to contain attestation "
              "format header");

          if (endorsements_header->version != OE_ATTESTATION_HEADER_VERSION)
            throw std::runtime_error("Unsupported endorsements format version");
          if (
            a.endorsements.size() >
            (endorsements_header->data_size + sizeof(oe_attestation_header_t)))
            throw std::runtime_error(
              "Unsupported endorsements format: excess data");

          if (
            memcmp(
              &evidence_header->format_id,
              &sgx_remote_uuid,
              sizeof(oe_uuid_t)) != 0)
            throw std::runtime_error(
              "Unsupported endorsements format: only OE_FORMAT_UUID_SGX_ECDSA "
              "is supported");
        }

        Attestation sgx_attestation(
          Source::SGX,
          {evidence_header->data,
           evidence_header->data + evidence_header->data_size},
          {endorsements_header->data,
           endorsements_header->data + endorsements_header->data_size});
        return sgx_attestation.verify(options);
      }
      else
      {
        const sgx_quote_t* quote = (sgx_quote_t*)a.evidence.data();
        const uint8_t* custom_claims = NULL;

        if (a.evidence.size() < sizeof(sgx_quote_t))
          throw std::runtime_error(
            "Unknown evidence format: too small to contain SGX quote");

        auto squote = a.evidence;

        if (squote.size() > (sizeof(sgx_quote_t) + quote->signature_len))
        {
          custom_claims = quote->signature + quote->signature_len;
          squote.resize(sizeof(sgx_quote_t) + quote->signature_len);
        }

        std::vector<uint8_t> scollateral;

        if (!a.endorsements.empty())
        {
          if (
            a.endorsements.size() < sizeof(oe_endorsements_t) ||
            a.endorsements.size() < sizeof(oe_sgx_endorsements_t))
            throw std::runtime_error(
              "Unknown endorsements format: too small to contain OE/SGX "
              "endorsements");

          const oe_endorsements_t* oeendo =
            (oe_endorsements_t*)a.endorsements.data();

          if (oeendo->version != OE_SGX_ENDORSEMENTS_VERSION)
            throw std::runtime_error(
              "unsupported version of OE endorsements data structure");

          if (oeendo->enclave_type != OE_ENCLAVE_TYPE_SGX)
            throw std::runtime_error(
              "unsupported enclave type in OE endorsements");

          sgx_ql_qve_collateral_t sgxcol = {0};
          sgxcol.major_version = 3;
          sgxcol.minor_version = 1;
          sgxcol.tee_type = 0; // 0 = SGX, 0x81 = TDX

          const uint32_t* offsets = (uint32_t*)oeendo->buffer;
          size_t offsets_size = oeendo->num_elements * sizeof(uint32_t);
          size_t data_size = oeendo->buffer_size - offsets_size;
          const uint8_t* data = oeendo->buffer + offsets_size;

          for (size_t i = 0; i < oeendo->num_elements; i++)
          {
            auto offset = offsets[i];
            if (offset >= data_size)
              throw std::runtime_error("invalid endorsement item offset");

            const uint8_t* item = &data[offset];
            size_t item_size = 0;

            if (i < oeendo->num_elements - 1)
              item_size = offsets[i + 1] - offsets[i];
            else
              item_size = data_size - offsets[i];

            switch (i)
            {
              case 0:
                // OE_SGX_ENDORSEMENT_FIELD_VERSION
                if (item_size != 4 || *((uint32_t*)item) != 1)
                  throw std::runtime_error(
                    "unsupported version of OE endorsements data structure");
                break;
              case 1:
                // OE_SGX_ENDORSEMENT_FIELD_TCB_INFO
                sgxcol.tcb_info = (char*)item;
                sgxcol.tcb_info_size = item_size;
                break;
              case 2:
                // OE_SGX_ENDORSEMENT_FIELD_TCB_ISSUER_CHAIN
                sgxcol.tcb_info_issuer_chain = (char*)item;
                sgxcol.tcb_info_issuer_chain_size = item_size;
                break;
              case 3:
                // OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_CERT
                sgxcol.pck_crl = (char*)item;
                sgxcol.pck_crl_size = item_size;
                break;
              case 4:
                // OE_SGX_ENDORSEMENT_FIELD_CRL_PCK_PROC_CA
                sgxcol.root_ca_crl = (char*)item;
                sgxcol.root_ca_crl_size = item_size;
                break;
              case 5:
                // OE_SGX_ENDORSEMENT_FIELD_CRL_ISSUER_CHAIN_PCK_CERT
                sgxcol.pck_crl_issuer_chain = (char*)item;
                sgxcol.pck_crl_issuer_chain_size = item_size;

                break;
              case 6:
                // OE_SGX_ENDORSEMENT_FIELD_QE_ID_INFO
                sgxcol.qe_identity = (char*)item;
                sgxcol.qe_identity_size = item_size;
                break;
              case 7:
                // OE_SGX_ENDORSEMENT_FIELD_QE_ID_ISSUER_CHAIN
                sgxcol.qe_identity_issuer_chain = (char*)item;
                sgxcol.qe_identity_issuer_chain_size = item_size;
                break;
              case 8:
                // OE_SGX_ENDORSEMENT_FIELD_CREATION_DATETIME
                // Ignore
                break;
              default:
                throw std::runtime_error(
                  "excess elements in OE endorsements data");
            }
          }

          put(sgxcol.major_version, scollateral);
          put(sgxcol.minor_version, scollateral);
          put(sgxcol.tee_type, scollateral);

          for (const auto& [d, sz] : std::vector<std::pair<void*, size_t>>{
                 {sgxcol.pck_crl_issuer_chain,
                  sgxcol.pck_crl_issuer_chain_size},
                 {sgxcol.root_ca_crl, sgxcol.root_ca_crl_size},
                 {sgxcol.pck_crl, sgxcol.pck_crl_size},
                 {sgxcol.tcb_info_issuer_chain,
                  sgxcol.tcb_info_issuer_chain_size},
                 {sgxcol.tcb_info, sgxcol.tcb_info_size},
                 {sgxcol.qe_identity_issuer_chain,
                  sgxcol.qe_identity_issuer_chain_size},
                 {sgxcol.qe_identity, sgxcol.qe_identity_size}})
          {
            put(sz, scollateral);
            for (size_t i = 0; i < sz; i++)
              scollateral.push_back(((uint8_t*)d)[i]);
          }
        }

        Attestation sgx_attestation(Source::SGX, squote, scollateral);
        return sgx_attestation.verify(options);
      }
#endif
    }
  }
}
