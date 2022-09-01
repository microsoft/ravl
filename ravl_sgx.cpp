// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_sgx.h"

#include "openssl_wrappers.h"
#include "ravl_requests.h"

#include <dlfcn.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <sgx_quote_3.h>
#include <span>
#include <stdexcept>
#include <string>
#include <unordered_set>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#define SGX_QUOTE_VERSION 3

using namespace crypto::OpenSSL;

// All of this is inspired by Open Enclave's SGX verification, especially
// https://github.com/openenclave/openenclave/blob/master/common/sgx/quote.c

// Intel Provisioning Spec:
// https://api.portal.trustedservices.intel.com/documentation

// PCK Crl from cache:
// 'https://global.acccache.azure.net/sgx/certification/v3/pckcrl?uri=https%253a%252f%252fcertificates.trustedservices.intel.com%252fintelsgxpckprocessor.crl&clientid=production_client&api-version=2020-02-12-preview'.
// Root CA Crl from cache:
// 'https://global.acccache.azure.net/sgx/certification/v3/pckcrl?uri=https%253a%252f%252fcertificates.trustedservices.intel.com%252fintelsgxrootca.crl&clientid=production_client&api-version=2020-02-12-preview'.
// TCB Info from cache:
// 'https://global.acccache.azure.net/sgx/certification/v3/tcb?fmspc=00906ed50000&clientid=production_client&api-version=2018-10-01-preview'.
// QE Identity from cache:
// 'https://global.acccache.azure.net/sgx/certification/v3/qe/identity?clientid=production_client&api-version=2018-10-01-preview'

namespace ravl
{
  namespace sgx
  {
    static const std::string pck_cert_common_name = "Intel SGX PCK Certificate";

    static const std::string intel_root_public_key_pem =
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO\n"
      "SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==\n"
      "-----END PUBLIC KEY-----\n";

    static const char* datetime_format = "%Y-%m-%dT%H:%M:%SZ";
    static const char* sgx_earliest_tcb_crl_date = "2017-03-17T00:00:00Z";

    static std::string sgx_ext_oid = "1.2.840.113741.1.13.1";
    static std::string sgx_ext_ppid_oid = sgx_ext_oid + ".1";
    static std::string sgx_ext_tcb_oid = sgx_ext_oid + ".2";
    static std::string sgx_ext_pceid_oid = sgx_ext_oid + ".3";
    static std::string sgx_ext_fmspc_oid = sgx_ext_oid + ".4";
    static std::string sgx_ext_type_oid = sgx_ext_oid + ".5";
    static std::string sgx_ext_platform_instance_oid = sgx_ext_oid + ".6";
    static std::string sgx_ext_configuration_oid = sgx_ext_oid + ".7";
    static std::string sgx_ext_configuration_dynamic_platform_oid =
      sgx_ext_configuration_oid + ".1";
    static std::string sgx_ext_configuration_cached_keys_oid =
      sgx_ext_configuration_oid + ".2";
    static std::string sgx_ext_configuration_smt_enabled_oid =
      sgx_ext_configuration_oid + ".3";

    void printf_certificate(X509* certificate)
    {
      Unique_BIO bio;
      X509_print(bio, certificate);
      std::string certificate_s = bio.to_string();
      printf("%s\n", certificate_s.c_str());
    }

    template <typename T>
    T get(const std::vector<uint8_t>& data, size_t& pos)
    {
      if (pos + sizeof(T) > data.size())
        throw std::runtime_error("not enough data");

      T r = 0;
      for (size_t i = 0; i < sizeof(T); i++)
        r = r << 8 | data.at(pos + i);
      pos += sizeof(T);
      return r;
    }

    std::vector<uint8_t> get_n(
      const std::vector<uint8_t>& data, size_t n, size_t& pos)
    {
      if (pos + n > data.size())
        throw std::runtime_error("not enough data");

      std::vector<uint8_t> r(n, 0);
      for (size_t i = 0; i < n; i++)
        r[i] = data.at(pos + i);
      pos += n;

      return r;
    }

    std::vector<uint8_t> from_hex(const std::string& s)
    {
      if (s.size() % 2)
        throw std::runtime_error("odd number of hex digits");

      std::vector<uint8_t> r;
      for (size_t i = 0; i < s.size(); i += 2)
      {
        uint8_t t;
        if (sscanf(s.c_str() + i, "%02hhx", &t) != 1)
          return {};
        r.push_back(t);
      }
      return r;
    }

    template <typename T>
    T from_hex_t(const std::string& s, bool little_endian = true)
    {
      if (s.size() % 2)
        throw std::runtime_error("odd number of hex digits");

      if (2 * sizeof(T) != s.size())
        throw std::runtime_error("hex string incomplete");

      T r = 0;
      for (size_t i = 0; i < sizeof(T); i++)
      {
        uint8_t t;
        if (sscanf(s.c_str() + 2 * i, "%02hhx", &t) != 1)
          return {};
        if (little_endian)
          r |= ((uint64_t)t) << (8 * i);
        else
          r = (r << 8) | t;
      }
      return r;
    }

    static inline void check_within(
      const void* ptr, const std::span<const uint8_t>& vec)
    {
      if (!(vec.data() <= ptr && ptr < (vec.data() + vec.size())))
        throw std::runtime_error("invalid pointer");
    }

    static inline void check_within(
      const std::span<const uint8_t>& span, const std::span<const uint8_t>& vec)
    {
      check_within(span.data(), vec);
      check_within(span.data() + span.size() - 1, vec);
    }

    class QL_QVE_Collateral // ~ sgx_ql_qve_collateral_t
    {
    public:
      QL_QVE_Collateral() {}

      QL_QVE_Collateral(const std::vector<uint8_t>& data)
      {
        size_t pos = 0, n = 0;

        major_version = get<uint16_t>(data, pos);
        minor_version = get<uint16_t>(data, pos);
        tee_type = get<uint32_t>(data, pos);

        n = get<size_t>(data, pos);
        pck_crl_issuer_chain = get_n(data, n, pos);

        n = get<size_t>(data, pos);
        root_ca_crl = get_n(data, n, pos);

        n = get<size_t>(data, pos);
        pck_crl = get_n(data, n, pos);

        n = get<size_t>(data, pos);
        tcb_info_issuer_chain = get_n(data, n, pos);

        n = get<size_t>(data, pos);
        tcb_info = get_n(data, n, pos);

        n = get<size_t>(data, pos);
        qe_identity_issuer_chain = get_n(data, n, pos);

        n = get<size_t>(data, pos);
        qe_identity = get_n(data, n, pos);

        // TODO: Investigate why there are sometimes extra null bytes
        // if (pos != data.size())
        //   throw std::runtime_error("excess collateral data");
      }

      uint16_t major_version;
      uint16_t minor_version;
      uint32_t tee_type;

      std::vector<uint8_t> pck_crl_issuer_chain;
      std::vector<uint8_t> root_ca_crl;
      std::vector<uint8_t> pck_crl;
      std::vector<uint8_t> tcb_info_issuer_chain;
      std::vector<uint8_t> tcb_info;
      std::vector<uint8_t> qe_identity_issuer_chain;
      std::vector<uint8_t> qe_identity;
    };

    static bool verify_signature(
      const Unique_EVP_PKEY& pkey,
      const std::span<const uint8_t>& message,
      const std::span<const uint8_t>& signature)
    {
      SHA256_CTX ctx;
      SHA256_Init(&ctx);

      SHA256_Update(&ctx, message.data(), message.size());

      std::vector<uint8_t> hash(ctx.md_len, 0);
      SHA256_Final(hash.data(), &ctx);

      auto signature_der = convert_signature_to_der(signature);

      Unique_EVP_PKEY_CTX pctx(pkey);
      CHECK1(EVP_PKEY_verify_init(pctx));
      int rc = EVP_PKEY_verify(
        pctx,
        signature_der.data(),
        signature_der.size(),
        hash.data(),
        hash.size());

      return rc == 1;
    }

    static bool verify_signature(
      const Unique_EC_KEY& eckey,
      const std::span<const uint8_t>& message,
      const std::span<const uint8_t>& signature)
    {
      return verify_signature(Unique_EVP_PKEY(eckey), message, signature);
    }

    static bool verify_signature(
      const std::span<const uint8_t>& public_key,
      const std::span<const uint8_t>& message,
      const std::span<const uint8_t>& signature)
    {
      auto eckey = Unique_EC_KEY_P256(public_key);
      return verify_signature(eckey, message, signature);
    }

    static bool verify_hash_match(
      const std::vector<std::span<const uint8_t>>& inputs,
      const std::span<const uint8_t>& expected)
    {
      SHA256_CTX sha256_ctx;
      CHECK1(SHA256_Init(&sha256_ctx));
      for (const auto& input : inputs)
        CHECK1(SHA256_Update(&sha256_ctx, input.data(), input.size()));
      std::vector<uint8_t> hash(sha256_ctx.md_len, 0);
      CHECK1(SHA256_Final(hash.data(), &sha256_ctx));
      if (hash.size() != expected.size())
        return false;
      for (size_t i = 0; i < hash.size(); i++)
        if (hash[i] != expected[i])
          return false;
      return true;
    }

    static std::string_view extract_pem(std::string_view& certstrs)
    {
      static std::string begin = "-----BEGIN CERTIFICATE-----";
      static std::string end = "-----END CERTIFICATE-----";

      size_t from = certstrs.find(begin);
      if (from == std::string::npos)
        return "";
      size_t to = certstrs.find(end, from);
      if (to == std::string::npos)
        return "";
      to += end.size();
      auto pem = certstrs.substr(from, to - from);
      from = certstrs.find(begin, to);
      certstrs.remove_prefix(
        from == std::string::npos ? certstrs.size() : from);
      return pem;
    }

    static std::string_view extract_pem(
      const std::span<const uint8_t>& certstrs)
    {
      std::string_view sv((char*)certstrs.data(), certstrs.size());
      return extract_pem(sv);
    }

    static std::vector<std::string> extract_pems(
      const std::span<const uint8_t>& data)
    {
      std::vector<std::string> r;
      std::string_view sv((char*)data.data(), data.size());

      while (!sv.empty())
      {
        auto pem = extract_pem(sv);
        if (!pem.empty())
          r.push_back(std::string(pem));
      }

      return r;
    }

    std::pair<struct tm, struct tm> get_validity_range(
      const Unique_STACK_OF_X509& chain)
    {
      if (!chain || chain.size() == 0)
        throw std::runtime_error(
          "no certificate change to compute validity ranges for");

      const ASN1_TIME *latest_from = nullptr, *earliest_to = nullptr;
      for (size_t i = 0; i < chain.size(); i++)
      {
        const auto& c = chain.at(i);
        const ASN1_TIME* not_before = X509_get0_notBefore(c);
        if (!latest_from || ASN1_TIME_compare(latest_from, not_before) == -1)
          latest_from = not_before;
        const ASN1_TIME* not_after = X509_get0_notAfter(c);
        if (!earliest_to || ASN1_TIME_compare(earliest_to, not_after) == 1)
          earliest_to = not_after;
      }

      std::pair<struct tm, struct tm> r;
      ASN1_TIME_to_tm(latest_from, &r.first);
      ASN1_TIME_to_tm(earliest_to, &r.second);
      return r;
    }

    struct TCB
    {
      std::array<uint8_t, 16> comp_svn;
      uint16_t pce_svn;
      std::array<uint8_t, 16> cpu_svn;
    };

    TCB get_tcb_ext(
      const Unique_ASN1_SEQUENCE& seq,
      int index,
      const std::string& expected_oid)
    {
      TCB r;

      auto sss = seq.get_seq(index, expected_oid);

      int n = sss.size();
      if (n != 18)
        throw asn1_format_exception(
          "X509 extension TCB sequence of invalid length");

      for (int i = 0; i < n; i++)
      {
        std::string expected_oid_i =
          std::string(sgx_ext_tcb_oid) + "." + std::to_string(i + 1);

        if (i < 16)
          r.comp_svn[i] = sss.get_uint8(i, expected_oid_i);
        else if (i == 16)
          r.pce_svn = sss.get_uint16(i, expected_oid_i);
        else if (i == 17)
        {
          auto t = sss.get_octet_string(i, expected_oid_i);
          if (t.size() != 16)
            throw asn1_format_exception("ASN.1 octet string of invalid size");
          for (size_t i = 0; i < 16; i++)
            r.cpu_svn.at(i) = t.at(i);
        }
        else
          throw std::runtime_error("unreachable");
      }

      return r;
    }

    std::vector<uint8_t> str2vec(const std::string& s)
    {
      return {s.data(), s.data() + s.size()};
    }

    std::vector<uint8_t> download_root_ca_pem()
    {
      auto response = Request{
        .url =
          "https://certificates.trustedservices.intel.com/"
          "Intel_SGX_Provisioning_Certification_RootCA.pem"}();

      return str2vec(response.body);
    }

    std::shared_ptr<QL_QVE_Collateral> download_collateral(
      const std::string& ca, const std::string& fmspc, bool qve = false)
    {
      auto r = std::make_shared<QL_QVE_Collateral>();

      r->major_version = 3;
      r->minor_version = 1;
      r->tee_type = 0;

      // Root CRL
      auto response = Request{
        .url =
          "https://certificates.trustedservices.intel.com/"
          "IntelSGXRootCA.crl"}();

      r->root_ca_crl = str2vec(response.body);

      // TCB info
      // https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v3
      response = Request{
        .url =
          "https://api.trustedservices.intel.com/sgx/certification/v3/"
          "tcb?fmspc=" +
          fmspc}();
      r->tcb_info = str2vec(response.body);
      r->tcb_info_issuer_chain =
        response.get_header_data("SGX-TCB-Info-Issuer-Chain", true);

      // PCK CRL
      // https://api.portal.trustedservices.intel.com/documentation#pcs-revocation-v3
      response = Request{
        .url =
          "https://api.trustedservices.intel.com/sgx/certification/v3/"
          "pckcrl?ca=" +
          ca + "&encoding=pem"}();
      r->pck_crl = str2vec(response.body);
      r->pck_crl_issuer_chain =
        response.get_header_data("SGX-PCK-CRL-Issuer-Chain", true);

      if (!qve)
      {
        // QE Identity
        // https://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity-v3
        response = Request{
          .url =
            "https://api.trustedservices.intel.com/sgx/certification/v3/qe/"
            "identity"}();
        r->qe_identity = str2vec(response.body);
        r->qe_identity_issuer_chain =
          response.get_header_data("SGX-Enclave-Identity-Issuer-Chain", true);
      }
      else
      {
        // QVE Identity
        // https://api.portal.trustedservices.intel.com/documentation#pcs-qve-identity-v3
        response = Request{
          .url =
            "https://api.trustedservices.intel.com/sgx/certification/v3/"
            "qve/identity"}();
        r->qe_identity = str2vec(response.body);
        r->qe_identity_issuer_chain =
          response.get_header_data("SGX-Enclave-Identity-Issuer-Chain", true);
      }

      return r;
    }

    struct PCKCertificateExtensions
    {
      std::vector<uint8_t> ppid;
      TCB tcb;
      std::vector<uint8_t> pceid;
      std::vector<uint8_t> fmspc;
      uint8_t sgx_type;

      std::optional<std::vector<uint8_t>> platform_instance_id = std::nullopt;

      struct Configuration
      {
        bool dynamic_platform;
        bool cached_keys;
        bool smt_enabled;
      };

      std::optional<Configuration> configuration = std::nullopt;
    };

    PCKCertificateExtensions get_pck_certificate_extensions(
      const Unique_X509& pck_certificate)
    {
      // See
      // https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.4.pdf

      int sgx_ext_idx = X509_get_ext_by_OBJ(
        pck_certificate, Unique_ASN1_OBJECT(sgx_ext_oid.c_str()), -1);

      X509_EXTENSION* sgx_ext = X509_get_ext(pck_certificate, sgx_ext_idx);

      if (!sgx_ext)
        throw std::runtime_error(
          "PCK certificate does not contain the SGX extension");

      Unique_ASN1_SEQUENCE seq(X509_EXTENSION_get_data(sgx_ext));

      int seq_sz = seq.size();
      if (seq_sz != 5 && seq_sz != 7)
        throw std::runtime_error(
          "SGX X509 extension sequence has invalid size");

      PCKCertificateExtensions r;

      r.ppid = seq.get_octet_string(0, sgx_ext_ppid_oid);
      r.tcb = get_tcb_ext(seq, 1, sgx_ext_tcb_oid);
      r.pceid = seq.get_octet_string(2, sgx_ext_pceid_oid);
      r.fmspc = seq.get_octet_string(3, sgx_ext_fmspc_oid);
      r.sgx_type = seq.get_enum(4, sgx_ext_type_oid) != 0;

      if (seq_sz > 5)
      {
        r.platform_instance_id =
          seq.get_octet_string(5, sgx_ext_platform_instance_oid);

        // Platform-CA certificates come with these extensions, but only
        // existence and order is verified here.
        auto config_seq = seq.get_seq(6, sgx_ext_configuration_oid);
        if (config_seq.size() != 3)
          throw std::runtime_error(
            "SGX X509 extension configuration sequence has invalid size");

        auto dyn_platform =
          config_seq.get_bool(0, sgx_ext_configuration_dynamic_platform_oid);
        auto cached_keys =
          config_seq.get_bool(1, sgx_ext_configuration_cached_keys_oid);
        auto smt_enabled =
          config_seq.get_bool(2, sgx_ext_configuration_smt_enabled_oid);

        r.configuration = PCKCertificateExtensions::Configuration{
          .dynamic_platform = dyn_platform,
          .cached_keys = cached_keys,
          .smt_enabled = smt_enabled};
      }

      return r;
    }

    bool is_all_zero(const std::vector<uint8_t>& v)
    {
      for (const auto& b : v)
        if (b != 0)
          return false;
      return true;
    }

    bool has_pck_common_name(const X509* x509)
    {
      auto subject_name = X509_get_subject_name(x509);
      int cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
      while (cn_i != -1)
      {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, cn_i);
        ASN1_STRING* entry_string = X509_NAME_ENTRY_get_data(entry);
        std::string common_name = (char*)ASN1_STRING_get0_data(entry_string);
        if (common_name == pck_cert_common_name)
          return true;
        cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, cn_i);
      }
      return false;
    }

    Unique_STACK_OF_X509 verify_certificate_chain(
      const Unique_X509_STORE& store,
      const Unique_STACK_OF_X509& stack,
      const Options& options,
      bool trusted_root)
    {
      if (stack.size() <= 1)
        throw std::runtime_error("certificate stack too small");

      if (trusted_root)
        X509_STORE_add_cert(store, stack.back());

      auto target = stack.at(0);

      Unique_X509_STORE_CTX store_ctx;
      X509_STORE_CTX_init(store_ctx, store, target, stack);

      if (options.ignore_time)
      {
        // TODO: double free of param?
        X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(store_ctx);
        if (!param)
          param = X509_VERIFY_PARAM_new();
        X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_NO_CHECK_TIME);
        X509_STORE_CTX_set0_param(store_ctx, param);
      }

      if (options.verification_time)
        X509_STORE_CTX_set_time(store_ctx, 0, *options.verification_time);

      int rc = X509_verify_cert(store_ctx);

      if (rc == 1)
        return Unique_STACK_OF_X509(store_ctx);
      else
      {
        int a = errno;
        unsigned long openssl_err = ERR_get_error();
        char buf[4096];
        ERR_error_string(openssl_err, buf);
        throw std::runtime_error("certificate verification failed");
      }
    }

    Unique_STACK_OF_X509 load_certificates(
      const Unique_X509_STORE& store,
      const std::vector<std::string>& certificates)
    {
      // Leaf tracking/searching may be unnecessary as the chains should be in
      // order anyways.

      Unique_STACK_OF_X509 r;
      X509* leaf = NULL;

      for (const auto& cert : certificates)
      {
        Unique_BIO cert_bio(cert.data(), cert.size());
        Unique_X509 x509(cert_bio, true);

        if (!X509_check_ca(x509))
        {
          if (leaf)
            throw std::runtime_error("multiple leaves in certificate set");

          leaf = x509;
        }

        r.push(std::move(x509));
      }

      if (!leaf)
      {
        // Some chains, e.g. pck_crl_issuer_chain, contain only CAs, so the leaf
        // isn't easy to detect, so we look for the certificate that isn't used
        // as an authority.
        for (size_t ii = 0; ii < r.size(); ii++)
        {
          const auto& i = r.at(ii);
          Unique_ASN1_OCTET_STRING subj_key_id(X509_get0_subject_key_id(i));

          bool i_appears_as_ca = false;
          for (size_t ji = 0; ji < r.size(); ji++)
          {
            if (ii == ji)
              continue;

            const auto& j = r.at(ji);

            Unique_ASN1_OCTET_STRING auth_key_id(X509_get0_authority_key_id(j));

            if (subj_key_id == auth_key_id)
            {
              i_appears_as_ca = true;
              break;
            }
          }

          if (!i_appears_as_ca)
          {
            if (leaf)
              throw std::runtime_error("multiple leaves in certificate set");

            leaf = i;
          }
        }
      }

      if (!leaf)
        throw std::runtime_error("no leaf certificate found");

      if (r.at(0) != leaf)
        throw std::runtime_error(
          "leaf certificate not at the front of the certificate chain");

      return r;
    }

    Unique_STACK_OF_X509 get_verified_certificate_chain(
      const std::span<const uint8_t> data,
      const Unique_X509_STORE& store,
      const Options& options,
      bool trusted_root = false)
    {
      std::vector<std::string> certificates = extract_pems(data);

      auto stack = load_certificates(store, certificates);
      auto chain =
        verify_certificate_chain(store, stack, options, trusted_root);

      if (chain.size() < 2)
        throw std::runtime_error("certificate chain is too short");

      return chain;
    }

    Unique_STACK_OF_X509 get_verified_certificate_chain(
      const std::string& data,
      Unique_X509_STORE& store,
      const Options& options,
      bool trusted_root = false)
    {
      std::span<const uint8_t> span((uint8_t*)data.data(), data.size());
      return get_verified_certificate_chain(span, store, options, trusted_root);
    }

    bool has_intel_public_key(const Unique_X509& certificate)
    {
      Unique_EVP_PKEY pubkey(certificate);
      Unique_BIO bio(intel_root_public_key_pem);
      Unique_EVP_PKEY intel_pubkey(bio, true);
      return pubkey == intel_pubkey;
    }

    bool json_vector_eq(
      const nlohmann::json& tcbinfo_j,
      const std::string& key,
      const std::vector<uint8_t>& ref,
      bool optional = false)
    {
      auto vj = tcbinfo_j[key];
      if (vj.is_null())
      {
        if (optional)
          return true;
        else
          throw std::runtime_error("missing json object");
      }

      auto vv = vj.get<std::string>();
      return from_hex(vv) == ref;
    }

    struct TCBLevel
    {
      std::array<uint8_t, 16> comp_svn = {0};
      uint16_t pce_svn = 0;
      std::string status = "";
      std::string date = "";
      std::vector<std::string> advisory_ids = {};
    };

    std::chrono::system_clock::time_point parse_time_point(const std::string& s)
    {
      struct tm stm = {};
      auto sres = strptime(s.c_str(), datetime_format, &stm);
      if (sres == NULL || *sres != '\0')
        throw std::runtime_error("time point parsing failure");
      auto idr = std::chrono::system_clock::from_time_t(timegm(&stm));
      idr -= std::chrono::seconds(stm.tm_gmtoff);
      return idr;
    }

    void check_datetime(const std::string& date_s, const std::string& name)
    {
      auto earliest_permitted = parse_time_point(sgx_earliest_tcb_crl_date);
      auto issue_timepoint = parse_time_point(date_s);
      if (issue_timepoint < earliest_permitted)
        throw std::runtime_error(name + " earlier than permitted");
    }

    TCBLevel verify_tcb_json(
      const std::span<uint8_t>& tcb_info,
      const PCKCertificateExtensions& pck_ext,
      const Unique_EVP_PKEY& signer_pubkey)
    {
      TCBLevel platform_tcb_level = {0};

      std::vector<uint8_t> signature;

      std::string tcb_info_s(
        tcb_info.data(), tcb_info.data() + tcb_info.size());

      try
      {
        auto col_tcb_info_j = nlohmann::json::parse(tcb_info_s);
        auto tcbinfo_j = col_tcb_info_j["tcbInfo"];

        if (
          tcbinfo_j.find("version") == tcbinfo_j.end() ||
          tcbinfo_j["version"].get<uint32_t>() != 2)
          throw std::runtime_error("unsupported tcbInfo version");

        auto id = tcbinfo_j["issueDate"].get<std::string>();
        check_datetime(id, "TCB issue date");
        auto nu = tcbinfo_j["nextUpdate"].get<std::string>();
        check_datetime(nu, "TCB next update");

        // TODO: advisory IDs?

        if (!json_vector_eq(tcbinfo_j, "fmspc", pck_ext.fmspc))
          throw std::runtime_error("fmspc mismatch");

        if (!json_vector_eq(tcbinfo_j, "pceId", pck_ext.pceid))
          throw std::runtime_error("pceid mismatch");

        uint64_t tcb_type = tcbinfo_j["tcbType"].get<uint64_t>();
        if (tcb_type != 0)
          throw std::runtime_error("tcbType not supported");

        // This is the TCB recovery event number, monotinically increasing.
        // Report as result?
        uint64_t tcb_eval_data_number =
          tcbinfo_j["tcbEvaluationDataNumber"].get<uint64_t>();

        for (const auto& tcb_level_j : tcbinfo_j["tcbLevels"])
        {
          std::string tcb_date = tcb_level_j["tcbDate"].get<std::string>();
          std::string tcb_status = tcb_level_j["tcbStatus"].get<std::string>();
          const auto& tcb = tcb_level_j["tcb"];

          size_t comp_svn_size = pck_ext.tcb.comp_svn.size();
          if (comp_svn_size != 16)
            throw std::runtime_error("unexpected comp_svn size");

          std::array<uint8_t, 16> tcb_level_comp_svn;
          for (size_t i = 0; i < comp_svn_size; i++)
          {
            std::string svn_name = fmt::format("sgxtcbcomp{:02d}svn", i + 1);
            tcb_level_comp_svn[i] = tcb[svn_name].get<uint8_t>();
          }
          uint16_t tcb_level_pce_svn = tcb["pcesvn"].get<uint16_t>();

          // optional advisoryIDs?

          if (platform_tcb_level.status.empty())
          {
            // See
            // https://github.com/openenclave/openenclave/blob/master/common/sgx/tcbinfo.c#L398
            // "Choose the first tcb level for which all of the platform's comp
            // svn values and pcesvn values are greater than or equal to
            // corresponding values of the tcb level."
            bool good = true;
            for (size_t i = 0; i < comp_svn_size && good; i++)
              good = good && pck_ext.tcb.comp_svn[i] >= tcb_level_comp_svn[i];
            good = good && pck_ext.tcb.pce_svn >= tcb_level_pce_svn;
            if (good)
            {
              platform_tcb_level = {
                tcb_level_comp_svn,
                tcb_level_pce_svn,
                tcb_status,
                tcb_date,
                std::vector<std::string>()};
            }
          }
        }

        if (platform_tcb_level.status.empty())
          throw std::runtime_error("no matching TCB level found");

        auto sig_j = col_tcb_info_j["signature"];
        signature = from_hex(sig_j.get<std::string>());
      }
      catch (const std::exception& ex)
      {
        throw std::runtime_error(
          std::string("incorrectly formatted SGX TCB: ") + ex.what());
      }
      catch (...)
      {
        throw std::runtime_error("incorrectly formatted SGX TCB");
      }

      // find the part of the json that was signed
      static const std::string pre = "{\"tcbInfo\":";
      static const std::string post = ",\"signature\"";

      auto l = tcb_info_s.find(pre);
      auto r = tcb_info_s.rfind(post);
      if (l == std::string::npos || r == std::string::npos)
        throw std::runtime_error("tcbInfo does not contain signature");

      std::span signed_msg = {
        (uint8_t*)tcb_info_s.data() + l + pre.size(),
        (uint8_t*)tcb_info_s.data() + r};

      if (!verify_signature(signer_pubkey, signed_msg, signature))
        throw std::runtime_error("tcbInfo signature verification failed");

      return platform_tcb_level;
    }

    TCBLevel verify_tcb(
      const std::span<uint8_t>& tcb_info_issuer_chain,
      const std::span<uint8_t>& tcb_info,
      const PCKCertificateExtensions& pck_ext,
      Unique_X509_STORE& store,
      const Options& options)
    {
      auto tcb_issuer_chain =
        get_verified_certificate_chain(tcb_info_issuer_chain, store, options);

      auto tcb_issuer_leaf = tcb_issuer_chain.front();
      auto tcb_issuer_root = tcb_issuer_chain.back();

      Unique_EVP_PKEY tcb_issuer_leaf_pubkey(tcb_issuer_leaf);

      if (!has_intel_public_key(tcb_issuer_root))
        throw std::runtime_error(
          "TCB issuer root certificate does not use the expected Intel SGX "
          "public key");

      return verify_tcb_json(tcb_info, pck_ext, tcb_issuer_leaf_pubkey);
    }

    bool verify_qe_id(
      const std::span<const uint8_t>& qe_identity_issuer_chain,
      const std::span<const uint8_t>& qe_identity,
      const std::span<const uint8_t>& qe_report_body_s,
      const TCBLevel& platform_tcb_level,
      const PCKCertificateExtensions& pck_ext,
      const Unique_X509_STORE& store,
      const Options& options)
    {
      const sgx_report_body_t& qe_report_body =
        *(sgx_report_body_t*)qe_report_body_s.data();
      auto qe_id_issuer_chain = get_verified_certificate_chain(
        qe_identity_issuer_chain, store, options);

      auto qe_id_issuer_leaf = qe_id_issuer_chain.at(0);
      auto qe_id_issuer_root =
        qe_id_issuer_chain.at(qe_id_issuer_chain.size() - 1);

      Unique_EVP_PKEY qe_id_issuer_leaf_pubkey(qe_id_issuer_leaf);

      if (!has_intel_public_key(qe_id_issuer_root))
        throw std::runtime_error(
          "QE identity issuer root certificate does not use the expected Intel "
          "SGX public key");

      std::string qe_identity_s = {
        (char*)qe_identity.data(), qe_identity.size()};
      std::vector<uint8_t> signature;

      try
      {
        std::string qe_tcb_level_status = "";
        std::string qe_tcb_date = "";
        uint16_t qe_tcb_level_isv_svn = 0;

        auto qe_id_j = nlohmann::json::parse(qe_identity_s);
        auto enclave_identity = qe_id_j["enclaveIdentity"];

        auto version = enclave_identity["version"].get<uint64_t>();
        if (version != 2)
          throw std::runtime_error("enclaveIdentity version not supported");

        auto eid_id = enclave_identity["id"].get<std::string>();
        if (eid_id != "QE" && eid_id != "QVE")
          throw std::runtime_error("QE identity type not supported");

        for (const auto& tcb_level : enclave_identity["tcbLevels"])
        {
          auto tcb_j = tcb_level["tcb"];
          uint16_t tcb_level_isv_svn = tcb_j["isvsvn"].get<uint16_t>();
          auto tcb_date = tcb_level["tcbDate"];
          auto tcb_status = tcb_level["tcbStatus"].get<std::string>();

          if (qe_tcb_level_status.empty())
          {
            // See
            // https://github.com/openenclave/openenclave/blob/master/common/sgx/tcbinfo.c#L1023
            // "Choose the first tcb level for which all of the platform's isv
            // svn values are greater than or equal to corresponding values of
            // the tcb level."
            if (qe_report_body.isv_svn >= tcb_level_isv_svn)
            {
              qe_tcb_level_status = tcb_status;
              qe_tcb_date = tcb_date;
              qe_tcb_level_isv_svn = tcb_level_isv_svn;

              // TODO: optional advisories?
            }
          }
        }

        if (qe_tcb_level_status.empty())
          throw std::runtime_error("no matching QE TCB level found");

        auto id = enclave_identity["issueDate"].get<std::string>();
        check_datetime(id, "QE TCB issue date");
        auto nu = enclave_identity["nextUpdate"].get<std::string>();
        check_datetime(nu, "QE TCB next update");

        std::vector<uint8_t> reported_mrsigner = {
          &qe_report_body.mr_signer.m[0],
          &qe_report_body.mr_signer.m[0] + sizeof(qe_report_body.mr_signer.m)};

        if (
          from_hex(enclave_identity["mrsigner"].get<std::string>()) !=
          reported_mrsigner)
          throw std::runtime_error("QE mrsigner mismatch");

        if (
          enclave_identity["isvprodid"].get<uint16_t>() !=
          qe_report_body.isv_prod_id)
          throw std::runtime_error("QE isv prod id mismatch");

        if (qe_tcb_level_isv_svn >= qe_report_body.isv_svn)
          throw std::runtime_error("QE isv svn too small");

        uint32_t msel_mask = from_hex_t<uint32_t>(
          enclave_identity["miscselectMask"].get<std::string>());
        uint32_t msel = from_hex_t<uint32_t>(
          enclave_identity["miscselect"].get<std::string>());
        if ((qe_report_body.misc_select & msel_mask) != msel)
          throw std::runtime_error("misc select mismatch");

        auto attribute_flags_xfrm_s =
          enclave_identity["attributes"].get<std::string>();
        auto attribute_flags_xfrm_mask_s =
          enclave_identity["attributesMask"].get<std::string>();

        if (
          attribute_flags_xfrm_s.size() != 32 ||
          attribute_flags_xfrm_mask_s.size() != 32)
          throw std::runtime_error("unexpected attribute value sizes");

        auto flags_s = attribute_flags_xfrm_s.substr(0, 16);
        auto xfrm_s = attribute_flags_xfrm_s.substr(16);
        auto flags_mask_s = attribute_flags_xfrm_mask_s.substr(0, 16);
        auto xfrm_mask_s = attribute_flags_xfrm_mask_s.substr(16);

        uint64_t flags = from_hex_t<uint64_t>(flags_s);
        uint64_t xfrm = from_hex_t<uint64_t>(xfrm_s);
        uint64_t flags_mask = from_hex_t<uint64_t>(flags_mask_s);
        uint64_t xfrm_mask = from_hex_t<uint64_t>(xfrm_mask_s);

        if ((qe_report_body.attributes.flags & flags_mask) != flags)
          throw std::runtime_error("attribute flags mismatch");

        if ((qe_report_body.attributes.xfrm & xfrm_mask) != xfrm)
          throw std::runtime_error("attribute xfrm mismatch");

        if (qe_report_body.attributes.flags & SGX_FLAGS_DEBUG)
          throw std::runtime_error("report purported to be from debug QE");

        auto sig_j = qe_id_j["signature"];
        signature = from_hex(sig_j.get<std::string>());
      }
      catch (const std::exception& ex)
      {
        throw std::runtime_error(
          std::string("incorrectly formatted SGX QE ID: ") + ex.what());
      }
      catch (...)
      {
        throw std::runtime_error("incorrectly formatted SGX QE ID");
      }

      // find the part of the json that was signed
      static const std::string& pre = "\"enclaveIdentity\":";
      static const std::string& post = ",\"signature\":\"";

      auto l = qe_identity_s.find(pre);
      auto r = qe_identity_s.rfind(post);
      if (l == std::string::npos || r == std::string::npos)
        throw std::runtime_error("QE identity does not contain signature");

      std::span signed_msg = {
        (uint8_t*)qe_identity_s.data() + l + pre.size(),
        (uint8_t*)qe_identity_s.data() + r};

      if (!verify_signature(qe_id_issuer_leaf_pubkey, signed_msg, signature))
        throw std::runtime_error("QE identity signature verification failed");

      return true;
    }

    std::span<const uint8_t> parse_quote(const Attestation& a)
    {
      static constexpr size_t sgx_quote_t_signed_size =
        sizeof(sgx_quote_t) - sizeof(uint32_t); // (minus signature_len)

      // TODO: Endianness, e.g. for sizes?

      const sgx_quote_t* quote = (sgx_quote_t*)a.evidence.data();

      if (a.evidence.size() < (sizeof(sgx_quote_t) + quote->signature_len))
        throw std::runtime_error(
          "Unknown evidence format: too small to contain an sgx_quote_t");

      std::span r = {(uint8_t*)quote, sgx_quote_t_signed_size};
      check_within(r, a.evidence);

      if (quote->version != SGX_QUOTE_VERSION)
        throw std::runtime_error(
          "Unknown evidence format: unsupported quote version");

      if (quote->sign_type != SGX_QL_ALG_ECDSA_P256)
        throw std::runtime_error(
          "Unknown evidence format: unsupported signing type");

      // if (a.evidence.size() > (sizeof(sgx_quote_t) + quote->signature_len))
      //   throw std::runtime_error(
      //     "Unsupported evidence format: excess evidence data");

      return r;
    }

    struct SignatureData // ~ _sgx_ql_ecdsa_sig_data_t
    {
      std::span<const uint8_t> report;
      std::span<const uint8_t> report_signature;
      std::span<const uint8_t> quote_signature;
      std::span<const uint8_t> public_key;
      std::span<const uint8_t> report_hash;
      std::span<const uint8_t> auth_data;
      std::span<const uint8_t> certification_data;
    };

    SignatureData parse_signature_data(
      const std::span<const uint8_t>& quote, const Attestation& a)
    {
      SignatureData r;

      // TODO: Endianness, e.g. for sizes?

      const sgx_ql_ecdsa_sig_data_t* sig_data =
        (sgx_ql_ecdsa_sig_data_t*)((const sgx_quote_t*)quote.data())->signature;

      if (sig_data == NULL)
        throw std::runtime_error("missing signature data");

      std::span sig_data_span = {(uint8_t*)sig_data, sizeof(*sig_data)};
      check_within(sig_data_span, a.evidence);

      r.report = {(uint8_t*)&sig_data->qe_report, sizeof(sig_data->qe_report)};
      check_within(r.report, a.evidence);

      r.report_signature = {
        sig_data->qe_report_sig, sizeof(sig_data->qe_report_sig)};
      check_within(r.report_signature, a.evidence);

      r.quote_signature = {sig_data->sig, sizeof(sig_data->sig)};
      check_within(r.quote_signature, a.evidence);

      r.public_key = {
        sig_data->attest_pub_key, sizeof(sig_data->attest_pub_key)};
      check_within(r.public_key, a.evidence);

      r.report_hash = {
        sig_data->qe_report.report_data.d, 32}; // SGX_REPORT_DATA_SIZE is 64?!
      check_within(r.report_hash, a.evidence);

      const sgx_ql_auth_data_t* ad_raw =
        (sgx_ql_auth_data_t*)sig_data->auth_certification_data;

      r.auth_data = {ad_raw->auth_data, ad_raw->size};
      check_within(r.auth_data, a.evidence);

      if (ad_raw == NULL || ad_raw->size == 0)
        throw std::runtime_error("missing authentication data");

      const sgx_ql_certification_data_t* cd_raw =
        (sgx_ql_certification_data_t*)(sig_data->auth_certification_data + sizeof(sgx_ql_auth_data_t) + ad_raw->size);

      r.certification_data = {cd_raw->certification_data, cd_raw->size};
      check_within(r.certification_data, a.evidence);

      if (cd_raw == NULL || cd_raw->size == 0)
        throw std::runtime_error("missing certification data");

      if (cd_raw->cert_key_type != PCK_CERT_CHAIN)
        throw std::runtime_error("unsupported certification data key type");

      return r;
    }

    bool verify(const Attestation& a, const Options& options)
    {
      std::span quote = parse_quote(a);
      SignatureData signature_data = parse_signature_data(quote, a);

      Unique_X509_STORE store;
      std::shared_ptr<QL_QVE_Collateral> collateral = nullptr;
      std::vector<uint8_t> root_ca_pem = {};

      if (!a.endorsements.empty() && !options.fresh_endorsements)
      {
        collateral = std::make_shared<QL_QVE_Collateral>(a.endorsements);

        if (options.root_ca_certificate_pem)
          root_ca_pem = *options.root_ca_certificate_pem;
        else if (options.fresh_root_ca_certificate)
          root_ca_pem = download_root_ca_pem();
      }
      else
      {
        // Get X509 extensions from the PCK cert to find CA type and fmspc. The
        // cert chain is still unverified at this point.
        auto pck_pem = extract_pem(signature_data.certification_data);
        Unique_X509 pck_leaf(Unique_BIO(pck_pem), true);
        auto pck_ext = get_pck_certificate_extensions(pck_leaf);

        bool have_pid = pck_ext.platform_instance_id &&
          !is_all_zero(*pck_ext.platform_instance_id);
        auto ca_type = have_pid ? "platform" : "processor";
        auto fmspc_hex = fmt::format("{:02x}", fmt::join(pck_ext.fmspc, ""));
        collateral = download_collateral(ca_type, fmspc_hex);

        if (options.root_ca_certificate_pem)
          root_ca_pem = *options.root_ca_certificate_pem;
        else
          root_ca_pem = download_root_ca_pem();
      }

      // These flags also check that we have a CRL for each CA.
      store.set_flags(X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
      store.add_crl(collateral->root_ca_crl);
      store.add_crl(collateral->pck_crl);

      bool trusted_root = false;

      if (!root_ca_pem.empty())
        store.add(root_ca_pem);
      else
        trusted_root = true;

      // Validate PCK certificate and it's issuer chain. We trust the root CA
      // certificate in the endorsements if no other one is provided, but check
      // that it has Intel's public key afterwards.
      auto pck_crl_issuer_chain = get_verified_certificate_chain(
        collateral->pck_crl_issuer_chain, store, options, trusted_root);

      auto pck_cert_chain = get_verified_certificate_chain(
        signature_data.certification_data, store, options, trusted_root);

      auto pck_leaf = pck_cert_chain.front();
      auto pck_root = pck_cert_chain.back();

      if (!has_pck_common_name(pck_leaf))
        throw std::runtime_error(
          "PCK certificate does not have expected common name");

      if (!has_intel_public_key(pck_root))
        throw std::runtime_error(
          "root certificate does not have the expected Intel SGX public key");

      if (!pck_root.is_ca())
        throw std::runtime_error("root certificate is not from a CA");

      // Verify QE and quote signatures and the authentication hash
      Unique_EVP_PKEY qe_leaf_pubkey(pck_leaf);

      bool qe_sig_ok = verify_signature(
        qe_leaf_pubkey, signature_data.report, signature_data.report_signature);
      if (!qe_sig_ok)
        throw std::runtime_error("QE signature verification failed");

      bool quote_sig_ok = verify_signature(
        signature_data.public_key, quote, signature_data.quote_signature);
      if (!quote_sig_ok)
        throw std::runtime_error("quote signature verification failed");

      bool pk_auth_hash_matches = verify_hash_match(
        {signature_data.public_key, signature_data.auth_data},
        signature_data.report_hash);
      if (!pk_auth_hash_matches)
        throw std::runtime_error("QE authentication message hash mismatch");

      // Verify TCB information
      auto pck_x509_ext = get_pck_certificate_extensions(pck_leaf);
      auto platform_tcb_level = verify_tcb(
        collateral->tcb_info_issuer_chain,
        collateral->tcb_info,
        pck_x509_ext,
        store,
        options);

      // Verify the QE identity
      bool qe_id_ok = verify_qe_id(
        collateral->qe_identity_issuer_chain,
        collateral->qe_identity,
        signature_data.report,
        platform_tcb_level,
        pck_x509_ext,
        store,
        options);

      return pck_cert_chain && qe_sig_ok && pk_auth_hash_matches &&
        quote_sig_ok && qe_id_ok;
    }
  }
}
