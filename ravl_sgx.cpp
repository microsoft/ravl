// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "ravl_sgx.h"

#include "openssl_wrappers.h"
#include "ravl_requests.h"

#include <curl/curl.h>
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

    static constexpr size_t sgx_quote_t_signed_size =
      sizeof(sgx_quote_t) - sizeof(uint32_t); // (minus signature_len)

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
      BUF_MEM* bptr;
      X509_print(bio, certificate);
      BIO_get_mem_ptr(bio, &bptr);
      std::string certificate_s = {bptr->data, bptr->data + bptr->length};
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
      const void* ptr, const std::vector<uint8_t>& vec)
    {
      if (!(vec.data() <= ptr && ptr < (vec.data() + vec.size())))
        throw std::runtime_error("invalid pointer");
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

      std::vector<uint8_t> root_ca;
    };

    Unique_EC_KEY key_from_coordinates(
      const std::span<const uint8_t>& public_key)
    {
      Unique_EC_KEY ec_key(NID_X9_62_prime256v1);
      Unique_BIGNUM x(BN_bin2bn(&public_key[0], 32, NULL));
      Unique_BIGNUM y(BN_bin2bn(&public_key[32], 32, NULL));
      CHECK1(EC_KEY_set_public_key_affine_coordinates(ec_key, x, y));
      return ec_key;
    }

    static std::vector<uint8_t> convert_signature_to_der(
      const std::vector<uint8_t>& signature)
    {
      return convert_signature_to_der({signature.begin(), signature.end()});
    }

    static std::vector<uint8_t> convert_signature_to_der(
      const std::span<const uint8_t>& signature)
    {
      auto signature_size = signature.size();
      auto half_size = signature_size / 2;
      Unique_ECDSA_SIG sig;
      {
        Unique_BIGNUM r;
        Unique_BIGNUM s;
        CHECKNULL(BN_bin2bn(signature.data(), half_size, r));
        CHECKNULL(BN_bin2bn(signature.data() + half_size, half_size, s));
        CHECK1(ECDSA_SIG_set0(sig, r, s));
        r.release(); // r, s now owned by the signature object
        s.release();
      }
      auto der_size = i2d_ECDSA_SIG(sig, NULL);
      CHECK0(der_size);
      std::vector<uint8_t> res(der_size);
      auto der_sig_buf = res.data();
      CHECK0(i2d_ECDSA_SIG(sig, &der_sig_buf));
      return res;
    }

    static void convert_signature_to_ieee_p1363(
      std::vector<uint8_t>& sig, size_t coordinate_size)
    {
      // Convert signature from ASN.1 format to IEEE P1363
      Unique_ECDSA_SIG sig_r_s(sig);
      const BIGNUM* r = ECDSA_SIG_get0_r(sig_r_s);
      const BIGNUM* s = ECDSA_SIG_get0_s(sig_r_s);
      int r_n = BN_num_bytes(r);
      int s_n = BN_num_bytes(s);
      size_t sz = coordinate_size;
      sig = std::vector<uint8_t>(2 * sz, 0);
      BN_bn2binpad(r, sig.data(), sz);
      BN_bn2binpad(s, sig.data() + sz, sz);
    }

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
      const std::span<const uint8_t>& public_key,
      const std::span<const uint8_t>& message,
      const std::span<const uint8_t>& signature)
    {
      auto eckey = key_from_coordinates(public_key);
      Unique_EVP_PKEY pkey(eckey);
      return verify_signature(pkey, message, signature);
    }

    static bool check_hash_match(
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

    static std::vector<std::string> extract_pems(char* data, size_t size)
    {
      std::vector<std::string> r;
      std::string certstrs(data, size);
      std::string begin = "-----BEGIN CERTIFICATE-----";
      std::string end = "-----END CERTIFICATE-----";
      auto from = certstrs.find(begin);
      while (from != std::string::npos)
      {
        auto to = certstrs.find(end, from);
        if (to == std::string::npos)
          break;
        to += end.size();
        auto pem = certstrs.substr(from, to - from);
        r.push_back(pem);
        from = certstrs.find(begin, to);
      }
      return r;
    }

    void add_crl(Unique_X509_STORE& store, const std::vector<uint8_t>& data)
    {
      if (!data.empty())
      {
        Unique_BIO bio(data.data(), data.size());
        Unique_X509_CRL crl(
          bio); // TODO: PEM only; some CRLs may be in DER format?
        X509_STORE_add_crl(store, crl);
      }
    }

    std::pair<struct tm, struct tm> get_validity_range(
      const Unique_STACK_OF_X509& chain)
    {
      if (!chain || chain.size() == 0)
        throw std::runtime_error(
          "no certificate change to compute validity ranges for");

      ASN1_TIME *latest_from = nullptr, *earliest_to = nullptr;
      for (size_t i = 0; i < chain.size(); i++)
      {
        const X509* c = chain.at(i);
        ASN1_TIME* not_before = X509_get_notBefore(c);
        if (!latest_from || ASN1_TIME_compare(latest_from, not_before) == -1)
          latest_from = not_before;
        ASN1_TIME* not_after = X509_get_notAfter(c);
        if (!earliest_to || ASN1_TIME_compare(earliest_to, not_after) == 1)
          earliest_to = not_after;
      }

      Unique_BIO mem;
      BUF_MEM* bptr;
      CHECK1(ASN1_TIME_print(mem, latest_from));
      BIO_get_mem_ptr(mem, &bptr);
      std::string latest_from_str(bptr->data, bptr->length);

      BIO_reset(mem);
      CHECK1(ASN1_TIME_print(mem, earliest_to));
      BIO_get_mem_ptr(mem, &bptr);
      std::string earliest_to_str(bptr->data, bptr->length);

      std::pair<struct tm, struct tm> r;
      ASN1_TIME_to_tm(latest_from, &r.first);
      ASN1_TIME_to_tm(earliest_to, &r.second);
      return r;
    }

    Unique_ASN1_TYPE get_obj_value(
      ASN1_SEQUENCE_ANY* seq,
      int index,
      const std::string& expected_oid,
      int expected_value_type)
    {
      ASN1_TYPE* type = sk_ASN1_TYPE_value(seq, index);
      if (type->type != V_ASN1_SEQUENCE)
        throw std::runtime_error("incorrectly formatted SGX extension");

      Unique_ASN1_SEQUENCE ss(type->value.sequence);

      if (sk_ASN1_TYPE_num(ss) != 2)
        throw std::runtime_error("incorrectly formatted SGX extension");

      // OID
      ASN1_TYPE* tt = sk_ASN1_TYPE_value(ss, 0);
      if (tt->type != V_ASN1_OBJECT)
        throw std::runtime_error("incorrectly formatted SGX extension");

      ASN1_OBJECT* obj = tt->value.object;

      if (OBJ_cmp(obj, Unique_ASN1_OBJECT(expected_oid)) != 0)
        throw std::runtime_error("incorrectly formatted SGX extension");

      // VALUE
      ASN1_TYPE* tv = sk_ASN1_TYPE_value(ss, 1);
      if (tv->type != expected_value_type)
        throw std::runtime_error("incorrectly formatted SGX extension");

      return Unique_ASN1_TYPE(tv);
    }

    std::vector<uint8_t> get_octet_string_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      Unique_ASN1_TYPE v =
        get_obj_value(seq, index, expected_oid, V_ASN1_OCTET_STRING);

      ASN1_TYPE* vp = v;

      return std::vector<uint8_t>(
        vp->value.octet_string->data,
        vp->value.octet_string->data + vp->value.octet_string->length);
    }

    Unique_ASN1_SEQUENCE get_seq_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(seq, index, expected_oid, V_ASN1_SEQUENCE);
      return Unique_ASN1_SEQUENCE(((ASN1_TYPE*)v)->value.sequence);
    }

    Unique_ASN1_OBJECT get_obj_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(seq, index, expected_oid, V_ASN1_OBJECT);
      return Unique_ASN1_OBJECT(((ASN1_TYPE*)v)->value.object);
    }

    bool get_bool_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(seq, index, expected_oid, V_ASN1_BOOLEAN);
      return ((ASN1_TYPE*)v)->value.boolean;
    }

    uint8_t get_uint8_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(seq, index, expected_oid, V_ASN1_INTEGER);

      Unique_BIGNUM bn;
      ASN1_INTEGER_to_BN(((ASN1_TYPE*)v)->value.integer, bn);
      auto num_bytes BN_num_bytes(bn);
      int is_zero = BN_is_zero(bn);
      if (num_bytes != 1 && !is_zero)
        throw std::runtime_error("incorrectly formatted SGX extension");
      uint8_t r = 0;
      BN_bn2bin(bn, &r);
      return r;
    }

    uint16_t get_uint16_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(seq, index, expected_oid, V_ASN1_INTEGER);

      Unique_BIGNUM bn;
      ASN1_INTEGER_to_BN(((ASN1_TYPE*)v)->value.integer, bn);
      auto num_bytes BN_num_bytes(bn);
      if (num_bytes > 2)
        throw std::runtime_error("incorrectly formatted SGX extension");
      std::vector<uint8_t> r(num_bytes);
      BN_bn2bin(bn, r.data());
      return num_bytes == 0 ? 0 : num_bytes == 1 ? r[0] : (r[0] | r[1] << 8);
    }

    int64_t get_enum_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(seq, index, expected_oid, V_ASN1_ENUMERATED);
      auto vp = ((ASN1_TYPE*)v);
      int64_t r = 0;
      CHECK1(ASN1_ENUMERATED_get_int64(&r, vp->value.enumerated));
      return r;
    }

    struct TCB
    {
      std::array<uint8_t, 16> comp_svn;
      uint16_t pce_svn;
      std::array<uint8_t, 16> cpu_svn;
    };

    TCB get_tcb_ext(
      ASN1_SEQUENCE_ANY* seq, int index, const std::string& expected_oid)
    {
      TCB r;

      auto sss = get_seq_ext(seq, index, expected_oid);

      int n = sk_ASN1_TYPE_num(sss);
      if (n != 18)
        throw std::runtime_error("incorrectly formatted SGX extension");

      for (int i = 0; i < n; i++)
      {
        std::string expected_oid_i =
          std::string(sgx_ext_tcb_oid) + "." + std::to_string(i + 1);

        if (i < 16)
          r.comp_svn[i] = get_uint8_ext(sss, i, expected_oid_i);
        else if (i == 16)
          r.pce_svn = get_uint16_ext(sss, i, expected_oid_i);
        else if (i == 17)
        {
          auto t = get_octet_string_ext(sss, i, expected_oid_i);
          if (t.size() != 16)
            throw std::runtime_error("incorrectly formatted SGX extension");
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

    std::shared_ptr<QL_QVE_Collateral> get_collateral(
      const std::string& ca, const std::string& fmspc, bool qve = false)
    {
      auto r = std::make_shared<QL_QVE_Collateral>();

      r->major_version = 3;
      r->minor_version = 1;
      r->tee_type = 0;

      // Root CA and CRL. Note: cert may be newer than the one in the evidence?
      auto response = Request{
        .url =
          "https://certificates.trustedservices.intel.com/"
          "Intel_SGX_Provisioning_Certification_RootCA.pem"}();

      r->root_ca = str2vec(response.body);

      // TODO: Get URL from the CRL distribution point in the cert? Only DER?
      response = Request{
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

      std::optional<std::vector<uint8_t>> platform_instance_id;

      struct Configuration
      {
        bool dynamic_platform;
        bool cached_keys;
        bool smt_enabled;
      };

      std::optional<Configuration> configuration;
    };

    PCKCertificateExtensions get_pck_certificate_extensions(
      const X509* pck_certificate)
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

      int seq_sz = sk_ASN1_TYPE_num(seq);
      if (seq_sz != 5 && seq_sz != 7)
        throw std::runtime_error("incorrectly formatted SGX extension");

      PCKCertificateExtensions r;

      r.ppid = get_octet_string_ext(seq, 0, sgx_ext_ppid_oid);
      r.tcb = get_tcb_ext(seq, 1, sgx_ext_tcb_oid);
      r.pceid = get_octet_string_ext(seq, 2, sgx_ext_pceid_oid);
      r.fmspc = get_octet_string_ext(seq, 3, sgx_ext_fmspc_oid);
      r.sgx_type = get_enum_ext(seq, 4, sgx_ext_type_oid) != 0;

      if (seq_sz > 5)
      {
        r.platform_instance_id =
          get_octet_string_ext(seq, 5, sgx_ext_platform_instance_oid);

        // Platform-CA certificates come with these extensions, but only
        // existence and order is verified here.
        auto config_seq = get_seq_ext(seq, 6, sgx_ext_configuration_oid);
        int seq_sz = sk_ASN1_TYPE_num(config_seq);
        if (seq_sz != 3)
          throw std::runtime_error("incorrectly formatted SGX extension");

        auto dyn_platform = get_bool_ext(
          config_seq, 0, sgx_ext_configuration_dynamic_platform_oid);
        auto cached_keys =
          get_bool_ext(config_seq, 1, sgx_ext_configuration_cached_keys_oid);
        auto smt_enabled =
          get_bool_ext(config_seq, 2, sgx_ext_configuration_smt_enabled_oid);

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
      Unique_X509_STORE& store,
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
      Unique_X509_STORE& store, const std::vector<std::string>& certificates)
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
          const ASN1_OCTET_STRING* subj_key_id = X509_get0_subject_key_id(i);

          bool i_appears_as_ca = false;
          for (size_t ji = 0; ji < r.size(); ji++)
          {
            if (ii == ji)
              continue;

            const auto& j = r.at(ji);

            const ASN1_OCTET_STRING* auth_key_id =
              X509_get0_authority_key_id(j);

            if (ASN1_OCTET_STRING_cmp(subj_key_id, auth_key_id) == 0)
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
      const std::span<const uint8_t>& data,
      Unique_X509_STORE& store,
      const Options& options,
      bool trusted_root = false)
    {
      std::vector<std::string> certificates =
        extract_pems((char*)data.data(), data.size());

      auto stack = load_certificates(store, certificates);
      auto chain =
        verify_certificate_chain(store, stack, options, trusted_root);

      if (chain.size() < 2)
        throw std::runtime_error("certificate chain is too short");

      return chain;
    }

    bool has_intel_public_key(X509* certificate)
    {
      Unique_EVP_PKEY pubkey(X509_get_pubkey(certificate));
      Unique_BIO bio(intel_root_public_key_pem);
      Unique_EVP_PKEY intel_pkey(bio, true);
      bool pk_params_eq = EVP_PKEY_cmp_parameters(pubkey, intel_pkey) != 0;
      return pk_params_eq && EVP_PKEY_cmp(pubkey, intel_pkey) == 1;
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

    TCBLevel check_tcb_json(
      const std::span<uint8_t>& tcb_info,
      const PCKCertificateExtensions& pck_ext,
      const Unique_EVP_PKEY& signer_pubkey)
    {
      TCBLevel platform_tcb_level = {0};

      std::vector<uint8_t> signature;
      const static std::string pre = "{\"tcbInfo\":";
      const static std::string post = ",\"signature\"";

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

    TCBLevel check_tcb(
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

      Unique_EVP_PKEY tcb_issuer_leaf_pubkey(X509_get_pubkey(tcb_issuer_leaf));

      if (!has_intel_public_key(tcb_issuer_root))
        throw std::runtime_error(
          "TCB issuer root certificate does not use the expected Intel SGX "
          "public key");

      return check_tcb_json(tcb_info, pck_ext, tcb_issuer_leaf_pubkey);
    }

    void check_qe_id(
      const std::span<uint8_t>& qe_identity_issuer_chain,
      const std::span<uint8_t>& qe_identity,
      const sgx_report_body_t& qe_report_body,
      const TCBLevel& platform_tcb_level,
      const PCKCertificateExtensions& pck_ext,
      Unique_X509_STORE& store,
      const Options& options)
    {
      auto qe_id_issuer_chain = get_verified_certificate_chain(
        qe_identity_issuer_chain, store, options);

      auto qe_id_issuer_leaf = qe_id_issuer_chain.at(0);
      auto qe_id_issuer_root =
        qe_id_issuer_chain.at(qe_id_issuer_chain.size() - 1);

      Unique_EVP_PKEY qe_id_issuer_leaf_pubkey(
        X509_get_pubkey(qe_id_issuer_leaf));

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

      const std::string& pre = "\"enclaveIdentity\":";
      const std::string& post = ",\"signature\":\"";

      // find the part of the json that was signed
      auto l = qe_identity_s.find(pre);
      auto r = qe_identity_s.rfind(post);
      if (l == std::string::npos || r == std::string::npos)
        throw std::runtime_error("QE identity does not contain signature");

      std::span signed_msg = {
        (uint8_t*)qe_identity_s.data() + l + pre.size(),
        (uint8_t*)qe_identity_s.data() + r};

      if (!verify_signature(qe_id_issuer_leaf_pubkey, signed_msg, signature))
        throw std::runtime_error("QE identity signature verification failed");
    }

    bool verify(const Attestation& a, const Options& options)
    {
      const sgx_quote_t* quote = (sgx_quote_t*)a.evidence.data();

      if (a.evidence.size() < (sizeof(sgx_quote_t) + quote->signature_len))
        throw std::runtime_error(
          "Unknown evidence format: too small to contain an sgx_quote_t");

      if (quote->version != SGX_QUOTE_VERSION)
        throw std::runtime_error(
          "Unknown evidence format: unsupported quote version");

      if (quote->sign_type != SGX_QL_ALG_ECDSA_P256)
        throw std::runtime_error(
          "Unknown evidence format: unsupported signing type");

      // if (a.evidence.size() > (sizeof(sgx_quote_t) + quote->signature_len))
      //   throw std::runtime_error(
      //     "Unsupported evidence format: excess evidence data");

      // TODO: Endianness, e.g. for size?
      const sgx_ql_ecdsa_sig_data_t* sig_data =
        (sgx_ql_ecdsa_sig_data_t*)quote->signature;

      if (sig_data == NULL)
        throw std::runtime_error("missing signature data");

      check_within(sig_data, a.evidence);

      const sgx_ql_auth_data_t* auth_data =
        (sgx_ql_auth_data_t*)sig_data->auth_certification_data;

      if (auth_data == NULL || auth_data->size == 0)
        throw std::runtime_error("missing authentication data");

      check_within(auth_data, a.evidence);

      const sgx_ql_certification_data_t* certification_data =
        (sgx_ql_certification_data_t*)(sig_data->auth_certification_data + sizeof(sgx_ql_auth_data_t) + auth_data->size);

      if (certification_data == NULL || certification_data->size == 0)
        throw std::runtime_error("missing certification data");

      check_within(certification_data, a.evidence);

      if (certification_data->cert_key_type != PCK_CERT_CHAIN)
        throw std::runtime_error("unsupported certification data key type");

      Unique_X509_STORE store;
      std::shared_ptr<QL_QVE_Collateral> col = nullptr;

      if (!a.endorsements.empty() && !options.fresh_endorsements)
      {
        col = std::make_shared<QL_QVE_Collateral>(a.endorsements);
        // col->root_ca is empty; who do we trust?
      }
      else
      {
        // Get the PCK cert, without having CRLs yet (those are in the
        // collateral). This is just to get the CA type and the fmspc from the
        // certificate extensions.
        auto pck_cert_chain = get_verified_certificate_chain(
          {certification_data->certification_data, certification_data->size},
          store,
          options,
          true);

        auto pck_leaf = pck_cert_chain.front();
        auto pck_ext = get_pck_certificate_extensions(pck_leaf);

        auto ca_type = !pck_ext.platform_instance_id ||
            is_all_zero(*pck_ext.platform_instance_id) ?
          "processor" :
          "platform";
        auto fmspc_hex = fmt::format("{:02x}", fmt::join(pck_ext.fmspc, ""));
        col = get_collateral(ca_type, fmspc_hex);
      }

      // These flags check also that we have a CRL for each CA.
      X509_STORE_set_flags(
        store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
      add_crl(store, col->root_ca_crl);
      add_crl(store, col->pck_crl);

      // Validate PCK certificate and chain (now with CRLs).
      bool trusted_root = col->root_ca.empty(); // TODO: who do we trust?
      auto pck_crl_issuer_chain = get_verified_certificate_chain(
        col->pck_crl_issuer_chain, store, options, trusted_root);

      auto pck_cert_chain = get_verified_certificate_chain(
        {certification_data->certification_data, certification_data->size},
        store,
        options);

      auto pck_leaf = pck_cert_chain.front();
      auto pck_root = pck_cert_chain.back();

      if (!has_pck_common_name(pck_leaf))
        throw std::runtime_error(
          "PCK certificate does not have expected common name");

      if (!has_intel_public_key(pck_root))
        throw std::runtime_error(
          "root certificate does not have the expected Intel SGX public key");

      if (X509_check_ca(pck_root) == 0)
        throw std::runtime_error("root certificate is not from a CA");

      auto val_range = get_validity_range(
        pck_cert_chain); // Check? Return in a results object?

      auto pck_ext = get_pck_certificate_extensions(pck_leaf);

      Unique_EVP_PKEY qe_leaf_pubkey(X509_get_pubkey(pck_leaf));

      std::span qe_report_span = {
        (uint8_t*)&sig_data->qe_report, sizeof(sig_data->qe_report)};
      std::span qe_sig_span = {
        sig_data->qe_report_sig, sizeof(sig_data->qe_report_sig)};

      bool qe_sig_ok =
        verify_signature(qe_leaf_pubkey, qe_report_span, qe_sig_span);
      if (!qe_sig_ok)
        throw std::runtime_error("QE signature verification failed");

      std::span pk_span = {
        sig_data->attest_pub_key, sizeof(sig_data->attest_pub_key)};
      std::span auth_data_span = {auth_data->auth_data, auth_data->size};
      std::span report_hash_span = {sig_data->qe_report.report_data.d, 32};

      bool pk_auth_hash_matches =
        check_hash_match({pk_span, auth_data_span}, report_hash_span);
      if (!pk_auth_hash_matches)
        throw std::runtime_error("QE authentication message hash mismatch");

      std::span quote_span = {(uint8_t*)quote, sgx_quote_t_signed_size};
      std::span sig_span = {sig_data->sig, sizeof(sig_data->sig)};

      bool quote_sig_ok = verify_signature(pk_span, quote_span, sig_span);
      if (!quote_sig_ok)
        throw std::runtime_error("quote signature verification failed");

      if (col)
      {
        auto platform_tcb_level = check_tcb(
          col->tcb_info_issuer_chain, col->tcb_info, pck_ext, store, options);

        check_qe_id(
          col->qe_identity_issuer_chain,
          col->qe_identity,
          sig_data->qe_report,
          platform_tcb_level,
          pck_ext,
          store,
          options);
      }

      return pck_cert_chain && qe_sig_ok && pk_auth_hash_matches &&
        quote_sig_ok;
    }
  }
}
