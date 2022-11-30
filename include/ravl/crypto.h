// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include "crypto_options.h"
#include "util.h"

#include <chrono>
#include <cstring>
#include <memory>
#include <openssl/err.h>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#ifdef RAVL_HAVE_OPENSSL
#  include "ravl/openssl.hpp"
#else
#  error No crypto library available.
#endif

namespace ravl
{
  namespace crypto
  {
    using UqBIO = OpenSSL::UqBIO;
    using UqX509 = OpenSSL::UqX509;
    using UqX509_CRL = OpenSSL::UqX509_CRL;
    using UqX509_REVOKED = OpenSSL::UqX509_REVOKED;
    using UqStackOfX509 = OpenSSL::UqStackOfX509;
    using UqASN1_OCTET_STRING = OpenSSL::UqASN1_OCTET_STRING;
    using UqX509_STORE = OpenSSL::UqX509_STORE;
    using UqEVP_MD_CTX = OpenSSL::UqEVP_MD_CTX;
    using UqEVP_PKEY = OpenSSL::UqEVP_PKEY;
    using UqASN1_SEQUENCE = OpenSSL::UqASN1_SEQUENCE;

    inline std::string to_base64(const std::span<const uint8_t>& bytes)
    {
      UqBIO bio_chain((UqBIO(BIO_f_base64())), UqBIO());

      BIO_set_flags(bio_chain, BIO_FLAGS_BASE64_NO_NL);
      BIO_set_close(bio_chain, BIO_CLOSE);
      int n = BIO_write(bio_chain, bytes.data(), bytes.size());
      BIO_flush(bio_chain);

      if (n < 0)
        throw std::runtime_error("base64 encoding error");

      return (std::string)bio_chain;
    }

    inline std::vector<uint8_t> from_base64(const std::string& b64)
    {
      UqBIO bio_chain((UqBIO(BIO_f_base64())), UqBIO(b64));

      std::vector<uint8_t> out(b64.size());
      BIO_set_flags(bio_chain, BIO_FLAGS_BASE64_NO_NL);
      BIO_set_close(bio_chain, BIO_CLOSE);
      int n = BIO_read(bio_chain, out.data(), b64.size());

      if (n < 0)
        throw std::runtime_error("base64 decoding error");

      out.resize(n);

      return out;
    }

    struct UqEVP_PKEY_P256 : public OpenSSL::UqEVP_PKEY
    {
#ifdef HAVE_SPAN
      UqEVP_PKEY_P256(const std::span<const uint8_t>& coordinates) :
        UqEVP_PKEY()
      {
        using namespace OpenSSL;

        UqBIGNUM x(&coordinates[0], 32);
        UqBIGNUM y(&coordinates[32], 32);

#  if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
        const char* group_name = "prime256v1";

        UqBN_CTX bn_ctx;
        UqEC_GROUP grp(NID_X9_62_prime256v1);
        UqEC_POINT pnt(grp);
        CHECK1(EC_POINT_set_affine_coordinates(grp, pnt, x, y, bn_ctx));
        size_t len = EC_POINT_point2oct(
          grp, pnt, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx);
        std::vector<unsigned char> buf(len);
        EC_POINT_point2oct(
          grp,
          pnt,
          POINT_CONVERSION_UNCOMPRESSED,
          buf.data(),
          buf.size(),
          bn_ctx);

        UqEVP_PKEY_CTX ek_ctx(EVP_PKEY_EC);
        OSSL_PARAM params[] = {
          OSSL_PARAM_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (void*)group_name, strlen(group_name)),
          OSSL_PARAM_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, buf.data(), buf.size()),
          OSSL_PARAM_END};

        EVP_PKEY* epk = NULL;
        CHECK1(EVP_PKEY_fromdata_init(ek_ctx));
        CHECK1(EVP_PKEY_fromdata(ek_ctx, &epk, EVP_PKEY_PUBLIC_KEY, params));

        p.reset(epk);
#  else
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        CHECK1(EC_KEY_set_public_key_affine_coordinates(ec_key, x, y));
        CHECK1(EVP_PKEY_set1_EC_KEY(*this, ec_key));
        EC_KEY_free(ec_key);
#  endif
      }
#endif
    };

    inline std::vector<uint8_t> convert_signature_to_der(
      const std::span<const uint8_t>& r,
      const std::span<const uint8_t>& s,
      bool little_endian)
    {
      using namespace OpenSSL;

      if (r.size() != s.size())
        throw std::runtime_error("incompatible signature coordinates");

      UqECDSA_SIG sig(UqBIGNUM(r, little_endian), UqBIGNUM(s, little_endian));
      int der_size = i2d_ECDSA_SIG(sig, NULL);
      CHECK0(der_size);
      if (der_size < 0)
        throw std::runtime_error("not an ECDSA signature");
      std::vector<uint8_t> res(der_size);
      auto der_sig_buf = res.data();
      CHECK0(i2d_ECDSA_SIG(sig, &der_sig_buf));
      return res;
    }

    inline std::vector<uint8_t> convert_signature_to_der(
      const std::span<const uint8_t>& signature, bool little_endian = false)
    {
      auto half_size = signature.size() / 2;
      return convert_signature_to_der(
        {signature.data(), half_size},
        {signature.data() + half_size, half_size},
        little_endian);
    }

    inline std::string_view extract_pem_certificate(std::string_view& data)
    {
      static std::string begin = "-----BEGIN CERTIFICATE-----";
      static std::string end = "-----END CERTIFICATE-----";

      if (data.empty())
        return "";
      size_t from = data.find(begin);
      if (from == std::string::npos)
      {
        data.remove_prefix(data.size());
        return "";
      }
      size_t to = data.find(end, from + begin.size());
      if (to == std::string::npos)
      {
        data.remove_prefix(data.size());
        return "";
      }
      to += end.size();
      auto pem = data.substr(from, to - from);
      from = data.find(begin, to);
      data.remove_prefix(from == std::string::npos ? data.size() : from);
      return pem;
    }

    inline std::string_view extract_pem_certificate(
      const std::span<const uint8_t>& data)
    {
      std::string_view sv((char*)data.data(), data.size());
      return extract_pem_certificate(sv);
    }

    inline std::vector<std::string> extract_pem_certificates(
      const std::span<const uint8_t>& data)
    {
      std::vector<std::string> r;
      std::string_view sv((char*)data.data(), data.size());

      while (!sv.empty())
      {
        auto pem = extract_pem_certificate(sv);
        if (!pem.empty())
          r.push_back(std::string(pem));
      }

      return r;
    }

    inline UqStackOfX509 load_certificates(
      const std::vector<std::string>& certificates)
    {
      // Leaf tracking/searching may be unnecessary as the chains should
      // be in order anyways.

      UqStackOfX509 r;
      UqX509 leaf;

      for (const auto& cert : certificates)
      {
        UqBIO cert_bio(cert.data(), cert.size());
        UqX509 x509(cert_bio, true);

        if (!x509.is_ca())
        {
          if (leaf)
            throw std::runtime_error("multiple leaves in certificate set");

          leaf = x509;
        }

        r.push(std::move(x509));
      }

      if (!leaf)
      {
        // Some chains, e.g. pck_crl_issuer_chain, contain only CAs, so
        // the leaf isn't easy to detect, so we look for the certificate
        // that isn't used as an authority.
        for (size_t ii = 0; ii < r.size(); ii++)
        {
          const UqX509& c_i = r.at(ii);
          UqASN1_OCTET_STRING subj_key_id(c_i.subject_key_id());

          bool i_appears_as_ca = false;
          for (size_t ji = 0; ji < r.size(); ji++)
          {
            if (ii == ji)
              continue;

            const auto& c_j = r.at(ji);

            if (c_j.has_authority_key_id())
            {
              UqASN1_OCTET_STRING auth_key_id(c_j.authority_key_id());

              if (subj_key_id == auth_key_id)
              {
                i_appears_as_ca = true;
                break;
              }
            }
          }

          if (!i_appears_as_ca)
          {
            if (leaf)
              throw std::runtime_error("multiple leaves in certificate set");

            leaf = c_i;
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

    inline UqStackOfX509 verify_certificate_chain(
      UqX509_STORE& store,
      UqStackOfX509& stack,
      const CertificateValidationOptions& options,
      bool trusted_root = false)
    {
      using namespace OpenSSL;

      if (stack.size() <= 1)
        throw std::runtime_error("certificate stack too small");

      // for (size_t i = 0; i < stack.size(); i++)
      //   std::cout << "[" << i << "]: " << (std::string)stack.at(i) <<
      //   std::endl;

      if (trusted_root)
        store.add(stack.back());

      UqX509 target = stack.at(0);

      UqX509_STORE_CTX store_ctx;
      store_ctx.init(store, target, stack);

      UqX509_VERIFY_PARAM param;
      param.set_depth(INT_MAX);
      param.set_auth_level(0);

      CHECK1(param.set_flags(X509_V_FLAG_X509_STRICT));
      CHECK1(param.set_flags(X509_V_FLAG_CHECK_SS_SIGNATURE));
      CHECK1(param.set_flags(X509_V_FLAG_PARTIAL_CHAIN));

      if (options.ignore_time)
        CHECK1(param.set_flags(X509_V_FLAG_NO_CHECK_TIME));

      if (options.verification_time)
        store_ctx.set_time(0, *options.verification_time);

      store_ctx.set_param(std::move(param));

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
      store_ctx.set_verify_cb([](int ok, X509_STORE_CTX* store_ctx) {
        int ec = store_ctx.get_error();
        if (ec == X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER)
        {
          // OpenSSL 3.0 with X509_V_FLAG_X509_STRICT requires an authority
          // key id, but, for instance, AMD SEV/SNP VCEK certificates don't
          // come with one, so we skip this check.
          return 1;
        }
        return ok;
      });
#endif

      int rc = store_ctx.verify_cert();

      if (rc == 1)
        return UqStackOfX509(store_ctx);
      else if (rc == 0)
      {
        int ec = X509_STORE_CTX_get_error(store_ctx);
        int depth = X509_STORE_CTX_get_error_depth(store_ctx);
        const char* err_str = X509_verify_cert_error_string(ec);
        throw std::runtime_error(fmt::format(
          "certificate chain verification failed: {} (depth: {})",
          err_str,
          depth));
      }
      else
      {
        throw std::runtime_error(OpenSSL::get_errors(ERR_get_error()));
      }
    }

    inline std::string to_string_short(const UqX509_CRL& crl, size_t indent = 0)
    {
      std::stringstream ss;
      auto rkd = crl.revoked();
      std::string ins(indent, ' ');
      ss << ins << "- Issuer: " << crl.issuer() << std::endl;
      ss << ins << "- Revoked serial numbers: ";
      if (rkd.size() == 0)
        ss << "none";
      ss << std::endl;
      for (size_t i = 0; i < rkd.size(); i++)
      {
        ss << ins << "- " << rkd.at(i).serialNumber() << std::endl;
      }
      ss << ins << "- Last update: " << (std::string)crl.last_update()
         << "  Next update: " << (std::string)crl.next_update();
      return ss.str();
    }

    inline std::string to_string_short(const UqX509& x509, size_t indent = 0)
    {
      std::string ins(indent, ' ');
      std::stringstream ss;

      ss << ins << "- Subject: " << (std::string)x509.get_subject_name()
         << std::endl;

      std::string subj_key_id =
        x509.has_subject_key_id() ? (std::string)x509.subject_key_id() : "none";
      ss << ins << "  - Subject key ID: " << subj_key_id << std::endl;

      std::string auth_key_id = x509.has_authority_key_id() ?
        (std::string)x509.authority_key_id() :
        "none";
      ss << ins << "  - Authority key ID: " << auth_key_id << std::endl;

      ss << ins << "  - CA: " << (x509.is_ca() ? "yes" : "no") << std::endl;
      ss << ins << "  - Not before: " << (std::string)x509.not_before()
         << "  Not after: " << (std::string)x509.not_after();
      return ss.str();
    }

    inline std::string to_string_short(
      const UqStackOfX509& stack, size_t indent = 0)
    {
      std::stringstream ss;
      for (size_t i = 0; i < stack.size(); i++)
      {
        if (i != 0)
          ss << std::endl;
        ss << to_string_short(stack.at(i), indent + 2);
      }
      return ss.str();
    }

    inline UqStackOfX509 verify_certificate_chain(
      UqStackOfX509& stack,
      UqX509_STORE& store,
      const CertificateValidationOptions& options,
      bool trusted_root = false,
      uint8_t verbosity = 0,
      size_t indent = 0)
    {
      if (verbosity > 0)
      {
        for (size_t i = 0; i < stack.size(); i++)
        {
          auto c = stack.at(i);
          log(to_string_short(c, indent));
          if (verbosity > 1)
          {
            log(std::string(indent + 2, ' ') + "- PEM:");
            auto s = c.pem();
            log(indentate(s, indent + 4));
          }
        }
      }

      try
      {
        auto chain =
          verify_certificate_chain(store, stack, options, trusted_root);

        if (chain.size() < 2)
          throw std::runtime_error("certificate chain is too short");

        if (verbosity > 0)
          log("- certificate chain verification successful", indent);

        return chain;
      }
      catch (std::exception& ex)
      {
        if (verbosity > 0)
          log(fmt::format("- failed: {}", ex.what()), indent);
        throw std::runtime_error(ex.what());
      }
      catch (...)
      {
        if (verbosity > 0)
          log(fmt::format("- failed: unknown exception"), indent);
        throw std::runtime_error("unknown exception");
      }
    }

    inline UqStackOfX509 verify_certificate_chain(
      const std::string& pem,
      UqX509_STORE& store,
      const CertificateValidationOptions& options,
      bool trusted_root = false,
      uint8_t verbosity = 0,
      size_t indent = 0)
    {
      UqStackOfX509 stack(pem);
      return verify_certificate_chain(
        stack, store, options, trusted_root, verbosity, indent);
    }

#ifdef HAVE_SPAN
    inline UqStackOfX509 verify_certificate_chain(
      const std::span<const uint8_t>& pem,
      UqX509_STORE& store,
      const CertificateValidationOptions& options,
      bool trusted_root = false,
      uint8_t verbosity = 0,
      size_t indent = 0)
    {
      UqStackOfX509 stack(pem);
      return verify_certificate_chain(
        stack, store, options, trusted_root, verbosity, indent);
    }
#endif

    inline std::vector<uint8_t> sha256(const std::span<const uint8_t>& message)
    {
      UqEVP_MD_CTX ctx(EVP_sha256());
      ctx.update(message);
      return ctx.final();
    }

    inline std::vector<uint8_t> sha384(const std::span<const uint8_t>& message)
    {
      UqEVP_MD_CTX ctx(EVP_sha384());
      ctx.update(message);
      return ctx.final();
    }

    inline std::vector<uint8_t> sha512(const std::span<const uint8_t>& message)
    {
      UqEVP_MD_CTX ctx(EVP_sha512());
      ctx.update(message);
      return ctx.final();
    }

    inline bool verify_certificate(
      UqX509_STORE& store,
      UqX509& certificate,
      const CertificateValidationOptions& options)
    {
      using namespace OpenSSL;

      UqX509_STORE_CTX store_ctx;
      store_ctx.init(store, certificate);

      UqX509_VERIFY_PARAM param;
      param.set_depth(INT_MAX);
      param.set_auth_level(0);

      CHECK1(param.set_flags(X509_V_FLAG_X509_STRICT));
      CHECK1(param.set_flags(X509_V_FLAG_CHECK_SS_SIGNATURE));

      if (options.ignore_time)
        CHECK1(param.set_flags(X509_V_FLAG_NO_CHECK_TIME));

      if (options.verification_time)
        store_ctx.set_time(0, *options.verification_time);

      store_ctx.set_param(std::move(param));

      int rc = store_ctx.verify_cert();

      if (rc == 1)
        return true;
      else if (rc == 0)
      {
        int err_code = X509_STORE_CTX_get_error(store_ctx);
        const char* err_str = X509_verify_cert_error_string(err_code);
        throw std::runtime_error(fmt::format(
          "certificate not self-signed or signature invalid: {}", err_str));
      }
      else
      {
        unsigned long openssl_err = ERR_get_error();
        char buf[4096];
        ERR_error_string(openssl_err, buf);
        ERR_clear_error();
        throw std::runtime_error(fmt::format("OpenSSL error: {}", buf));
      }
    }
  }
}
