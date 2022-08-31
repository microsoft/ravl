// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <chrono>
#include <cstring>
#include <memory>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace crypto
{
  namespace OpenSSL
  {
    /*
     * Generic OpenSSL error handling
     */

    /// Returns the error string from an error code
    inline std::string error_string(int ec)
    {
      // ERR_error_string doesn't really expect the code could actually be zero
      // and uses the `static char buf[256]` which is NOT cleaned nor checked
      // if it has changed. So we use ERR_error_string_n directly.
      if (ec)
      {
        std::string err(256, '\0');
        ERR_error_string_n((unsigned long)ec, err.data(), err.size());
        // Remove any trailing NULs before returning
        err.resize(std::strlen(err.c_str()));
        return err;
      }
      else
      {
        return "unknown error";
      }
    }

    /// Throws if rc is 1 and has error
    inline void CHECK1(int rc)
    {
      unsigned long ec = ERR_get_error();
      if (rc != 1 && ec != 0)
      {
        throw std::runtime_error(
          std::string("OpenSSL error: ") + error_string(ec));
      }
    }

    /// Throws if rc is 0 and has error
    inline void CHECK0(int rc)
    {
      unsigned long ec = ERR_get_error();
      if (rc == 0 && ec != 0)
      {
        throw std::runtime_error(
          std::string("OpenSSL error: ") + error_string(ec));
      }
    }

    /// Throws if ptr is null
    inline void CHECKNULL(void* ptr)
    {
      if (ptr == NULL)
      {
        throw std::runtime_error("OpenSSL error: missing object");
      }
    }

    /*
     * Unique pointer wrappers for SSL objects, with SSL' specific constructors
     * and destructors. Some objects need special functionality, others are just
     * wrappers around the same template interface Unique_SSL_OBJECT.
     */

    /// Generic template interface for different types of objects below.
    template <class T, T* (*CTOR)(), void (*DTOR)(T*)>
    class Unique_SSL_OBJECT
    {
    protected:
      /// Pointer owning storage
      std::unique_ptr<T, void (*)(T*)> p;

    public:
      /// C-tor with new pointer via T's c-tor
      Unique_SSL_OBJECT() : p(CTOR(), DTOR)
      {
        CHECKNULL(p.get());
      }
      /// C-tor with pointer created in base class
      Unique_SSL_OBJECT(T* ptr, void (*dtor)(T*), bool check_null = true) :
        p(ptr, dtor)
      {
        if (check_null)
          CHECKNULL(p.get());
      }
      /// No copy constructors
      Unique_SSL_OBJECT(const Unique_SSL_OBJECT&) = delete;

      /// Type cast to underlying pointer
      operator T*()
      {
        return p.get();
      }
      /// Type cast to underlying pointer
      operator T*() const
      {
        return p.get();
      }
      /// Enable field/member lookups
      const T* operator->() const
      {
        return p.get();
      }
      /// Reset pointer, free old if any
      void reset(T* other)
      {
        p.reset(other);
      }
      /// Release pointer, so it's freed elsewhere (CAUTION!)
      T* release()
      {
        return p.release();
      }
    };

    struct Unique_BIO : public Unique_SSL_OBJECT<BIO, nullptr, nullptr>
    {
      Unique_BIO() :
        Unique_SSL_OBJECT(BIO_new(BIO_s_mem()), [](auto x) { BIO_free(x); })
      {}
      Unique_BIO(const void* buf, int len) :
        Unique_SSL_OBJECT(
          BIO_new_mem_buf(buf, len), [](auto x) { BIO_free(x); })
      {}
      Unique_BIO(const std::string& s) :
        Unique_SSL_OBJECT(
          BIO_new_mem_buf(s.data(), s.size()), [](auto x) { BIO_free(x); })
      {}
      Unique_BIO(const std::vector<uint8_t>& d) :
        Unique_SSL_OBJECT(
          BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
      {}
      Unique_BIO(const std::span<const uint8_t>& d) :
        Unique_SSL_OBJECT(
          BIO_new_mem_buf(d.data(), d.size()), [](auto x) { BIO_free(x); })
      {}
    };

    struct Unique_EC_KEY : public Unique_SSL_OBJECT<EC_KEY, nullptr, nullptr>
    {
      Unique_EC_KEY(int nid) :
        Unique_SSL_OBJECT(
          EC_KEY_new_by_curve_name(nid), EC_KEY_free, /*check_null=*/true)
      {}
      Unique_EC_KEY(const Unique_EC_KEY& other) :
        Unique_SSL_OBJECT(other, EC_KEY_free, /*check_null=*/true)
      {
        EC_KEY_up_ref(p.get());
      }
    };

    struct Unique_BIGNUM : public Unique_SSL_OBJECT<BIGNUM, BN_new, BN_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_BIGNUM(const unsigned char* buf, int sz) :
        Unique_SSL_OBJECT(
          BN_bin2bn(buf, sz, NULL), BN_free, /*check_null=*/false)
      {}
    };

    struct Unique_EC_KEY_P256 : public Unique_EC_KEY
    {
      Unique_EC_KEY_P256(const std::span<const uint8_t>& coordinates) :
        Unique_EC_KEY(NID_X9_62_prime256v1)
      {
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        Unique_BIGNUM x(&coordinates[0], 32);
        Unique_BIGNUM y(&coordinates[32], 32);
        CHECK1(EC_KEY_set_public_key_affine_coordinates(ec_key, x, y));
        p.reset(ec_key);
      }
    };

    struct Unique_X509_CRL
      : public Unique_SSL_OBJECT<X509_CRL, X509_CRL_new, X509_CRL_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_X509_CRL(const Unique_BIO& mem) :
        Unique_SSL_OBJECT(
          PEM_read_bio_X509_CRL(mem, NULL, NULL, NULL), X509_CRL_free)
      {}
    };

    struct Unique_X509 : public Unique_SSL_OBJECT<X509, X509_new, X509_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      // p == nullptr is OK (e.g. wrong format)
      Unique_X509(const Unique_BIO& mem, bool pem, bool check_null = false) :
        Unique_SSL_OBJECT(
          pem ? PEM_read_bio_X509(mem, NULL, NULL, NULL) :
                d2i_X509_bio(mem, NULL),
          X509_free,
          check_null)
      {}
      Unique_X509(Unique_X509&& other) :
        Unique_SSL_OBJECT(NULL, X509_free, false)
      {
        X509* ptr = other;
        other.release();
        p.reset(ptr);
      }
      Unique_X509(X509* x509) : Unique_SSL_OBJECT(x509, X509_free, true)
      {
        X509_up_ref(x509);
      }
    };

    struct Unique_X509_STORE
      : public Unique_SSL_OBJECT<X509_STORE, X509_STORE_new, X509_STORE_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_X509_STORE_CTX : public Unique_SSL_OBJECT<
                                     X509_STORE_CTX,
                                     X509_STORE_CTX_new,
                                     X509_STORE_CTX_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_EVP_PKEY
      : public Unique_SSL_OBJECT<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_EVP_PKEY(const Unique_BIO& mem, bool pem = true) :
        Unique_SSL_OBJECT(
          pem ? PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL) :
                d2i_PUBKEY_bio(mem, NULL),
          EVP_PKEY_free)
      {}
      Unique_EVP_PKEY(const Unique_EC_KEY& ec_key) :
        Unique_SSL_OBJECT(EVP_PKEY_new(), EVP_PKEY_free)
      {
        EVP_PKEY_set1_EC_KEY(p.get(), ec_key);
      }
      Unique_EVP_PKEY(const Unique_X509& x509) :
        Unique_SSL_OBJECT(X509_get_pubkey(x509), EVP_PKEY_free)
      {}

      bool operator==(const Unique_EVP_PKEY& other) const
      {
        return EVP_PKEY_cmp_parameters((*this), other) == 1 &&
          EVP_PKEY_cmp((*this), other) == 1;
      }

      bool operator!=(const Unique_EVP_PKEY& other) const
      {
        return !(*this == other);
      }
    };

    struct Unique_EVP_PKEY_CTX
      : public Unique_SSL_OBJECT<EVP_PKEY_CTX, nullptr, nullptr>
    {
      Unique_EVP_PKEY_CTX(const Unique_EVP_PKEY& key) :
        Unique_SSL_OBJECT(EVP_PKEY_CTX_new(key, NULL), EVP_PKEY_CTX_free)
      {}
      Unique_EVP_PKEY_CTX() :
        Unique_SSL_OBJECT(
          EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free)
      {}
    };

    struct Unique_STACK_OF_X509
      : public Unique_SSL_OBJECT<STACK_OF(X509), nullptr, nullptr>
    {
      Unique_STACK_OF_X509() :
        Unique_SSL_OBJECT(
          sk_X509_new_null(), [](auto x) { sk_X509_pop_free(x, X509_free); })
      {}
      Unique_STACK_OF_X509(const Unique_X509_STORE_CTX& ctx) :
        Unique_SSL_OBJECT(X509_STORE_CTX_get1_chain(ctx), [](auto x) {
          sk_X509_pop_free(x, X509_free);
        })
      {}
      Unique_STACK_OF_X509(Unique_STACK_OF_X509&& other) :
        Unique_SSL_OBJECT(other, [](auto x) { sk_X509_pop_free(x, X509_free); })
      {
        other.release();
      }

      size_t size() const
      {
        return sk_X509_num(p.get());
      }

      X509* at(size_t i) const
      {
        if (i >= size())
          throw std::out_of_range("index into certificate stack too large");
        return sk_X509_value(p.get(), i);
      }

      void push(Unique_X509&& x509)
      {
        X509* ptr = x509;
        x509.release();
        sk_X509_push(p.get(), ptr);
      }

      Unique_X509 front() const
      {
        return (*this).at(0);
      }

      Unique_X509 back() const
      {
        return (*this).at(size() - 1);
      }
    };

    struct Unique_STACK_OF_X509_EXTENSIONS
      : public Unique_SSL_OBJECT<STACK_OF(X509_EXTENSION), nullptr, nullptr>
    {
      Unique_STACK_OF_X509_EXTENSIONS() :
        Unique_SSL_OBJECT(sk_X509_EXTENSION_new_null(), [](auto x) {
          sk_X509_EXTENSION_pop_free(x, X509_EXTENSION_free);
        })
      {}
      Unique_STACK_OF_X509_EXTENSIONS(STACK_OF(X509_EXTENSION) * exts) :
        Unique_SSL_OBJECT(
          exts,
          [](auto x) { sk_X509_EXTENSION_pop_free(x, X509_EXTENSION_free); },
          /*check_null=*/false)
      {}
    };

    struct Unique_ECDSA_SIG
      : public Unique_SSL_OBJECT<ECDSA_SIG, ECDSA_SIG_new, ECDSA_SIG_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_ECDSA_SIG(const std::vector<uint8_t>& sig) :
        Unique_SSL_OBJECT(
          [&sig]() {
            const unsigned char* pp = sig.data();
            return d2i_ECDSA_SIG(NULL, &pp, sig.size());
          }(),
          ECDSA_SIG_free,
          false)
      {}
    };

    struct Unique_ASN1_OBJECT
      : public Unique_SSL_OBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_ASN1_OBJECT(const std::string& oid) :
        Unique_SSL_OBJECT(OBJ_txt2obj(oid.c_str(), 0), ASN1_OBJECT_free)
      {}
      Unique_ASN1_OBJECT(ASN1_OBJECT* o) :
        Unique_SSL_OBJECT(OBJ_dup(o), ASN1_OBJECT_free, true)
      {}

      bool operator==(const Unique_ASN1_OBJECT& other) const
      {
        return OBJ_cmp(*this, other) == 0;
      }

      bool operator!=(const Unique_ASN1_OBJECT& other) const
      {
        return !(*this == other);
      }
    };

    struct Unique_ASN1_TYPE
      : public Unique_SSL_OBJECT<ASN1_TYPE, ASN1_TYPE_new, ASN1_TYPE_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;

      Unique_ASN1_TYPE(ASN1_TYPE* t) :
        Unique_SSL_OBJECT(
          [&t]() {
            ASN1_TYPE* n = ASN1_TYPE_new();
            CHECK1(ASN1_TYPE_set1(n, t->type, t->value.ptr));
            return n;
          }(),
          ASN1_TYPE_free)
      {}

      Unique_ASN1_TYPE(int type, void* value) :
        Unique_SSL_OBJECT(
          [&type, &value]() {
            ASN1_TYPE* n = ASN1_TYPE_new();
            CHECK1(ASN1_TYPE_set1(n, type, value));
            return n;
          }(),
          ASN1_TYPE_free,
          true)
      {}
    };

    struct Unique_ASN1_OCTET_STRING : public Unique_SSL_OBJECT<
                                        ASN1_OCTET_STRING,
                                        ASN1_OCTET_STRING_new,
                                        ASN1_OCTET_STRING_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;

      Unique_ASN1_OCTET_STRING(const ASN1_OCTET_STRING* t) :
        Unique_SSL_OBJECT(ASN1_OCTET_STRING_dup(t), ASN1_OCTET_STRING_free)
      {}

      bool operator==(const Unique_ASN1_OCTET_STRING& other) const
      {
        return ASN1_OCTET_STRING_cmp(*this, other) == 0;
      }

      bool operator!=(const Unique_ASN1_OCTET_STRING& other) const
      {
        return !(*this == other);
      }
    };

    struct Unique_ASN1_SEQUENCE : public Unique_SSL_OBJECT<
                                    ASN1_SEQUENCE_ANY,
                                    sk_ASN1_TYPE_new_null,
                                    sk_ASN1_TYPE_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_ASN1_SEQUENCE(ASN1_OCTET_STRING* os) :
        Unique_SSL_OBJECT(
          [&os]() {
            ASN1_SEQUENCE_ANY* seq = NULL;
            const unsigned char* pp = os->data;
            CHECKNULL(d2i_ASN1_SEQUENCE_ANY(&seq, &pp, os->length));
            return seq;
          }(),
          [](STACK_OF(ASN1_TYPE) * p) {
            for (size_t i = 0; i < sk_ASN1_TYPE_num(p); i++)
              ASN1_TYPE_free(sk_ASN1_TYPE_value(p, i));
            sk_ASN1_TYPE_free(p);
          })
      {}

      Unique_ASN1_TYPE at(int index) const
      {
        return Unique_ASN1_TYPE(sk_ASN1_TYPE_value(p.get(), index));
      }

      int size() const
      {
        return sk_ASN1_TYPE_num(p.get());
      }
    };
  }
}
