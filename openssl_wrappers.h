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

    /// Generic template interface for different types of objects below
    /// If there are no c-tors in the derived class that matches this one,
    /// pass `nullptr` to the CTOR/DTOR parameters and make sure to implement
    /// and delete the appropriate c-tors in the derived class.
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
      Unique_BIO(SSL_CTX* ctx) :
        Unique_SSL_OBJECT(
          BIO_new_ssl_connect(ctx), [](auto x) { BIO_free_all(x); })
      {}
    };

    struct Unique_SSL_CTX : public Unique_SSL_OBJECT<SSL_CTX, nullptr, nullptr>
    {
      Unique_SSL_CTX(const SSL_METHOD* m) :
        Unique_SSL_OBJECT(SSL_CTX_new(m), SSL_CTX_free)
      {}
    };

    struct Unique_SSL : public Unique_SSL_OBJECT<SSL, nullptr, nullptr>
    {
      Unique_SSL(SSL_CTX* ctx) : Unique_SSL_OBJECT(SSL_new(ctx), SSL_free) {}
    };

    struct Unique_EC_KEY : public Unique_SSL_OBJECT<EC_KEY, nullptr, nullptr>
    {
      Unique_EC_KEY(int nid) :
        Unique_SSL_OBJECT(
          EC_KEY_new_by_curve_name(nid), EC_KEY_free, /*check_null=*/true)
      {}
      Unique_EC_KEY(EC_KEY* key) :
        Unique_SSL_OBJECT(key, EC_KEY_free, /*check_null=*/true)
      {}
      Unique_EC_KEY(const Unique_EC_KEY& other) :
        Unique_SSL_OBJECT(EC_KEY_dup(other), EC_KEY_free, /*check_null=*/true)
      {}
    };

    struct Unique_EVP_PKEY
      : public Unique_SSL_OBJECT<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_EVP_PKEY(BIO* mem, bool pem = true) :
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
      Unique_EVP_PKEY(EVP_PKEY* pkey) : Unique_SSL_OBJECT(pkey, EVP_PKEY_free)
      {}
    };

    struct Unique_EVP_PKEY_CTX
      : public Unique_SSL_OBJECT<EVP_PKEY_CTX, nullptr, nullptr>
    {
      Unique_EVP_PKEY_CTX(EVP_PKEY* key) :
        Unique_SSL_OBJECT(EVP_PKEY_CTX_new(key, NULL), EVP_PKEY_CTX_free)
      {}
      Unique_EVP_PKEY_CTX() :
        Unique_SSL_OBJECT(
          EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL), EVP_PKEY_CTX_free)
      {}
    };

    struct Unique_X509_REQ
      : public Unique_SSL_OBJECT<X509_REQ, X509_REQ_new, X509_REQ_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_X509_REQ(BIO* mem) :
        Unique_SSL_OBJECT(
          PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL), X509_REQ_free)
      {}
    };

    struct Unique_X509_CRL
      : public Unique_SSL_OBJECT<X509_CRL, X509_CRL_new, X509_CRL_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_X509_CRL(BIO* mem) :
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
      Unique_X509(X509* cert) :
        Unique_SSL_OBJECT(X509_dup(cert), X509_free, true)
      {}
      Unique_X509(const Unique_X509& other) :
        Unique_SSL_OBJECT(X509_dup(other), X509_free, true)
      {}
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

    struct Unique_EVP_CIPHER_CTX : public Unique_SSL_OBJECT<
                                     EVP_CIPHER_CTX,
                                     EVP_CIPHER_CTX_new,
                                     EVP_CIPHER_CTX_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_STACK_OF_X509
      : public Unique_SSL_OBJECT<STACK_OF(X509), nullptr, nullptr>
    {
      Unique_STACK_OF_X509() :
        Unique_SSL_OBJECT(
          sk_X509_new_null(), [](auto x) { sk_X509_pop_free(x, X509_free); })
      {}
      Unique_STACK_OF_X509(X509_STORE_CTX* ctx) :
        Unique_SSL_OBJECT(X509_STORE_CTX_get1_chain(ctx), [](auto x) {
          sk_X509_pop_free(x, X509_free);
        })
      {}
      Unique_STACK_OF_X509(const Unique_STACK_OF_X509& other) :
        Unique_SSL_OBJECT(
          sk_X509_dup(other), [](auto x) { sk_X509_pop_free(x, X509_free); })
      {}

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

      X509* front() const
      {
        return (*this).at(0);
      }

      X509* back() const
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

    struct Unique_BIGNUM : public Unique_SSL_OBJECT<BIGNUM, BN_new, BN_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_BIGNUM(BIGNUM* t) :
        Unique_SSL_OBJECT(t, BN_free, /*check_null=*/false)
      {}
    };

    struct Unique_X509_TIME
      : public Unique_SSL_OBJECT<ASN1_TIME, ASN1_TIME_new, ASN1_TIME_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_X509_TIME(ASN1_TIME* t) :
        Unique_SSL_OBJECT(t, ASN1_TIME_free, /*check_null=*/false)
      {}
    };

    struct Unique_BN_CTX
      : public Unique_SSL_OBJECT<BN_CTX, BN_CTX_new, BN_CTX_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_EC_GROUP
      : public Unique_SSL_OBJECT<EC_GROUP, nullptr, nullptr>
    {
      Unique_EC_GROUP(int nid) :
        Unique_SSL_OBJECT(
          EC_GROUP_new_by_curve_name(nid), EC_GROUP_free, /*check_null=*/true)
      {}
    };

    struct Unique_EC_POINT
      : public Unique_SSL_OBJECT<EC_POINT, nullptr, nullptr>
    {
      Unique_EC_POINT(const EC_GROUP* group) :
        Unique_SSL_OBJECT(
          EC_POINT_new(group), EC_POINT_free, /*check_null=*/true)
      {}
      Unique_EC_POINT(EC_POINT* point) :
        Unique_SSL_OBJECT(point, EC_POINT_free, /*check_null=*/true)
      {}
    };

    struct Unique_EVP_ENCODE_CTX : public Unique_SSL_OBJECT<
                                     EVP_ENCODE_CTX,
                                     EVP_ENCODE_CTX_new,
                                     EVP_ENCODE_CTX_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
    };

    struct Unique_ASN1_OBJECT
      : public Unique_SSL_OBJECT<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_ASN1_OBJECT(ASN1_OBJECT* t) :
        Unique_SSL_OBJECT(t, ASN1_OBJECT_free, /*check_null=*/false)
      {}
      Unique_ASN1_OBJECT(const std::string& oid) :
        Unique_SSL_OBJECT(OBJ_txt2obj(oid.c_str(), 0), ASN1_OBJECT_free)
      {}
    };

    struct Unique_ASN1_TYPE
      : public Unique_SSL_OBJECT<ASN1_TYPE, ASN1_TYPE_new, ASN1_TYPE_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_ASN1_TYPE(const ASN1_TYPE* t) :
        Unique_SSL_OBJECT(
          [&t]() {
            ASN1_TYPE* n = ASN1_TYPE_new();
            CHECK1(ASN1_TYPE_set1(n, t->type, t->value.ptr));
            return n;
          }(),
          ASN1_TYPE_free)
      {}
    };

    struct Unique_ASN1_SEQUENCE : public Unique_SSL_OBJECT<
                                    ASN1_SEQUENCE_ANY,
                                    sk_ASN1_TYPE_new_null,
                                    sk_ASN1_TYPE_free>
    {
      using Unique_SSL_OBJECT::Unique_SSL_OBJECT;
      Unique_ASN1_SEQUENCE(const ASN1_OCTET_STRING* os) :
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
    };
  }
}
