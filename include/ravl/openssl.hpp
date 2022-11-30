// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef __has_include
#  if __has_include(<span>)
#    include <span>
#    define HAVE_SPAN
#  endif
#endif

extern "C"
{
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
}

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#  include <openssl/core_names.h>
#  include <openssl/types.h>
#endif

namespace OpenSSL
{
  class asn1_format_exception : public std::runtime_error
  {
  public:
    asn1_format_exception(const std::string& detail) :
      std::runtime_error("incorrectly formatted ASN.1 structure: " + detail)
    {}
    virtual ~asn1_format_exception() = default;
  };

  /// Returns the error string from an error code
  inline std::string error_string(int ec)
  {
    if (ec)
    {
      std::string err(256, '\0');
      ERR_error_string_n((unsigned long)ec, err.data(), err.size());
      err.resize(std::strlen(err.c_str()));
      return err;
    }
    else
    {
      return "unknown error";
    }
  }

  inline std::string get_errors(int ec)
  {
    std::string r("OpenSSL error(s):");
    while (ec != 0)
    {
      r += " " + error_string(ec);
      ec = ERR_get_error();
    }
    return r;
  }

  /// Throws if rc is 1 and has error
  inline void CHECK1(int rc)
  {
    unsigned long ec = ERR_get_error();
    if (rc != 1 && ec != 0)
      throw std::runtime_error(get_errors(ec));
  }

  /// Throws if rc is 0 and has error
  inline void CHECK0(int rc)
  {
    unsigned long ec = ERR_get_error();
    if (rc == 0 && ec != 0)
      throw std::runtime_error(get_errors(ec));
  }

  /// Throws if ptr is null
  inline void CHECKNULL(void* ptr)
  {
    if (ptr == NULL)
      throw std::runtime_error(
        "OpenSSL object creation failed because of " +
        get_errors(ERR_get_error()));
  }

  /// Generic template interface for didtorerent types of objects below.
  template <class T, T* (*CTOR)(), void (*DTOR)(T*)>
  class UqSSLObject
  {
  protected:
    /// Pointer owning storage
    std::unique_ptr<T, void (*)(T*)> p;

  public:
    /// Constructor with new pointer via T's constructor.
    UqSSLObject() : p(CTOR(), DTOR)
    {
      CHECKNULL(p.get());
    }

    /// Constructor with pointer created in base class.
    explicit UqSSLObject(
      T*& ptr, void (*dtor)(T*) = DTOR, bool check_null = true) :
      p(ptr, dtor)
    {
      if (check_null)
        CHECKNULL(p.get());
      ptr = nullptr; // indicate ptr ownership takeover
    }

    /// Constructor with pointer created in base class.
    explicit UqSSLObject(
      T*&& ptr, void (*dtor)(T*) = DTOR, bool check_null = true) :
      p(ptr, dtor)
    {
      if (check_null)
        CHECKNULL(p.get());
      ptr = nullptr; // indicate ptr ownership takeover
    }

    /// Take over suitable unique_ptrs
    UqSSLObject(std::unique_ptr<T, void (*)(T*)>&& other) : p(std::move(other))
    {}

    /// Move constructor
    UqSSLObject(UqSSLObject&& other) :
      p(other.p.release(), other.p.get_deleter())
    {}

    /// No copy constructor.
    UqSSLObject(const UqSSLObject&) = delete;

    /// By default, no direct assignment.
    UqSSLObject& operator=(const UqSSLObject&) = delete;

    /// Type cast to underlying pointer.
    operator T*()
    {
      return p.get();
    }

    /// Type cast to underlying pointer.
    operator const T*() const
    {
      return p.get();
    }

    /// Enable field/member lookups.
    const T* operator->() const
    {
      return p.get();
    }

    /// Release p without freeing
    void release()
    {
      (void)p.release();
    }
  };

  template <typename T>
  std::unique_ptr<T, void (*)(T*)> make_unique_nodelete(const T* x)
  {
    return std::unique_ptr<T, void (*)(T*)>(const_cast<T*>(x), [](T*) {});
  }

  template <typename T>
  std::unique_ptr<T, void (*)(T*)> make_unique_copy(
    const std::unique_ptr<T, void (*)(T*)>& x)
  {
    // To be used in functions that can up_ref instead of acutal copying.
    return std::unique_ptr<T, void (*)(T*)>(x.get(), x.get_deleter());
  }

  struct UqBIO : public UqSSLObject<BIO, nullptr, nullptr>
  {
  private:
    static constexpr auto uq_bio_free = [](auto x) { CHECK1(BIO_free(x)); };

  public:
    UqBIO() : UqSSLObject(BIO_new(BIO_s_mem()), uq_bio_free) {}

    UqBIO(const void* buf, int len) :
      UqSSLObject(BIO_new_mem_buf(buf, len), uq_bio_free)
    {}

    UqBIO(const std::string& s) :
      UqSSLObject(BIO_new_mem_buf(s.data(), s.size()), uq_bio_free)
    {}

    UqBIO(const std::string_view& s) :
      UqSSLObject(BIO_new_mem_buf(s.data(), s.size()), uq_bio_free)
    {}

    UqBIO(const std::vector<uint8_t>& d) :
      UqSSLObject(BIO_new_mem_buf(d.data(), d.size()), uq_bio_free)
    {}

#ifdef HAVE_SPAN
    UqBIO(const std::span<const uint8_t>& d) :
      UqSSLObject(BIO_new_mem_buf(d.data(), d.size()), uq_bio_free)
    {}
#endif

    UqBIO(const BIO_METHOD* method) : UqSSLObject(BIO_new(method), uq_bio_free)
    {}

    UqBIO(UqBIO&& b, UqBIO&& next) :
      UqSSLObject(BIO_push(b, next), BIO_free_all)
    {
      (void)b.p.release();
      (void)next.p.release();
    }

    explicit operator std::string() const
    {
      BUF_MEM* bptr;
      BIO_get_mem_ptr(p.get(), &bptr);
      return std::string(bptr->data, bptr->length);
    }
  };

  struct UqBIGNUM : public UqSSLObject<BIGNUM, BN_new, BN_free>
  {
    using UqSSLObject::UqSSLObject;

    UqBIGNUM(const unsigned char* buf, int sz, bool little_endian = false) :
      UqSSLObject(
        little_endian ? BN_lebin2bn(buf, sz, NULL) : BN_bin2bn(buf, sz, NULL),
        BN_free,
        /*check_null=*/false)
    {}

#ifdef HAVE_SPAN
    UqBIGNUM(const std::span<const uint8_t>& data, bool little_endian = false) :
      UqSSLObject(
        little_endian ? BN_lebin2bn(data.data(), data.size(), NULL) :
                        BN_bin2bn(data.data(), data.size(), NULL),
        BN_free,
        /*check_null=*/false)
    {}
#endif
  };

  struct UqASN1_INTEGER
    : public UqSSLObject<ASN1_INTEGER, ASN1_INTEGER_new, ASN1_INTEGER_free>
  {
    using UqSSLObject::UqSSLObject;

    explicit UqASN1_INTEGER(
      ASN1_INTEGER*& x,
      void (*dtor)(ASN1_INTEGER*) = ASN1_INTEGER_free,
      bool check_null = true) :
      UqSSLObject::UqSSLObject(ASN1_INTEGER_dup(x), dtor, check_null)
    {}

    void set(long n)
    {
      CHECK1(ASN1_INTEGER_set(*this, n));
    }

    void set_int64(int64_t n)
    {
      CHECK1(ASN1_INTEGER_set_int64(*this, n));
    }

    void set_uint64(uint64_t n)
    {
      CHECK1(ASN1_INTEGER_set_uint64(*this, n));
    }
  };

  struct UqASN1_TIME
    : public UqSSLObject<ASN1_TIME, ASN1_TIME_new, ASN1_TIME_free>
  {
    using UqSSLObject::UqSSLObject;

    UqASN1_TIME(UqASN1_TIME& x) :
      UqSSLObject(ASN1_STRING_dup(x), ASN1_TIME_free)
    {}

    void gmtime_adj(long adj)
    {
      auto x = X509_gmtime_adj(*this, adj);
      CHECKNULL(x);
      if (p.get() != x)
        p.reset(x);
    }

    explicit operator std::string() const
    {
      UqBIO bio;
      CHECK1(ASN1_TIME_print(bio, *this));
      return (std::string)bio;
    }
  };

  struct UqX509_NAME
    : public UqSSLObject<X509_NAME, X509_NAME_new, X509_NAME_free>
  {
    using UqSSLObject::UqSSLObject;

    void add_entry_by_txt(
      const char* field, int type, const char* bytes, int len, int loc, int set)
    {
      add_entry_by_txt(field, type, (const unsigned char*)bytes, len, loc, set);
    }

    void add_entry_by_txt(
      const char* field,
      int type,
      const uint8_t* bytes,
      int len,
      int loc,
      int set)
    {
      OpenSSL::CHECK1(X509_NAME_add_entry_by_txt(
        *this, field, type, (const unsigned char*)bytes, len, loc, set));
    }

    explicit operator std::string()
    {
      UqBIO bio;
      X509_NAME_print(bio, *this, 0);
      return (std::string)bio;
    }

    std::string to_string(int indent = 0, unsigned long flags = 0)
    {
      UqBIO bio;
      if (flags)
        X509_NAME_print_ex(bio, *this, indent, flags);
      else
        X509_NAME_print(bio, *this, indent);
      return (std::string)bio;
    }
  };

  struct UqX509_REVOKED
    : public UqSSLObject<X509_REVOKED, X509_REVOKED_new, X509_REVOKED_free>
  {
    using UqSSLObject::UqSSLObject;

    friend struct UqStackOfX509_REVOKEDBase;

    explicit UqX509_REVOKED(
      X509_REVOKED*& x,
      void (*dtor)(X509_REVOKED*) = X509_REVOKED_free,
      bool check_null = true) :
      UqSSLObject(X509_REVOKED_dup(x), X509_REVOKED_free)
    {}

    UqX509_REVOKED(const UqX509_REVOKED& x) :
      UqSSLObject(X509_REVOKED_dup(x.p.get()), X509_REVOKED_free)
    {}

    std::string serialNumber() const
    {
      const ASN1_INTEGER* sn = X509_REVOKED_get0_serialNumber(*this);
      char* c = i2s_ASN1_INTEGER(NULL, sn);
      std::string r = c;
      free(c);
      return r;
    }
  };

  struct UqStackOfX509_REVOKED;

  struct UqX509_CRL : public UqSSLObject<X509_CRL, X509_CRL_new, X509_CRL_free>
  {
    using UqSSLObject::UqSSLObject;

    UqX509_CRL(UqBIO& mem, bool pem = true) :
      UqSSLObject(
        pem ? PEM_read_bio_X509_CRL(mem, NULL, NULL, NULL) :
              d2i_X509_CRL_bio(mem, NULL),
        X509_CRL_free)
    {}

    UqX509_CRL(const std::vector<uint8_t>& data, bool pem = true) :
      UqSSLObject(
        pem ? PEM_read_bio_X509_CRL(
                UqBIO(data.data(), data.size()), NULL, NULL, NULL) :
              d2i_X509_CRL_bio(UqBIO(data.data(), data.size()), NULL),
        X509_CRL_free)
    {}

#ifdef HAVE_SPAN
    UqX509_CRL(const std::span<const uint8_t>& data, bool pem = true) :
      UqSSLObject(
        pem ? PEM_read_bio_X509_CRL(
                UqBIO(data.data(), data.size()), NULL, NULL, NULL) :
              d2i_X509_CRL_bio(UqBIO(data.data(), data.size()), NULL),
        X509_CRL_free)
    {}

    UqX509_CRL(const std::string& pem) :
      UqX509_CRL(
        std::span<const uint8_t>((uint8_t*)pem.data(), pem.size()), true)
    {}
#else
    UqX509_CRL(const std::string& pem) :
      UqX509_CRL(UqBIO((uint8_t*)pem.data(), pem.size()), true)
    {}
#endif

    UqX509_CRL(const UqX509_CRL& other) :
      UqSSLObject(other.p.get(), X509_CRL_free)
    {
      X509_CRL_up_ref(p.get());
    }

    UqX509_CRL& operator=(const UqX509_CRL& other)
    {
      X509_CRL_up_ref(other.p.get());
      p.reset(other.p.get());
      return *this;
    }

    UqX509_CRL& operator=(UqX509_CRL&& other)
    {
      p = std::move(other.p);
      return *this;
    }

    std::string issuer(size_t indent = 0) const
    {
      auto name = X509_CRL_get_issuer(*this);
      UqBIO bio;
      CHECK1(X509_NAME_print(bio, name, indent));
      return (std::string)bio;
    }

    UqStackOfX509_REVOKED revoked() const;

    std::string pem() const
    {
      UqBIO bio;
      PEM_write_bio_X509_CRL(bio, p.get());
      return (std::string)bio;
    }

    const UqASN1_TIME last_update() const
    {
      auto x = X509_CRL_get0_lastUpdate(*this);
      return make_unique_nodelete<ASN1_TIME>(x);
    }

    std::string next_update() const
    {
      auto t = X509_CRL_get0_nextUpdate(*this);
      UqBIO bio;
      ASN1_TIME_print(bio, t);
      return (std::string)bio;
    }
  };

  struct UqASN1_OBJECT
    : public UqSSLObject<ASN1_OBJECT, ASN1_OBJECT_new, ASN1_OBJECT_free>
  {
    using UqSSLObject::UqSSLObject;

    UqASN1_OBJECT(const std::string& oid) :
      UqSSLObject(OBJ_txt2obj(oid.c_str(), 0), ASN1_OBJECT_free)
    {}

    bool operator==(const UqASN1_OBJECT& other) const
    {
      return OBJ_cmp(*this, other) == 0;
    }

    bool operator!=(const UqASN1_OBJECT& other) const
    {
      return !(*this == other);
    }

    int nid() const
    {
      return OBJ_obj2nid(*this);
    }
  };

  struct UqEVP_PKEY;
  struct UqX509V3_CTX;

  struct UqX509_EXTENSION : public UqSSLObject<
                              X509_EXTENSION,
                              X509_EXTENSION_new,
                              X509_EXTENSION_free>
  {
    using UqSSLObject::UqSSLObject;

    friend struct UqStackOfX509_EXTENSIONBase;

    UqX509_EXTENSION(const UqX509_EXTENSION& ext) :
      UqSSLObject(X509_EXTENSION_dup(ext.p.get()), X509_EXTENSION_free)
    {}

    explicit UqX509_EXTENSION(
      X509_EXTENSION*& ext,
      void (*dtor)(X509_EXTENSION*) = X509_EXTENSION_free,
      bool check_null = true) :
      UqSSLObject(X509_EXTENSION_dup(ext), X509_EXTENSION_free)
    {}

    UqX509_EXTENSION(
      LHASH_OF(CONF_VALUE) * conf,
      UqX509V3_CTX& ctx,
      int nid,
      const char* value);

    UqASN1_OBJECT get_object() const
    {
      return make_unique_nodelete(X509_EXTENSION_get_object(p.get()));
    }
  };

  struct UqASN1_OCTET_STRING;
  struct UqX509_STORE_CTX;

  struct UqX509 : public UqSSLObject<X509, X509_new, X509_free>
  {
    using UqSSLObject::UqSSLObject;

    friend struct UqStackOfX509Base;

    UqX509(UqBIO& mem, bool pem, bool check_null = true) :
      UqSSLObject(
        pem ? PEM_read_bio_X509(mem, NULL, NULL, NULL) :
              d2i_X509_bio(mem, NULL),
        X509_free,
        check_null)
    {}

    UqX509(UqBIO&& mem, bool pem, bool check_null = true) :
      UqX509(mem, pem, check_null)
    {}

    UqX509(const std::string& pem, bool check_null = true) :
      UqSSLObject(
        PEM_read_bio_X509(UqBIO(pem), NULL, NULL, NULL), X509_free, check_null)
    {}

    UqX509(const UqX509& other) :
      UqSSLObject(X509_dup(other.p.get()), X509_free)
    {}

    UqX509(UqX509&& other)
    {
      p = std::move(other.p);
    }

    explicit UqX509(
      X509*& x, void (*dtor)(X509*) = X509_free, bool check_null = true) :
      UqSSLObject(x, X509_free, check_null)
    {
      X509_up_ref(p.get());
    }

    UqX509& operator=(const UqX509& other)
    {
      X509_up_ref(other.p.get());
      p = make_unique_copy<X509>(other.p);
      return *this;
    }

    UqX509& operator=(UqX509&& other)
    {
      p = std::move(other.p);
      return *this;
    }

    bool is_ca() const
    {
      return X509_check_ca(p.get()) != 0;
    }

    int extension_index(const std::string& oid) const
    {
      return X509_get_ext_by_OBJ(*this, UqASN1_OBJECT(oid.c_str()), -1);
    }

    UqX509_EXTENSION extension(const std::string& oid) const
    {
      return make_unique_nodelete(X509_get_ext(*this, extension_index(oid)));
    }

    bool has_common_name(const std::string& expected_name) const
    {
      auto subject_name = X509_get_subject_name(*this);
      int cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
      while (cn_i != -1)
      {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject_name, cn_i);
        ASN1_STRING* entry_string = X509_NAME_ENTRY_get_data(entry);
        std::string common_name = (char*)ASN1_STRING_get0_data(entry_string);
        if (common_name == expected_name)
          return true;
        cn_i = X509_NAME_get_index_by_NID(subject_name, NID_commonName, cn_i);
      }
      return false;
    }

    std::string pem() const
    {
      UqBIO mem;
      CHECK1(PEM_write_bio_X509(mem, p.get()));
      return (std::string)mem;
    }

    UqX509_NAME get_subject_name() const
    {
      return UqX509_NAME(make_unique_nodelete(X509_get_subject_name(*this)));
    }

    void set_subject_name(
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
      const
#endif
      UqX509_NAME& name) const
    {
      X509_set_subject_name(p.get(), name);
    }

    void set_subject_name(UqX509_NAME&& name) const
    {
      set_subject_name(name);
    }

    UqX509_NAME get_issuer_name() const
    {
      return UqX509_NAME(X509_get_issuer_name(*this));
    }

    void set_issuer_name(
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
      const
#endif
      UqX509_NAME& name) const
    {
      X509_set_issuer_name(p.get(), name);
    }

    void set_issuer_name(UqX509_NAME&& name) const
    {
      set_issuer_name(name);
    }

    bool has_subject_key_id() const
    {
      return X509_get0_subject_key_id(p.get()) != NULL;
    }

    UqASN1_OCTET_STRING subject_key_id() const;

    bool has_authority_key_id() const
    {
      return X509_get0_authority_key_id(p.get()) != NULL;
    }

    UqASN1_OCTET_STRING authority_key_id() const;

    UqASN1_TIME not_before() const
    {
      return UqASN1_TIME(make_unique_nodelete(X509_getm_notBefore(*this)));
    }

    UqASN1_TIME not_after() const
    {
      return UqASN1_TIME(make_unique_nodelete(X509_getm_notAfter(*this)));
    }

    UqEVP_PKEY get_pubkey() const;

    void set_pubkey(UqEVP_PKEY& key) const;
    void set_pubkey(UqEVP_PKEY&& key) const;

    bool has_public_key(const UqEVP_PKEY& target) const;
    bool has_public_key(UqEVP_PKEY&& target) const;
    bool has_public_key(const std::string& target) const;

    void set_version(long n)
    {
      CHECK1(X509_set_version(*this, n));
    }

    UqASN1_INTEGER get_serial_number()
    {
      return make_unique_nodelete(X509_get_serialNumber(*this));
    }

    void sign(UqEVP_PKEY& key, const EVP_MD* md);

    void add_ext(UqX509_EXTENSION& ex, int loc)
    {
      CHECK1(X509_add_ext(p.get(), ex, loc));
    }

    void add_ext(UqX509_EXTENSION&& ex, int loc)
    {
      add_ext(ex, loc);
    }

    bool verify(UqEVP_PKEY& key);

    explicit operator std::string() const
    {
      UqBIO bio;
      CHECK1(X509_print(bio, p.get()));
      return (std::string)bio;
    }

    int print_ex(
      UqBIO& bio, unsigned long nameflags, unsigned long skipflags) const
    {
      return X509_print_ex(bio, p.get(), nameflags, skipflags);
    }

    std::string to_string(
      unsigned long nameflags, unsigned long skipflags) const
    {
      UqBIO bio;
      CHECK1(print_ex(bio, nameflags, skipflags));
      return (std::string)bio;
    }

    int verify_cert(UqX509_STORE_CTX& ctx);
  };

  struct UqX509_STORE
    : public UqSSLObject<X509_STORE, X509_STORE_new, X509_STORE_free>
  {
    using UqSSLObject::UqSSLObject;

    void set_flags(int flags)
    {
      X509_STORE_set_flags(*this, flags);
    }

    void add(const UqX509& x509)
    {
      // Allow up-ref despite const
      X509_STORE_add_cert(p.get(), const_cast<X509*>((const X509*)x509));
    }

    void add(UqX509&& x509)
    {
      add(x509);
    }

    void add(const std::vector<uint8_t>& data, bool pem = true)
    {
      UqBIO bio(data);
      add(UqX509(bio, pem));
    }

    void add(const std::string& pem)
    {
      UqX509 cert(pem, true);
      add(cert);
    }

    void add_crl(const std::vector<uint8_t>& data)
    {
      UqX509_CRL crl(data); // TODO: PEM only; some CRLs may be in DER format?
      CHECK1(X509_STORE_add_crl(*this, crl));
    }

    void add_crl(const std::string& pem)
    {
      UqX509_CRL crl(
        pem.data()); // TODO: PEM only; some CRLs may be in DER format?
      CHECK1(X509_STORE_add_crl(*this, crl));
    }

#ifdef HAVE_SPAN
    void add(const std::span<const uint8_t>& data, bool pem = true)
    {
      UqBIO bio(data);
      add(UqX509(bio, pem));
    }

    void add_crl(const std::span<const uint8_t>& data)
    {
      if (!data.empty())
      {
        UqX509_CRL crl(data); // TODO: PEM only; some CRLs may be in DER format?
        CHECK1(X509_STORE_add_crl(*this, crl));
      }
    }
#endif

    void add_crl(std::optional<UqX509_CRL>& crl)
    {
      if (crl)
        CHECK1(X509_STORE_add_crl(p.get(), *crl));
    }
  };

  struct UqX509_STORE_CTX;

  struct UqX509_VERIFY_PARAM : public UqSSLObject<
                                 X509_VERIFY_PARAM,
                                 X509_VERIFY_PARAM_new,
                                 X509_VERIFY_PARAM_free>
  {
    using UqSSLObject::UqSSLObject;

    friend UqX509_STORE_CTX;

    int set_flags(int flags)
    {
      return X509_VERIFY_PARAM_set_flags(*this, flags);
    }

    void set_depth(int depth)
    {
      X509_VERIFY_PARAM_set_depth(*this, depth);
    }

    void set_auth_level(int auth_level)
    {
      X509_VERIFY_PARAM_set_auth_level(*this, auth_level);
    }
  };

  struct UqStackOfX509;

  struct UqX509_STORE_CTX : public UqSSLObject<
                              X509_STORE_CTX,
                              X509_STORE_CTX_new,
                              X509_STORE_CTX_free>
  {
    using UqSSLObject::UqSSLObject;

    void init(UqX509_STORE& store, UqX509& target, UqStackOfX509& chain);

    void init(UqX509_STORE& store, UqX509& target);

    bool verify_cert() const
    {
      return X509_verify_cert(p.get());
    }

    int get_error() const
    {
      return X509_STORE_CTX_get_error(p.get());
    }

    void set_param(UqX509_VERIFY_PARAM&& param)
    {
      X509_STORE_CTX_set0_param(*this, param);
      (void)param.p.release();
    }

    void set_time(unsigned long flags, time_t t)
    {
      X509_STORE_CTX_set_time(*this, flags, t);
    }

    void set_verify_cb(X509_STORE_CTX_verify_cb verify)
    {
      X509_STORE_CTX_set_verify_cb(*this, verify);
    }

    int get_error()
    {
      return X509_STORE_CTX_get_error(*this);
    }
  };

  struct UqEVP_PKEY_CTX;

  struct UqEVP_PKEY : public UqSSLObject<EVP_PKEY, EVP_PKEY_new, EVP_PKEY_free>
  {
    using UqSSLObject::UqSSLObject;

    friend UqX509;

    UqEVP_PKEY(UqBIO& mem, bool pem = true) :
      UqSSLObject(
        pem ? PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL) :
              d2i_PUBKEY_bio(mem, NULL),
        EVP_PKEY_free)
    {}

    UqEVP_PKEY(const UqX509& x509) :
      UqSSLObject(x509.get_pubkey(), EVP_PKEY_free)
    {}

    UqEVP_PKEY(const UqEVP_PKEY& other) :
      UqSSLObject(NULL, EVP_PKEY_free, false)
    {
      EVP_PKEY_up_ref(other.p.get());
      p = make_unique_copy(other.p);
    }

    UqEVP_PKEY(UqEVP_PKEY&& other) : UqSSLObject(std::move(other.p)) {}

    bool operator==(const UqEVP_PKEY& other) const
    {
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
      return EVP_PKEY_eq(*this, other) == 1;
#else
      return EVP_PKEY_cmp(*this, other) == 1;
#endif
    }

    bool operator!=(const UqEVP_PKEY& other) const
    {
      return !(*this == other);
    }

    UqEVP_PKEY& operator=(const UqEVP_PKEY& other)
    {
      EVP_PKEY_up_ref(other.p.get());
      p.reset(other.p.get());
      return *this;
    }

    bool verify_signature(
      const std::vector<uint8_t>& message,
      const std::vector<uint8_t>& signature);

#ifdef HAVE_SPAN
    bool verify_signature(
      const std::span<const uint8_t>& message,
      const std::span<const uint8_t>& signature);
#endif
  };

  inline UqEVP_PKEY UqX509::get_pubkey() const
  {
    EVP_PKEY* pk = X509_get_pubkey(p.get());
    // Note: up-ref should not be requried according to the documentation.
    // Perhaps an indication that something is wrong in UqStackOfX509?
    EVP_PKEY_up_ref(pk);
    return UqEVP_PKEY(pk, EVP_PKEY_free);
  }

  inline void UqX509::set_pubkey(UqEVP_PKEY& key) const
  {
    CHECK1(X509_set_pubkey(p.get(), key));
  }

  inline void UqX509::set_pubkey(UqEVP_PKEY&& key) const
  {
    CHECK1(X509_set_pubkey(p.get(), key));
    key.p.reset();
  }

  inline void UqX509::sign(UqEVP_PKEY& key, const EVP_MD* md)
  {
    OpenSSL::CHECK1(X509_sign(p.get(), key, md));
  }

  inline bool UqX509::verify(UqEVP_PKEY& key)
  {
    return X509_verify(p.get(), key) == 1;
  }

  struct UqEVP_PKEY_CTX : public UqSSLObject<EVP_PKEY_CTX, nullptr, nullptr>
  {
    UqEVP_PKEY_CTX(UqEVP_PKEY& key) :
      UqSSLObject(EVP_PKEY_CTX_new(key, NULL), EVP_PKEY_CTX_free)
    {}

    UqEVP_PKEY_CTX(int id) :
      UqSSLObject(EVP_PKEY_CTX_new_id(id, NULL), EVP_PKEY_CTX_free)
    {}

    void set_ec_paramgen_curve_nid(UqEVP_PKEY_CTX& pkctx, int nid) const
    {
      CHECK1(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, nid));
    }

    void set_ec_param_enc(int param_enc) const
    {
      EVP_PKEY_CTX_set_ec_param_enc(p.get(), param_enc);
    }

    void keygen_init() const
    {
      CHECK1(EVP_PKEY_keygen_init(p.get()));
    }

    UqEVP_PKEY keygen() const
    {
      EVP_PKEY* ppkey = NULL;
      CHECK1(EVP_PKEY_keygen(p.get(), &ppkey));
      return UqEVP_PKEY(ppkey);
    }
  };

  struct UqBN_CTX : public UqSSLObject<BN_CTX, BN_CTX_new, BN_CTX_free>
  {
    using UqSSLObject::UqSSLObject;
  };

  struct UqEC_GROUP : public UqSSLObject<EC_GROUP, nullptr, EC_GROUP_free>
  {
    UqEC_GROUP(int nid) :
      UqSSLObject(EC_GROUP_new_by_curve_name(nid), EC_GROUP_free)
    {}
  };

  struct UqEC_POINT : public UqSSLObject<EC_POINT, nullptr, EC_POINT_free>
  {
    UqEC_POINT(const UqEC_GROUP& grp) :
      UqSSLObject(EC_POINT_new(grp), EC_POINT_free)
    {}
  };

  struct UqStackOfX509_EXTENSION;

  inline bool UqEVP_PKEY::verify_signature(
    const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature)
  {
    UqEVP_PKEY_CTX pctx(*this);

    CHECK1(EVP_PKEY_verify_init(pctx));

    int rc = EVP_PKEY_verify(
      pctx, signature.data(), signature.size(), message.data(), message.size());

    return rc == 1;
  }

#ifdef HAVE_SPAN
  inline bool UqEVP_PKEY::verify_signature(
    const std::span<const uint8_t>& message,
    const std::span<const uint8_t>& signature)
  {
    UqEVP_PKEY_CTX pctx(*this);

    CHECK1(EVP_PKEY_verify_init(pctx));

    int rc = EVP_PKEY_verify(
      pctx, signature.data(), signature.size(), message.data(), message.size());

    return rc == 1;
  }
#endif

  inline bool UqX509::has_public_key(const UqEVP_PKEY& target) const
  {
    return UqEVP_PKEY(*this) == target;
  }

  inline bool UqX509::has_public_key(UqEVP_PKEY&& target) const
  {
    return has_public_key((UqEVP_PKEY&)target);
  }

  inline bool UqX509::has_public_key(const std::string& target) const
  {
    UqBIO bio(target);
    UqEVP_PKEY key(bio);
    return has_public_key(key);
  }

  struct UqX509_REQ : public UqSSLObject<X509_REQ, X509_REQ_new, X509_REQ_free>
  {
    using UqSSLObject::UqSSLObject;

    UqX509_REQ(UqBIO& mem) :
      UqSSLObject(PEM_read_bio_X509_REQ(mem, NULL, NULL, NULL), X509_REQ_free)
    {}

    void set_subject_name(
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
      const
#endif
      UqX509_NAME& name)
    {
      OpenSSL::CHECK1(X509_REQ_set_subject_name(p.get(), name));
    }

    void add_extensions(UqStackOfX509_EXTENSION& exts);

    void sign(UqEVP_PKEY& key, const EVP_MD* md)
    {
      OpenSSL::CHECK1(X509_REQ_sign(p.get(), key, md));
    }

    bool verify(UqEVP_PKEY& key)
    {
      return X509_REQ_verify(p.get(), key);
    }

    void pem_write(UqBIO& bio)
    {
      OpenSSL::CHECK1(PEM_write_bio_X509_REQ(bio, *this));
    }

    std::string pem()
    {
      UqBIO bio;
      OpenSSL::CHECK1(PEM_write_bio_X509_REQ(bio, *this));
      return (std::string)bio;
    }

    UqX509 to_X509(int days, UqEVP_PKEY& key) const
    {
      return UqX509(X509_REQ_to_X509(p.get(), days, key));
    }

    void set_version(long n)
    {
      CHECK1(X509_REQ_set_version(*this, n));
    }

    UqEVP_PKEY get_pubkey() const
    {
      return UqEVP_PKEY(X509_REQ_get_pubkey(p.get()));
    }

    void set_pubkey(UqEVP_PKEY& key) const
    {
      CHECK1(X509_REQ_set_pubkey(p.get(), key));
    }

    UqStackOfX509_EXTENSION get_extensions() const;

    int print_ex(UqBIO& bio) const
    {
      return X509_REQ_print(bio, p.get());
    }

    explicit operator std::string() const
    {
      UqBIO bio;
      CHECK1(print_ex(bio));
      return (std::string)bio;
    }
  };

  struct UqX509V3_CTX : public UqSSLObject<X509V3_CTX, nullptr, nullptr>
  {
    using UqSSLObject::UqSSLObject;

    UqX509V3_CTX() : UqSSLObject(new X509V3_CTX(), [](auto x) { delete x; }) {}

    void set_nodb()
    {
      X509V3_set_ctx_nodb(p.get());
    }

    void set(UqX509& issuer, UqX509& subject, int flags)
    {
      X509V3_set_ctx(*this, issuer, subject, NULL, NULL, flags);
    }

    void set(
      UqX509& issuer,
      UqX509& subject,
      UqX509_REQ& req,
      UqX509_CRL& crl,
      int flags)
    {
      X509V3_set_ctx(*this, issuer, subject, req, crl, flags);
    }
  };

  inline UqX509_EXTENSION::UqX509_EXTENSION(
    LHASH_OF(CONF_VALUE) * conf,
    UqX509V3_CTX& ctx,
    int nid,
    const char* value) :
    UqSSLObject(X509V3_EXT_conf_nid(conf, ctx, nid, value), X509_EXTENSION_free)
  {}

  struct UqECDSA_SIG
    : public UqSSLObject<ECDSA_SIG, ECDSA_SIG_new, ECDSA_SIG_free>
  {
    using UqSSLObject::UqSSLObject;

    UqECDSA_SIG(const std::vector<uint8_t>& sig) :
      UqSSLObject(
        [&sig]() {
          const unsigned char* pp = sig.data();
          return d2i_ECDSA_SIG(NULL, &pp, sig.size());
        }(),
        ECDSA_SIG_free,
        false)
    {}

    UqECDSA_SIG(UqBIGNUM&& r, UqBIGNUM&& s) :
      UqSSLObject(ECDSA_SIG_new(), ECDSA_SIG_free)
    {
      CHECK1(ECDSA_SIG_set0(*this, r, s));
      // r, s now owned by *this
      r.release();
      s.release();
    }
  };

  struct UqASN1_TYPE
    : public UqSSLObject<ASN1_TYPE, ASN1_TYPE_new, ASN1_TYPE_free>
  {
    using UqSSLObject::UqSSLObject;

    explicit UqASN1_TYPE(
      ASN1_TYPE*&& t,
      void (*dtor)(ASN1_TYPE*) = ASN1_TYPE_free,
      bool check_null = true) :
      UqSSLObject(
        [&t]() {
          ASN1_TYPE* n = ASN1_TYPE_new();
          CHECK1(ASN1_TYPE_set1(n, t->type, t->value.ptr));
          return n;
        }(),
        dtor)
    {}

    UqASN1_TYPE(int type, void* value) :
      UqSSLObject(
        [&type, &value]() {
          ASN1_TYPE* n = ASN1_TYPE_new();
          CHECK1(ASN1_TYPE_set1(n, type, value));
          return n;
        }(),
        ASN1_TYPE_free,
        true)
    {}
  };

  struct UqASN1_OCTET_STRING : public UqSSLObject<
                                 ASN1_OCTET_STRING,
                                 ASN1_OCTET_STRING_new,
                                 ASN1_OCTET_STRING_free>
  {
    using UqSSLObject::UqSSLObject;

    explicit UqASN1_OCTET_STRING(const ASN1_OCTET_STRING* t) :
      UqSSLObject(ASN1_OCTET_STRING_dup(t), ASN1_OCTET_STRING_free)
    {}

    bool operator==(const UqASN1_OCTET_STRING& other) const
    {
      return ASN1_OCTET_STRING_cmp(*this, other) == 0;
    }

    bool operator!=(const UqASN1_OCTET_STRING& other) const
    {
      return !(*this == other);
    }

    explicit operator std::string() const
    {
      char* c = i2s_ASN1_OCTET_STRING(NULL, *this);
      std::string r = c;
      free(c);
      return r;
    }
  };

  inline UqASN1_OCTET_STRING UqX509::subject_key_id() const
  {
    const ASN1_OCTET_STRING* key_id = X509_get0_subject_key_id(p.get());
    if (!key_id)
      throw std::runtime_error("certificate does not contain a subject key id");
    return UqASN1_OCTET_STRING(key_id);
  }

  inline UqASN1_OCTET_STRING UqX509::authority_key_id() const
  {
    const ASN1_OCTET_STRING* key_id = X509_get0_authority_key_id(p.get());
    if (!key_id)
      throw std::runtime_error(
        "certificate does not contain an authority key id");
    return UqASN1_OCTET_STRING(key_id);
  }

  struct UqASN1_SEQUENCE
    : public UqSSLObject<ASN1_SEQUENCE_ANY, nullptr, nullptr>
  {
    using UqSSLObject::UqSSLObject;

    explicit UqASN1_SEQUENCE(const ASN1_OCTET_STRING* os) :
      UqSSLObject(
        [&os]() {
          ASN1_SEQUENCE_ANY* seq = NULL;
          const unsigned char* pp = os->data;
          CHECKNULL(d2i_ASN1_SEQUENCE_ANY(&seq, &pp, os->length));
          return seq;
        }(),
        [](auto x) { sk_ASN1_TYPE_pop_free(x, ASN1_TYPE_free); })
    {}

    UqASN1_TYPE at(int index) const
    {
      return UqASN1_TYPE(sk_ASN1_TYPE_value(*this, index));
    }

    int size() const
    {
      return sk_ASN1_TYPE_num(*this);
    }

    UqASN1_TYPE get_obj_value(
      int index, const std::string& expected_oid, int expected_value_type) const
    {
      UqASN1_TYPE type = at(index);

      if (type->type != V_ASN1_SEQUENCE)
        throw asn1_format_exception("ASN.1 object not a sequence");

      UqASN1_SEQUENCE ss(type->value.sequence);

      if (ss.size() != 2)
        throw asn1_format_exception("ASN.1 sequence of invalid size");

      // OID
      UqASN1_TYPE tt = ss.at(0);

      if (tt->type != V_ASN1_OBJECT)
        throw asn1_format_exception("ASN.1 object value of invalid type");

      if (OBJ_cmp(tt->value.object, UqASN1_OBJECT(expected_oid)) != 0)
        throw asn1_format_exception("ASN.1 object with unexpected id");

      // VALUE
      UqASN1_TYPE tv = ss.at(1);
      if (tv->type != expected_value_type)
        throw asn1_format_exception("ASN.1 value of unexpected type");

      return UqASN1_TYPE(tv->type, tv->value.ptr);
    }

    uint8_t get_uint8(int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_INTEGER);

      UqBIGNUM bn;
      ASN1_INTEGER_to_BN(v->value.integer, bn);
      auto num_bytes BN_num_bytes(bn);
      int is_zero = BN_is_zero(bn);
      if (num_bytes != 1 && !is_zero)
        throw asn1_format_exception("ASN.1 integer value not a uint8_t");
      uint8_t r = 0;
      BN_bn2bin(bn, &r);
      return r;
    }

    uint16_t get_uint16(int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_INTEGER);

      UqBIGNUM bn;
      ASN1_INTEGER_to_BN(v->value.integer, bn);
      auto num_bytes BN_num_bytes(bn);
      if (num_bytes > 2)
        throw asn1_format_exception("ASN.1 integer value not a uint16_t");
      std::vector<uint8_t> r(num_bytes);
      BN_bn2bin(bn, r.data());
      return num_bytes == 0 ? 0 : num_bytes == 1 ? r[0] : (r[0] | r[1] << 8);
    }

    int64_t get_enum(int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_ENUMERATED);
      int64_t r = 0;
      CHECK1(ASN1_ENUMERATED_get_int64(&r, v->value.enumerated));
      return r;
    }

    std::vector<uint8_t> get_octet_string(
      int index, const std::string& expected_oid) const
    {
      UqASN1_TYPE v = get_obj_value(index, expected_oid, V_ASN1_OCTET_STRING);

      return std::vector<uint8_t>(
        v->value.octet_string->data,
        v->value.octet_string->data + v->value.octet_string->length);
    }

    UqASN1_SEQUENCE get_seq(int index, const std::string& expected_oid) const
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_SEQUENCE);
      return UqASN1_SEQUENCE(v->value.sequence);
    }

    bool get_bool(int index, const std::string& expected_oid)
    {
      auto v = get_obj_value(index, expected_oid, V_ASN1_BOOLEAN);
      return v->value.boolean;
    }
  };

  struct UqEVP_MD_CTX
    : public UqSSLObject<EVP_MD_CTX, EVP_MD_CTX_new, EVP_MD_CTX_free>
  {
    using UqSSLObject::UqSSLObject;

    UqEVP_MD_CTX(const EVP_MD* md) :
      UqSSLObject(EVP_MD_CTX_new(), EVP_MD_CTX_free)
    {
      md_size = EVP_MD_size(md);
      CHECK1(EVP_DigestInit_ex(*this, md, NULL));
    }

    void update(const std::vector<uint8_t>& message)
    {
      CHECK1(EVP_DigestUpdate(*this, message.data(), message.size()));
    }

#ifdef HAVE_SPAN
    void update(const std::span<const uint8_t>& message)
    {
      CHECK1(EVP_DigestUpdate(*this, message.data(), message.size()));
    }
#endif

    std::vector<uint8_t> final()
    {
      std::vector<uint8_t> r(md_size);
      unsigned sz = r.size();
      CHECK1(EVP_DigestFinal_ex(*this, r.data(), &sz));
      return r;
    }

  protected:
    int md_size = 0;
  };

  template <typename T, typename Q>
  class UqStackOf : public UqSSLObject<STACK_OF(Q), nullptr, nullptr>
  {
  public:
    UqStackOf(){};
    virtual ~UqStackOf()
    {
      dtor(*this);
    }
    UqStackOf(STACK_OF(Q) * ptr) : UqSSLObject(ptr, dtor) {}
    UqStackOf(UqStackOf&& x) : UqSSLObject(std::move(x.p)) {}
    UqStackOf& operator=(UqStackOf&& other)
    {
      p = std::move(other.p);
      return *this;
    }
    size_t size() const
    {
      int r = sk_num(*this);
      return r == (-1) ? 0 : r;
    }
    T at(size_t i) const
    {
      if (i >= size())
        throw std::out_of_range("index into stack out of range");
      auto v = value(*this, i);
      if (v == NULL)
        throw std::runtime_error("no such value");
      return T(v);
    }
    void insert(size_t i, T&& x)
    {
      CHECK0(sk_insert(*this, x, i));
      std::move(x).release();
    }
    T front() const
    {
      return (*this).at(0);
    }
    T back() const
    {
      return (*this).at(size() - 1);
    }
    bool empty() const
    {
      return size() == 0;
    }
    void push(T&& x)
    {
      sk_push(*this, x);
      x.release();
    }
    void push(const T& x)
    {
      push(T(x));
    }

  protected:
    int sk_num();
    int sk_insert(Q*, int);
    Q* sk_value(int);
    int sk_push(const Q* ptr);
    void dtor();
  };

  // template <>
  // class UqStackOf<UqX509, X509>
  //   : public UqSSLObject<STACK_OF(X509), sk_X509_new_null, sk_X509_free>
  // {
  // protected:
  //   /* clang-format off */
  //   int sk_num() { return sk_X509_num(*this); }
  //   int sk_insert(X509* x, int i) { return sk_X509_insert(*this, x, i); }
  //   X509* sk_value(int i) { return sk_X509_value(*this, i); }
  //   int sk_push(X509* x) { return sk_X509_push(*this, x); }
  //   void dtor() { sk_X509_pop_free(*this, X509_free); };
  //   /* clang-format on */
  // };

#define UQSTACKOFBASE(T) \
  struct UqStackOf##T##Base \
    : public UqSSLObject<STACK_OF(T), sk_##T##_new_null, nullptr> \
  { \
  protected: \
    static constexpr void (*dtor)(STACK_OF(T) *) = [](STACK_OF(T) * x) { \
      sk_##T##_pop_free(x, T##_free); \
    }; \
\
  public: \
    using UqSSLObject::UqSSLObject; \
    UqStackOf##T##Base() : UqSSLObject(sk_##T##_new_null(), dtor) \
    {} \
    UqStackOf##T##Base( \
      STACK_OF(T) * &ptr, \
      void (*dtorarg)(STACK_OF(T) *) = dtor, \
      bool check_null = true) : \
      UqSSLObject(ptr, dtorarg) \
    {} \
    UqStackOf##T##Base(UqStackOf##T##Base&& x) : UqSSLObject(std::move(x.p)) \
    {} \
    UqStackOf##T##Base& operator=(UqStackOf##T##Base&& other) \
    { \
      p = std::move(other.p); \
      return *this; \
    } \
    size_t size() const \
    { \
      int r = sk_##T##_num(*this); \
      return r == (-1) ? 0 : r; \
    } \
    Uq##T at(size_t i) const \
    { \
      if (i >= size()) \
        throw std::out_of_range("index into stack out of range"); \
      T* value = sk_##T##_value(*this, i); \
      if (value == NULL) \
        throw std::runtime_error("no such value"); \
      return Uq##T(value); \
    } \
    void insert(size_t i, Uq##T&& x) \
    { \
      auto ptr = x.p.release(); \
      CHECK0(sk_##T##_insert(*this, ptr, i)); \
    } \
    void push(Uq##T&& x) \
    { \
      sk_##T##_push(*this, x.p.release()); \
    } \
    void push(const Uq##T& x) \
    { \
      push(Uq##T(x)); \
    } \
    Uq##T front() const \
    { \
      return (*this).at(0); \
    } \
    Uq##T back() const \
    { \
      return (*this).at(size() - 1); \
    } \
    bool empty() const \
    { \
      return size() == 0; \
    } \
  }

  UQSTACKOFBASE(X509);

  struct UqStackOfX509 : public UqStackOfX509Base
  {
    using UqStackOfX509Base::UqStackOfX509Base;

    UqStackOfX509(
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
      const
#endif
      UqX509_STORE_CTX& ctx) :
      UqStackOfX509Base(X509_STORE_CTX_get1_chain(ctx), dtor)
    {}

#ifdef HAVE_SPAN
    UqStackOfX509(const std::span<const uint8_t>& pem) : UqStackOfX509Base()
    {
      UqBIO mem(pem);
      STACK_OF(X509_INFO)* sk_info =
        PEM_X509_INFO_read_bio(mem, NULL, NULL, NULL);
      int sz = sk_X509_INFO_num(sk_info);
      p.reset(sk_X509_new_null());
      for (int i = 0; i < sz; i++)
      {
        auto sk_i = sk_X509_INFO_value(sk_info, i);
        if (!sk_i->x509)
          throw std::runtime_error("invalid PEM element");
        X509_up_ref(sk_i->x509);
        sk_X509_push(*this, sk_i->x509);
      }
      sk_X509_INFO_pop_free(sk_info, X509_INFO_free);
    }
#endif

    UqStackOfX509(const std::string& pem) : UqStackOfX509Base()
    {
      UqBIO mem(pem);
      STACK_OF(X509_INFO)* sk_info =
        PEM_X509_INFO_read_bio(mem, NULL, NULL, NULL);
      int sz = sk_X509_INFO_num(sk_info);
      p.reset(sk_X509_new_null());
      for (int i = 0; i < sz; i++)
      {
        auto sk_i = sk_X509_INFO_value(sk_info, i);
        if (!sk_i->x509)
          throw std::runtime_error("invalid PEM element");
        X509_up_ref(sk_i->x509);
        sk_X509_push(*this, sk_i->x509);
      }
      sk_X509_INFO_pop_free(sk_info, X509_INFO_free);
    }

    std::pair<struct tm, struct tm> get_validity_range()
    {
      if (size() == 0)
        throw std::runtime_error(
          "no certificate change to compute validity ranges for");

      const ASN1_TIME *latest_from = nullptr, *earliest_to = nullptr;
      for (size_t i = 0; i < size(); i++)
      {
        const auto& c = at(i);
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

    std::string pem() const
    {
      std::string r;
      for (size_t i = 0; i < size(); i++)
        r += at(i).pem();
      return r;
    }
  };

  UQSTACKOFBASE(X509_EXTENSION);

  struct UqStackOfX509_EXTENSION : public UqStackOfX509_EXTENSIONBase
  {
    using UqStackOfX509_EXTENSIONBase::UqStackOfX509_EXTENSIONBase;
  };

  inline UqStackOfX509_EXTENSION UqX509_REQ::get_extensions() const
  {
    return UqStackOfX509_EXTENSION(X509_REQ_get_extensions(p.get()));
  }

  inline void UqX509_STORE_CTX::init(
    UqX509_STORE& store, UqX509& target, UqStackOfX509& chain)
  {
    CHECK1(X509_STORE_CTX_init(p.get(), store, target, chain));
  }

  inline void UqX509_STORE_CTX::init(UqX509_STORE& store, UqX509& target)
  {
    CHECK1(X509_STORE_CTX_init(p.get(), store, target, NULL));
  }

  UQSTACKOFBASE(X509_REVOKED);

  struct UqStackOfX509_REVOKED : public UqStackOfX509_REVOKEDBase
  {
    using UqStackOfX509_REVOKEDBase::UqStackOfX509_REVOKEDBase;
  };

  inline UqStackOfX509_REVOKED UqX509_CRL::revoked() const
  {
    auto sk = X509_CRL_get_REVOKED(p.get());
    if (!sk)
      return UqStackOfX509_REVOKED();
    else
    {
      auto copy = sk_X509_REVOKED_deep_copy(
        sk,
        [](const X509_REVOKED* x) {
          return X509_REVOKED_dup(const_cast<X509_REVOKED*>(x));
        },
        X509_REVOKED_free);
      return UqStackOfX509_REVOKED(copy);
    }
  }

  inline void UqX509_REQ::add_extensions(UqStackOfX509_EXTENSION& exts)
  {
    CHECK1(X509_REQ_add_extensions(*this, exts));
  }
}