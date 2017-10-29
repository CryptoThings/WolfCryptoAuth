/*
 * Copyright (C) 2016-2017 Robert Totte
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __WOLFCRYPTOAUTH_H__
#define __WOLFCRYPTOAUTH_H__

#define WOLFSSL_USE_ECC508

#include "AtCryptoAuthLib.h"
#include "WolfSSLClient.h"

#include "wolfssl/wolfcrypt/settings.h"

#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

class WolfCryptoAuth;

class WolfCryptoAuthCert : public WolfSSLCertLoader {
  WolfCryptoAuth *ecc;
  uint8_t *cert_data;
  size_t   cert_data_size;
public:
  WolfCryptoAuthCert(WolfCryptoAuth *_p) :
    WolfSSLCertLoader(), ecc(_p), cert_data(NULL) {}

  virtual ~WolfCryptoAuthCert() {}
  virtual bool have_cert();
  virtual const uint8_t *data();
  virtual size_t size();

  virtual int type() { return SSL_FILETYPE_PEM; }
  // cert loaded, free resources allocated in data() or have_cert()
  virtual void done();
};

class WolfCertEEPROM : public WolfSSLCertLoader {
  uint8_t  cert1_id;
  uint8_t  cert2_id;
  uint8_t  cert3_id;
  uint8_t *cert_data;
  size_t   cert_data_size;
  size_t read_cert_eeprom(int cert_id, uint8_t *data, size_t dsize);
  int i2c_eeprom_read(int addr, uint32_t eeaddress,
                      uint8_t *buffer, int length);
public:
  WolfCertEEPROM(uint8_t c1, uint8_t c2=0, uint8_t c3=0) :
    WolfSSLCertLoader(),
    cert1_id(c1),
    cert2_id(c2),
    cert3_id(c3),
    cert_data(NULL) {}

  virtual ~WolfCertEEPROM() {}
  virtual bool have_cert();
  virtual const uint8_t *data();
  virtual size_t size();

  virtual int type() { return SSL_FILETYPE_PEM; }
  // cert loaded, free resources allocated in data() or have_cert()
  virtual void done();
};

class WolfCryptoAuth : public WolfSSLClient, public AtCryptoAuthLib
{
public:
  WolfCryptoAuth(WolfSSLCertLoader &_certLoader) :
    WolfSSLClient(), AtCryptoAuthLib(),
    default_wca_cert(NULL),
    ecc_cert_gen(_certLoader)
  {

  }

  WolfCryptoAuth() :
    WolfSSLClient(), AtCryptoAuthLib(),
    default_wca_cert(this),
    ecc_cert_gen(default_wca_cert)
  {

  }

  bool init(Client &net) {
    int ret;
    ret = AtCryptoAuthLib::init();
    if (ret != 0)
      return ret;
    return WolfSSLClient::init(net);
  }
    
  bool init() {
    int ret;
    ret = AtCryptoAuthLib::init();
    if (ret != 0)
      return ret;
    return WolfSSLClient::init();
  }

  bool crypt_init(const uint8_t* key = NULL) {
    ATCA_STATUS ret;
    ret = AtCryptoAuthLib::init(key);
    return (ret == ATCA_SUCCESS);
  }

// SSL callbacks
public:
  bool setup_callbacks();

private:
  struct tls_callback_info {
    WolfCryptoAuth *wca;
    AtCryptoAuthLib::SlotCfg slot;
  };
  static
  int atca_tls_sign_certificate_cb(WOLFSSL* ssl, const byte* in, word32 inSz,
    byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx);

  static
  int atca_tls_verify_signature_cb(WOLFSSL* ssl, const byte* sig, word32 sigSz,
    const byte* hash, word32 hashSz, const byte* key, word32 keySz,
    int* result, void* ctx);

  static
  int atca_tls_create_pms_cb(WOLFSSL* ssl, unsigned char* pubKey,
    unsigned int* size, unsigned char inOut);

  static
  int atca_tls_get_random_number(uint32_t count, uint8_t* rand_out);

// Certificate generation
public:
  struct cert_info {
    char *country;
    char *state;
    char *locality;
    char *sur;
    char *org;
    char *unit;
    char *commonName;
    char *email;
    int year;
    int mon;
    int day;
    int valid_years;

    cert_info() : country(NULL), state(NULL), locality(NULL), sur(NULL),
                  org(NULL), unit(NULL), commonName(NULL), email(NULL),
                  year(0), mon(0), day(0), valid_years(0) {}
  };

  int make_csr(AtCryptoAuthLib::SlotCfg slot, cert_info &cn,
               uint8_t *pem, int *pemSz);

private:
  int make_cert_req(Cert* cert, byte* buffer, word32 buffSz,
                    ecc_key* key, AtCryptoAuthLib::SlotCfg slot, RNG* rng);

  static
  int EccSignCert(const byte* in, word32 inlen,
      byte* out, word32 *outSz, WC_RNG* rng, void *ctx);

  WolfCryptoAuthCert default_wca_cert;
//  WolfCertEEPROM ecc_cert_gen;
  WolfSSLCertLoader &ecc_cert_gen;
};

#ifdef CORE_TEENSY

class WolfCertTeensyEEPROM : public WolfSSLCertLoader {
  uint8_t *cert_data;
  size_t   cert_data_size;

public:
  WolfCertTeensyEEPROM() :
    WolfSSLCertLoader(),
    cert_data(NULL) {}

  virtual ~WolfCertTeensyEEPROM() {}
  virtual bool have_cert();
  virtual const uint8_t *data();
  virtual size_t size();

  virtual int type() { return SSL_FILETYPE_PEM; }
  // cert loaded, free resources allocated in data() or have_cert()
  virtual void done();
};
#endif // CORE_TEENSY

#endif // __WOLFCRYPTOAUTH_H__

