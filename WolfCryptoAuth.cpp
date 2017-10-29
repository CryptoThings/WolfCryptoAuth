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

#include <Arduino.h>

#include "WolfCryptoAuth.h"

#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "cryptoauthlib.h"
#include "atcacert/atcacert_def.h"
#include "tls/atcatls.h"
#include "tls/atcatls_cfg.h"
#include "atcacert/atcacert_client.h"
#include "Wire.h"

#undef BREAK

extern "C"
void Logging_cb(const int logLevel, const char *const logMessage);

static char g_print_buf[80];

#define T_PRINTF(...)    \
{ \
  snprintf(g_print_buf, 80, __VA_ARGS__); \
  Serial.print(g_print_buf); \
}

#define BREAK(x,y) { Logging_cb((x),(y)); break; }

bool WolfCryptoAuth::setup_callbacks()
{
  set_cert_chain(ecc_cert_gen);

  set_verify_peer();
  SetEccSignCb(atca_tls_sign_certificate_cb, this);
  SetEccVerifyCb(atca_tls_verify_signature_cb, this);
  SetEccPmsCb(atca_tls_create_pms_cb, this);

  return true;
}

int WolfCryptoAuth::atca_tls_sign_certificate_cb(WOLFSSL* ssl, const byte* in,
  word32 inSz, byte* out, word32* outSz, const byte* key, word32 keySz, void* ctx)
{
  int ret = ATCA_SUCCESS;
  mp_int r, s;
  WolfCryptoAuth *wc;

  Logging_cb(3, "atca_tls_sign_certificate_cb");
  do {

    if (in == NULL || out == NULL || outSz == NULL) BREAK(ret, "Failed: invalid param");

    wc = static_cast<WolfCryptoAuth*>(ssl->EccPmsCtx);
    if (wc == NULL) BREAK(ret, "CTX invalid");

    ret = wc->sign(in, out);
    if (ret != ATCA_SUCCESS) BREAK(ret, "Failed: sign digest");

    ret = mp_init_multi(&r, &s, NULL, NULL, NULL, NULL);
    if (ret != MP_OKAY) BREAK(ret, "Failed: init R and S");

      /* Load R and S */    
    ret = mp_read_unsigned_bin(&r, &out[0], ATCA_KEY_SIZE);
    if (ret != MP_OKAY) {
      goto exit_sign;
    }
    ret = mp_read_unsigned_bin(&s, &out[ATCA_KEY_SIZE], ATCA_KEY_SIZE);
    if (ret != MP_OKAY) {
      goto exit_sign;
    }

      /* Check for zeros */
    if (mp_iszero(&r) || mp_iszero(&s)) {
      ret = -1;
      goto exit_sign;        
    }

    /* convert mp_ints to ECDSA sig, initializes r and s internally */
    ret = StoreECC_DSA_Sig(out, outSz, &r, &s);
    if (ret != MP_OKAY) {
      goto exit_sign;      
    }

  Logging_cb(3, "atca_tls_sign_certificate_cb OK");
exit_sign:
    mp_clear(&r);
    mp_clear(&s);

  } while(0);

  return ret;
}

int WolfCryptoAuth::atca_tls_verify_signature_cb(WOLFSSL* ssl, const byte* sig,
  word32 sigSz, const byte* hash, word32 hashSz, const byte* key, word32 keySz,
  int* result, void* ctx)
{
  int ret = ATCA_SUCCESS;
  bool verified = FALSE;
  uint8_t raw_sigature[ATCA_SIG_SIZE];  
  mp_int r, s;
  WolfCryptoAuth *wc;

  Logging_cb(3, "atca_tls_verify_signature_cb");
  do {
    if (key == NULL || sig == NULL || hash == NULL || result == NULL)
      BREAK(ret, "Failed: invalid param");

    wc = static_cast<WolfCryptoAuth*>(ssl->EccPmsCtx);
    if (wc == NULL) BREAK(ret, "CTX invalid");

    memset(&r, 0, sizeof(r));
    memset(&s, 0, sizeof(s));

    ret = DecodeECC_DSA_Sig(sig, sigSz, &r, &s);
    if (ret != MP_OKAY) {
        return -1;
    }

    /* Extract R and S */
    ret = mp_to_unsigned_bin(&r, &raw_sigature[0]);
    if (ret != MP_OKAY) {
        goto exit_verify;
    }

    ret = mp_to_unsigned_bin(&s, &raw_sigature[ATCA_KEY_SIZE]);
    if (ret != MP_OKAY) {
        goto exit_verify;
    }

    ret = wc->verify((const uint8_t *)key+1, (const uint8_t *)hash, raw_sigature, verified);
    if (ret != 0 || (verified != TRUE)) { 
      BREAK(ret, "Failed: verify signature");
    } else { 
      *result = TRUE;
      Logging_cb(3, "atca_tls_verify_signature_cb OK");
    }

exit_verify:
    mp_clear(&r);
    mp_clear(&s);

  } while(0);

  return ret;
}

int WolfCryptoAuth::atca_tls_create_pms_cb(WOLFSSL* ssl, unsigned char* pubKey,
  unsigned int* size, unsigned char inOut)
{
  int ret = ATCA_SUCCESS;
  uint8_t peerPubKey[ECC_BUFSIZE];
  uint32_t peerPubKeyLen = sizeof(peerPubKey);
  WolfCryptoAuth *wc;

  Logging_cb(3, "atca_tls_create_pms_cb");
  do {

    if (ssl->arrays->preMasterSecret == NULL || pubKey == NULL || size == NULL || inOut != 0)
      BREAK(ret, "Failed: invalid param");

    wc = static_cast<WolfCryptoAuth*>(ssl->EccPmsCtx);
    if (wc == NULL) BREAK(ret, "CTX invalid");

    ret = wc_ecc_export_x963(ssl->peerEccKey, peerPubKey, (word32*)&peerPubKeyLen);
    if (ret != MP_OKAY) BREAK(ret, "Failed: export public key");

    pubKey[0] = ATCA_PUB_KEY_SIZE + 1;
    pubKey[1] = 0x04;

    ret = wc->ecdh_gen_key(&(pubKey[2]));
    if (ret != 0) BREAK(ret, "Failed: ECDHE gen key");

    ret = wc->ecdh(peerPubKey + 1, ssl->arrays->preMasterSecret);
    if (ret != 0) BREAK(ret, "Failed: ECDH");

    *size = ATCA_PUB_KEY_SIZE + 2;

    ssl->arrays->preMasterSz = ATCA_KEY_SIZE;
  } while(0);
  
  if (ret == 0)
    Logging_cb(3, "atca_tls_create_pms_cb OK");
  else
    Logging_cb(3, "atca_tls_create_pms_cb FAIL");
  return ret;
}

int WolfCryptoAuth::atca_tls_get_random_number(uint32_t count, uint8_t* rand_out)
{
  int ret = ATCA_SUCCESS;
  uint8_t i = 0, rnd_num[RANDOM_NUM_SIZE];
  uint32_t copy_count = 0;

  Logging_cb(3, "atca_tls_get_random_number");
  do {

    if (rand_out == NULL) BREAK(ret, "Failed: invalid param");

    while (i < count) {

      ret = atcatls_random(rnd_num);
      if (ret != 0) BREAK(ret, "Failed: create random number");

      copy_count = (count - i > RANDOM_NUM_SIZE) ? RANDOM_NUM_SIZE : count - i;
      memcpy(&rand_out[i], rnd_num, copy_count);
      i += copy_count;
    }
  } while(0);

  return ret;
}

int WolfCryptoAuth::EccSignCert(const byte* in, word32 inlen,
    byte* out, word32 *outSz, WC_RNG* rng, void *ctx)
{
  int ret = ATCA_SUCCESS;
  mp_int r, s;
  WolfCryptoAuth::tls_callback_info *wc;
  (void)rng;
  (void)ctx;

  if (in == NULL || out == NULL || outSz == NULL) {
    T_PRINTF("Failed: invalid param: %d\n", ret);
    return ret;
  }

  wc = static_cast<WolfCryptoAuth::tls_callback_info*>(ctx);
  if (wc == NULL) {
    T_PRINTF("Failed: ctx cast failed");
    return -1;
  };

  ret = wc->wca->sign(wc->slot, in, out);
  if (ret != ATCA_SUCCESS) {
    T_PRINTF("Failed: sign digest: %d\n", ret);
    return ret;
  }

  ret = mp_init_multi(&r, &s, NULL, NULL, NULL, NULL);
  if (ret != MP_OKAY) {
    T_PRINTF("Failed: init R and S: %d\n", ret);
    return ret;
  }

  do {
      /* Load R and S */    
    ret = mp_read_unsigned_bin(&r, &out[0], ATCA_KEY_SIZE);
    if (ret != MP_OKAY) {
      break;
    }
    ret = mp_read_unsigned_bin(&s, &out[ATCA_KEY_SIZE], ATCA_KEY_SIZE);
    if (ret != MP_OKAY) {
      break;
    }

      /* Check for zeros */
    if (mp_iszero(&r) || mp_iszero(&s)) {
      ret = -1;
      break;
    }

    /* convert mp_ints to ECDSA sig, initializes r and s internally */
    ret = StoreECC_DSA_Sig(out, outSz, &r, &s);
    if (ret != MP_OKAY) {
      break;
    }
  } while(0);

  T_PRINTF("atca_tls_sign_certificate_cb OK");

  mp_clear(&r);
  mp_clear(&s);

  return ret;
}

#if 0
typedef struct atcacert_tm_utc_s {
  int tm_sec;     // 0 to 59
  int tm_min;     // 0 to 59
  int tm_hour;    // 0 to 23
  int tm_mday;    // 1 to 31
  int tm_mon;     // 0 to 11
  int tm_year;    // years since 1900
} atcacert_tm_utc_t;

struct tm {
  int  tm_sec;     /* seconds after the minute [0-60] */
  int  tm_min;     /* minutes after the hour [0-59] */
  int  tm_hour;    /* hours since midnight [0-23] */
  int  tm_mday;    /* day of the month [1-31] */
  int  tm_mon;     /* months since January [0-11] */
  int  tm_year;    /* years since 1900 */
  int  tm_wday;    /* days since Sunday [0-6] */
  int  tm_yday;    /* days since January 1 [0-365] */
  int  tm_isdst;   /* Daylight Savings Time flag */
  long tm_gmtoff;  /* offset from CUT in seconds */
  char *tm_zone;   /* timezone abbreviation */
};
#endif

static word32 BytePrecision(word32 value)
{
    word32 i;
    for (i = sizeof(value); i; --i)
        if (value >> ((i - 1) * WOLFSSL_BIT_SIZE))
            break;

    return i;
}

static word32 SetASNLength(word32 length, byte* output)
{
    word32 i = 0, j;

    if (length < ASN_LONG_LENGTH)
        output[i++] = (byte)length;
    else {
        output[i++] = (byte)(BytePrecision(length) | ASN_LONG_LENGTH);

        for (j = BytePrecision(length); j; --j) {
            output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            i++;
        }
    }

    return i;
}

static INLINE byte itob(int number)
{
    return (byte)number + 0x30;
}

static void SetTime(struct atcacert_tm_utc_s* date, byte* output)
{
    int i = 0;

    output[i++] = itob((date->tm_year % 10000) / 1000);
    output[i++] = itob((date->tm_year % 1000)  /  100);
    output[i++] = itob((date->tm_year % 100)   /   10);
    output[i++] = itob( date->tm_year % 10);

    output[i++] = itob(date->tm_mon / 10);
    output[i++] = itob(date->tm_mon % 10);

    output[i++] = itob(date->tm_mday / 10);
    output[i++] = itob(date->tm_mday % 10);

    output[i++] = itob(date->tm_hour / 10);
    output[i++] = itob(date->tm_hour % 10);

    output[i++] = itob(date->tm_min / 10);
    output[i++] = itob(date->tm_min % 10);

    output[i++] = itob(date->tm_sec / 10);
    output[i++] = itob(date->tm_sec % 10);

    output[i] = 'Z';  /* Zulu profile */
}

static int get_validity_date(struct atcacert_tm_utc_s *tm_bef, struct atcacert_tm_utc_s *tm_aft,
  byte *before, int *beforeSz, byte *after, int *afterSz, int yrs)
{
  before[0] = ASN_GENERALIZED_TIME;
  *beforeSz  = SetASNLength(ASN_GEN_TIME_SZ, before + 1) + 1;  /* gen tag */

  SetTime(tm_bef, before + *beforeSz);
  *beforeSz += ASN_GEN_TIME_SZ;

  after[0] = ASN_GENERALIZED_TIME;
  *afterSz  = SetASNLength(ASN_GEN_TIME_SZ, after + 1) + 1;  /* gen tag */

  SetTime(tm_aft, after + *afterSz);
  *afterSz += ASN_GEN_TIME_SZ;

  return 0;
}

int WolfCryptoAuth::make_cert_req(Cert* cert, byte* buffer, word32 buffSz,
                    ecc_key* key, AtCryptoAuthLib::SlotCfg slot, RNG* rng)
{
  int ret;
  tls_callback_info c_info;

  ret = wc_MakeCertReq(cert, buffer, buffSz, NULL, key);
  if (ret < 0) {
    T_PRINTF("ERROR: wc_MakeCertReq %d\n", ret);
    return ret;
  }
  T_PRINTF("wc_MakeCert %d\n", ret);

  c_info.wca = this;
  c_info.slot = slot;
  ret = wc_SignCert_cb(cert->bodySz, cert->sigType,
          buffer, buffSz, NULL, key, rng, EccSignCert, &c_info);
  if (ret < 0) {
    T_PRINTF("ERROR: wc_SignCert %d\n", ret);
    return ret;
  }
  T_PRINTF("wc_SignCert %d\n", ret);

  return ret;
}

int WolfCryptoAuth::make_csr(AtCryptoAuthLib::SlotCfg slot, cert_info &cn,
        uint8_t *pem, int *pemSz)
{
  int         ret;
  RNG         rng;
  Cert        myCert;
  byte        derCert[2048];
  int         derSz;
  ecc_key     key;
  byte        public_key[128];
  struct atcacert_tm_utc_s   bef, aft;
  ATCA_STATUS status = ATCA_SUCCESS;

  public_key[0] = 0x04;
  status = get_pub_key(slot, &(public_key[1]));
  if (status != ATCA_SUCCESS) {
      T_PRINTF("ERROR: get_pubkey %d\n", status);
      return -1000 - status;
  }

  wc_InitRng(&rng);

  do {
    wc_ecc_init(&key);

    ret = wc_ecc_import_x963(public_key, 65, &key);
    if (ret != 0) {
        T_PRINTF("ERROR: wc_ecc_import_x963 %d\n", ret);
        break;
    }

    ret = wc_ecc_check_key(&key);
    if (ret != 0) {
        T_PRINTF("ERROR: wc_ecc_check_key %d\n", ret);
        break;
    }

    wc_InitCert(&myCert);

    bef.tm_year  = cn.year;
    bef.tm_mon   = cn.mon;
    bef.tm_mday  = cn.day;
    aft.tm_year  = cn.year + cn.valid_years;
    aft.tm_mon   = cn.mon;
    aft.tm_mday  = cn.day;

    get_validity_date(&bef, &aft,
                      myCert.beforeDate, &myCert.beforeDateSz,
                      myCert.afterDate, &myCert.afterDateSz, 4);

    if (cn.country != NULL)
      strncpy(myCert.subject.country, cn.country, CTC_NAME_SIZE);
    if (cn.state != NULL)
      strncpy(myCert.subject.state, cn.state, CTC_NAME_SIZE);
    if (cn.locality != NULL)
      strncpy(myCert.subject.locality, cn.locality, CTC_NAME_SIZE);
    if (cn.sur != NULL)
      strncpy(myCert.subject.sur, cn.sur, CTC_NAME_SIZE);
    if (cn.org != NULL)
      strncpy(myCert.subject.org, cn.org, CTC_NAME_SIZE);
    if (cn.unit != NULL)
      strncpy(myCert.subject.unit, cn.unit, CTC_NAME_SIZE);
    if (cn.commonName != NULL)
      strncpy(myCert.subject.commonName, cn.commonName, CTC_NAME_SIZE);
    if (cn.email != NULL)
      strncpy(myCert.subject.email, cn.email, CTC_NAME_SIZE);

    myCert.sigType = CTC_SHA256wECDSA;

    /* add SKID from the Public Key */
    ret = wc_SetSubjectKeyIdFromPublicKey(&myCert, NULL, &key);
    if (ret != 0) {
      break;
    }

    /* add AKID from the Public Key */
    ret = wc_SetAuthKeyIdFromPublicKey(&myCert, NULL, &key);
    if (ret != 0) {
      break;
    }

    derSz = make_cert_req(&myCert, derCert, 2048, &key, slot, &rng);
    if (derSz < 0) {
      ret = derSz;
      break;
    }

    *pemSz = wc_DerToPem(derCert, derSz, pem, *pemSz, CERTREQ_TYPE);
    if (*pemSz < 0) {
      ret = *pemSz;
      break;
    }

    ret = 0;
  } while (0);

  wc_FreeRng(&rng);

  return ret;
}

bool WolfCryptoAuthCert::have_cert()
{
  int ret;
  uint8_t cert_der[1024];
  size_t cert_der_size;
  size_t cert_pem_size;

  cert_data = (uint8_t *)malloc(2048);
  if (cert_data == NULL)
    return false;

  cert_der_size = 1024;
  cert_pem_size = 2048;
  ret = ecc->build_device_cert(cert_der, &cert_der_size,
      cert_data, &cert_pem_size);
  if (ret != ATCA_SUCCESS) {
    free(cert_data);
    cert_data = NULL;
    return false;
  }
  cert_data[cert_pem_size] = '\n';
  cert_data_size = cert_pem_size+1;
  
  cert_der_size = 1024;
  cert_pem_size = 2048-cert_pem_size;
  ret = ecc->build_signer_cert(cert_der, &cert_der_size,
      &(cert_data[cert_data_size]), &cert_pem_size);
  if (ret != ATCA_SUCCESS) {
    free(cert_data);
    cert_data = NULL;
    return false;
  }
  cert_data_size += cert_pem_size;

  cert_data[cert_data_size] = '\0';

  return true;
}

const uint8_t *WolfCryptoAuthCert::data()
{
/*
  char *p;
  int x, sl;
  sl = strlen((char*)cert_data);
  p = (char *)cert_data;
  Serial.flush();
  for (x = 0; x < sl; x++) {
    if (cert_data[x] == '\r') {
      cert_data[x] = '\0';
      Serial.println(p);
      cert_data[x] = '\r';
      p = (char *)&(cert_data[x+1]);
    }
  }

  Serial.println((char*)cert_data);
  Serial.flush();
*/
  return cert_data;
}

size_t WolfCryptoAuthCert::size()
{
  return cert_data_size;
}

void WolfCryptoAuthCert::done()
{
  free(cert_data);
  cert_data = NULL;
}


bool WolfCertEEPROM::have_cert()
{
  size_t sz;

  cert_data = (uint8_t *)malloc(2048);
  if (cert_data == NULL)
    return false;

  // device then signer
  cert_data_size = 0;
  if (cert1_id != 0) {
    sz = read_cert_eeprom(cert1_id, &(cert_data[cert_data_size]),
                          2048-cert_data_size);
    if (sz == 0) {
      free(cert_data);
      return false;
    }
    cert_data_size += sz;
  }
  if (cert2_id != 0) {
    sz = read_cert_eeprom(cert2_id, &(cert_data[cert_data_size]),
                          2048-cert_data_size);
    if (sz == 0) {
      free(cert_data);
      return false;
    }
    cert_data_size += sz;
  }
  if (cert3_id != 0) {
    sz = read_cert_eeprom(cert3_id, &(cert_data[cert_data_size]),
                          2048-cert_data_size);
    if (sz == 0) {
      free(cert_data);
      return false;
    }
    cert_data_size += sz;
  }
  cert_data[cert_data_size] = '\0';

  return true;
}

const uint8_t *WolfCertEEPROM::data()
{
/*
  Serial.println((char*)cert_data);
  int x, sl;
  char *p;

  Serial.flush();
  sl = strlen((char*)cert_data);
  p = (char *)cert_data;
  for (x = 0; x < sl; x++) {
    if (cert_data[x] == '\r') {
      cert_data[x] = '\0';
      Serial.println(p);
      cert_data[x] = '\r';
      p = (char *)&(cert_data[x+1]);
    }
  }
  Serial.flush();
*/

  return cert_data;
}

size_t WolfCertEEPROM::size()
{
  return cert_data_size;
}

void WolfCertEEPROM::done()
{
  free(cert_data);
  cert_data = NULL;
}

int WolfCertEEPROM::i2c_eeprom_read(int addr, uint32_t eeaddress,
                            uint8_t *buffer, int length)
{
  size_t ret;
  int rr;

  Wire.beginTransmission(addr);
  ret = Wire.write((int)(eeaddress >> 8)); // MSB
  if (ret != 1) return 101;
  ret = Wire.write((int)(eeaddress & 0xFF)); // LSB
  if (ret != 1) return 102;
  ret = Wire.endTransmission();
  if (ret != 0) return ret;
  ret = Wire.requestFrom(addr,length);
  if (ret == 0) return 103;
  for (int c = 0; c < length; c++ ) {
    if (Wire.available()) {
      rr = Wire.read();
      if (rr < 0) return 104;
      buffer[c] = rr;
    } else {
      return 105;
    }
  }
  return 0;
}

size_t WolfCertEEPROM::read_cert_eeprom(int cert_id, uint8_t *data, size_t dsize)
{
  uint16_t wr_start;
  size_t i;
  int ret, w;

  wr_start = 2048*cert_id;

  for (i = 0; i < dsize; i += 32) {
    ret = i2c_eeprom_read(0x50, wr_start+i, &(data[i]), 32);
    if (ret != 0) {
      return 0;
    }
    for (w = 0; w < 32; w++) {
      if (data[i+w] == '\0') {
        return (i+w);
      }
    }
  }
  return 0;
}

#ifdef CORE_TEENSY
#include <EEPROM.h>

/*
 * on teensy EEPROM with ECC508a:
 * 32-byte slot key
 * 2-bytes Cert 1 len (MSB first) (Device)
   = (EEPROM[32] << 8) | EEPROM[33]
 * 2-bytes Cert 2 len (Signer)
   = (EEPROM[34] << 8) | EEPROM[35]
 * N-bytes Cert 1
 * N-bytes Cert 2
 */
bool WolfCertTeensyEEPROM::have_cert()
{
  size_t sz1, sz2;
  size_t alloc_sz;
  size_t i;

  sz1 = ((EEPROM.read(32) << 8) & 0xFF00) | (EEPROM.read(33) & 0x00FF);
  sz2 = ((EEPROM.read(34) << 8) & 0xFF00) | (EEPROM.read(35) & 0x00FF);
  if ((sz1 == 0) || (sz2 == 0) || (sz1+sz2+36 > 2048)) {
    return false;
  }

  alloc_sz = sz1+sz2+1;
  cert_data = (uint8_t *)malloc(alloc_sz);
  if (cert_data == NULL)
    return false;

  for (i = 0; i < sz1; i++) {
    cert_data[i] = EEPROM.read(i+36);
  }
  for (i = 0; i < sz2; i++) {
    cert_data[i+sz1] = EEPROM.read(sz1+i+36);
  }
  cert_data_size = sz1+sz2;
  cert_data[cert_data_size] = '\0';

  return true;
}

const uint8_t *WolfCertTeensyEEPROM::data()
{
  return cert_data;
}

size_t WolfCertTeensyEEPROM::size()
{
  return cert_data_size;
}

void WolfCertTeensyEEPROM::done()
{
  free(cert_data);
  cert_data = NULL;
}

#endif // CORE_TEENSY

int WolfSSL_GenerateSeed(uint8_t *output, uint32_t sz)
{
  uint8_t rand_out[32];
  int ret = 0;

  if (output == NULL) {
    return -1;
  }

  ret = atcab_random(rand_out);
  for (uint32_t i = 0; i < sz; i++) {
    output[i] = rand_out[i % 32];
  }

  return ret;
}


