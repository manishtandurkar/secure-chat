#ifndef PREKEY_H
#define PREKEY_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "common.h"

/* Pre-key bundle for initial key exchange */
typedef struct {
    EVP_PKEY *identity_key;
    EVP_PKEY *signed_prekey;
    uint8_t   signed_prekey_sig[512];
    size_t    sig_len;
    EVP_PKEY *one_time_prekey;
} PreKeyBundle;

EVP_PKEY    *prekey_generate(void);
PreKeyBundle prekey_bundle_create(EVP_PKEY *identity_key);
void         prekey_bundle_free(PreKeyBundle *bundle);

#endif /* PREKEY_H */
