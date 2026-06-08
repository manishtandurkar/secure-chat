#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "common.h"

/* RSA functions */
EVP_PKEY *rsa_generate_keypair(void);
int  rsa_pubkey_to_pem(EVP_PKEY *key, char *buf, size_t buf_len);
EVP_PKEY *rsa_pubkey_from_pem(const char *pem_buf, size_t pem_len);
int  rsa_sign(EVP_PKEY *privkey, const unsigned char *data, size_t data_len,
              unsigned char *sig_buf, size_t *sig_len);
int  rsa_verify(EVP_PKEY *pubkey, const unsigned char *data, size_t data_len,
                const unsigned char *sig, size_t sig_len);

/* AES functions */
int  aes_encrypt(const unsigned char *key,
                 const unsigned char *iv,
                 const unsigned char *plaintext, int plaintext_len,
                 unsigned char *ciphertext_buf);

int  aes_decrypt(const unsigned char *key,
                 const unsigned char *iv,
                 const unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *plaintext_buf);

int  aes_generate_iv(unsigned char *iv_buf);

int  msg_pad(const uint8_t *plaintext, size_t plaintext_len,
             uint8_t *padded_out);

int  msg_unpad(const uint8_t *padded, size_t padded_len,
               uint8_t *plaintext_out);

/* KDF functions (crypto_common.c) */
void kdf_ck(const uint8_t *chain_key,
            uint8_t *chain_key_out,
            uint8_t *msg_key_out);

void kdf_rk(const uint8_t *root_key,
            const uint8_t *dh_output, size_t dh_len,
            uint8_t *rk_out, uint8_t *ck_out);

int  hkdf_derive(const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len,
                 uint8_t *out, size_t out_len);

int  hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out);

int  random_bytes(uint8_t *buf, size_t len);

/* DH key exchange */
EVP_PKEY *dh_generate_keypair(void);
int  dh_compute_shared_secret(EVP_PKEY *privkey, EVP_PKEY *peer_pubkey,
                               uint8_t *secret_out, size_t *secret_len);

#endif /* CRYPTO_H */
