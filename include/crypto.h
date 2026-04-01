#ifndef CRYPTO_H
#define CRYPTO_H

#include "common.h"

/* Forward declaration for OpenSSL types */
typedef struct evp_pkey_st EVP_PKEY;

/* RSA utilities */

/**
 * Generate a new RSA-2048 keypair. Returns EVP_PKEY* or NULL on error.
 */
EVP_PKEY *rsa_generate_keypair(void);

/**
 * Serialize public key to PEM format into buf (max buf_len bytes).
 * Returns number of bytes written, or -1 on error.
 */
int rsa_pubkey_to_pem(EVP_PKEY *key, char *buf, size_t buf_len);

/**
 * Load a public key from PEM buffer. Returns EVP_PKEY* or NULL.
 */
EVP_PKEY *rsa_pubkey_from_pem(const char *pem_buf, size_t pem_len);

/**
 * Sign data using private key. Signature written to sig_buf.
 * sig_len set to actual signature length. Returns 0 on success.
 */
int rsa_sign(EVP_PKEY *privkey, const unsigned char *data, size_t data_len,
             unsigned char *sig_buf, size_t *sig_len);

/**
 * Verify signature. Returns 1 if valid, 0 if invalid, -1 on error.
 */
int rsa_verify(EVP_PKEY *pubkey, const unsigned char *data, size_t data_len,
               const unsigned char *sig, size_t sig_len);

/* AES utilities */

/**
 * Encrypt plaintext using AES-256-CBC.
 * key must be 32 bytes. iv must be 16 bytes (randomly generated per message).
 * ciphertext_buf must be at least plaintext_len + AES_BLOCK_SIZE bytes.
 * Returns ciphertext length or -1 on error.
 */
int aes_encrypt(const unsigned char *key, const unsigned char *iv,
                const unsigned char *plaintext, int plaintext_len,
                unsigned char *ciphertext_buf);

/**
 * Decrypt ciphertext using AES-256-CBC.
 * Returns plaintext length or -1 on error.
 */
int aes_decrypt(const unsigned char *key, const unsigned char *iv,
                const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext_buf);

/**
 * Generate cryptographically secure random IV (16 bytes).
 * Returns 0 on success, -1 on failure.
 */
int aes_generate_iv(unsigned char *iv_buf);

/* Diffie-Hellman utilities (X25519) */

/**
 * Generate DH keypair using X25519. Returns EVP_PKEY* or NULL.
 */
EVP_PKEY *dh_generate_keypair(void);

/**
 * Extract DH public key to buffer (32 bytes for X25519).
 * Returns 0 on success, -1 on error.
 */
int dh_get_public_key(EVP_PKEY *keypair, uint8_t *pubkey_out, size_t *pubkey_len);

/**
 * Create EVP_PKEY from raw DH public key bytes.
 * Returns EVP_PKEY* or NULL.
 */
EVP_PKEY *dh_pubkey_from_bytes(const uint8_t *pubkey_bytes, size_t len);

/**
 * Compute shared secret from our private key and peer's public key.
 * Returns 0 on success, -1 on error.
 */
int dh_compute_shared_secret(EVP_PKEY *our_keypair, EVP_PKEY *peer_pubkey,
                              uint8_t *secret_out, size_t *secret_len);

/**
 * Serialize DH public key to buffer for transmission.
 * Returns 0 on success, -1 on error.
 */
int dh_serialize_pubkey(EVP_PKEY *pubkey, uint8_t *buf, size_t buf_len, size_t *bytes_written);

/**
 * Deserialize DH public key from buffer.
 * Returns EVP_PKEY* or NULL.
 */
EVP_PKEY *dh_deserialize_pubkey(const uint8_t *buf, size_t len);

/* Message padding utilities */

/**
 * Pad plaintext to MSG_PADDED_SIZE using PKCS#7-style padding.
 * Output buffer must be MSG_PADDED_SIZE bytes.
 * Returns 0 or -1.
 */
int msg_pad(const uint8_t *plaintext, size_t plaintext_len, uint8_t *padded_out);

/**
 * Strip padding after decryption. Returns original length or -1.
 */
int msg_unpad(const uint8_t *padded, size_t padded_len, uint8_t *plaintext_out);

/* Common crypto utilities */

/**
 * Generate cryptographically secure random bytes
 * Returns 0 on success, -1 on failure
 */
int generate_random_bytes(uint8_t *buf, size_t len);

/**
 * HMAC-SHA256: outputs 32 bytes
 * Returns 0 on success, -1 on error
 */
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *output);

/**
 * HKDF-SHA256 key derivation
 * Returns 0 on success, -1 on error
 */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *input_key, size_t input_key_len,
                const uint8_t *info, size_t info_len,
                uint8_t *output, size_t output_len);

/**
 * KDF_CK: advance chain key for Double Ratchet
 * chain_key_out = HMAC-SHA256(chain_key, 0x02)
 * msg_key_out   = HMAC-SHA256(chain_key, 0x01)
 */
void kdf_ck(const uint8_t *chain_key, uint8_t *chain_key_out, uint8_t *msg_key_out);

/**
 * KDF_RK: derive new root key and chain key from DH output
 * Uses HKDF-SHA256 with root_key as salt
 */
void kdf_rk(const uint8_t *root_key,
            const uint8_t *dh_output, size_t dh_len,
            uint8_t *rk_out, uint8_t *ck_out);

/**
 * Free EVP_PKEY (works for RSA and DH keys)
 */
void crypto_free_key(EVP_PKEY *key);

#endif /* CRYPTO_H */