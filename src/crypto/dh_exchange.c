#include "crypto.h"
#include <string.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* Generate Diffie-Hellman keypair using X25519 (modern, secure) */
EVP_PKEY *dh_generate_keypair(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    
    if (!ctx) {
        return NULL;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Extract DH public key to buffer (32 bytes for X25519) */
int dh_get_public_key(EVP_PKEY *keypair, uint8_t *pubkey_out, size_t *pubkey_len) {
    if (!keypair || !pubkey_out || !pubkey_len) {
        return ERROR_CRYPTO;
    }
    
    size_t len = *pubkey_len;
    if (EVP_PKEY_get_raw_public_key(keypair, pubkey_out, &len) != 1) {
        return ERROR_CRYPTO;
    }
    
    *pubkey_len = len;
    return SUCCESS;
}

/* Create EVP_PKEY from raw DH public key bytes */
EVP_PKEY *dh_pubkey_from_bytes(const uint8_t *pubkey_bytes, size_t len) {
    if (!pubkey_bytes || len != 32) {  /* X25519 public keys are always 32 bytes */
        return NULL;
    }
    
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, 
                                                   pubkey_bytes, len);
    return pkey;
}

/* Compute shared secret from our private key and peer's public key */
int dh_compute_shared_secret(EVP_PKEY *our_keypair, EVP_PKEY *peer_pubkey,
                              uint8_t *secret_out, size_t *secret_len) {
    if (!our_keypair || !peer_pubkey || !secret_out || !secret_len) {
        return ERROR_CRYPTO;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_keypair, NULL);
    if (!ctx) {
        return ERROR_CRYPTO;
    }
    
    int ret = ERROR_CRYPTO;
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        goto cleanup;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0) {
        goto cleanup;
    }
    
    /* Get length of shared secret */
    size_t len = 0;
    if (EVP_PKEY_derive(ctx, NULL, &len) <= 0) {
        goto cleanup;
    }
    
    if (len > *secret_len) {
        goto cleanup;
    }
    
    /* Actually derive the shared secret */
    if (EVP_PKEY_derive(ctx, secret_out, &len) <= 0) {
        goto cleanup;
    }
    
    *secret_len = len;
    ret = SUCCESS;
    
cleanup:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* Serialize DH public key to buffer for transmission */
int dh_serialize_pubkey(EVP_PKEY *pubkey, uint8_t *buf, size_t buf_len, size_t *bytes_written) {
    if (!pubkey || !buf || !bytes_written) {
        return ERROR_CRYPTO;
    }
    
    size_t len = buf_len;
    if (EVP_PKEY_get_raw_public_key(pubkey, buf, &len) != 1) {
        return ERROR_CRYPTO;
    }
    
    *bytes_written = len;
    return SUCCESS;
}

/* Deserialize DH public key from buffer */
EVP_PKEY *dh_deserialize_pubkey(const uint8_t *buf, size_t len) {
    if (!buf || len != 32) {  /* X25519 keys are 32 bytes */
        return NULL;
    }
    
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, buf, len);
}
