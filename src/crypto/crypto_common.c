#include "crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

/* Generate cryptographically secure random bytes */
int generate_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return ERROR_CRYPTO;
    }
    
    if (RAND_bytes(buf, len) != 1) {
        return ERROR_CRYPTO;
    }
    
    return SUCCESS;
}

/* HMAC-SHA256: outputs 32 bytes */
int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *output) {
    if (!key || !data || !output) {
        return ERROR_CRYPTO;
    }
    
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha256(), key, key_len, data, data_len, output, &out_len)) {
        return ERROR_CRYPTO;
    }
    
    if (out_len != 32) {
        return ERROR_CRYPTO;
    }
    
    return SUCCESS;
}

/* HKDF-SHA256 key derivation */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *input_key, size_t input_key_len,
                const uint8_t *info, size_t info_len,
                uint8_t *output, size_t output_len) {
    if (!input_key || !output || output_len == 0) {
        return ERROR_CRYPTO;
    }
    
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) {
        return ERROR_CRYPTO;
    }
    
    int ret = ERROR_CRYPTO;
    
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        goto cleanup;
    }
    
    if (salt && salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
            goto cleanup;
        }
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, input_key, input_key_len) <= 0) {
        goto cleanup;
    }
    
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
            goto cleanup;
        }
    }
    
    size_t actual_len = output_len;
    if (EVP_PKEY_derive(pctx, output, &actual_len) <= 0) {
        goto cleanup;
    }
    
    if (actual_len != output_len) {
        goto cleanup;
    }
    
    ret = SUCCESS;
    
cleanup:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/* KDF_CK: advance chain key for Double Ratchet
   chain_key_out = HMAC-SHA256(chain_key, 0x02)
   msg_key_out   = HMAC-SHA256(chain_key, 0x01) */
void kdf_ck(const uint8_t *chain_key,
            uint8_t *chain_key_out,
            uint8_t *msg_key_out) {
    uint8_t constant_msg = 0x01;
    uint8_t constant_chain = 0x02;
    
    /* Derive message key */
    hmac_sha256(chain_key, RATCHET_KEY_LEN, &constant_msg, 1, msg_key_out);
    
    /* Derive next chain key */
    hmac_sha256(chain_key, RATCHET_KEY_LEN, &constant_chain, 1, chain_key_out);
}

/* KDF_RK: derive new root key and chain key from DH output
   Uses HKDF-SHA256 with root_key as salt */
void kdf_rk(const uint8_t *root_key,
            const uint8_t *dh_output, size_t dh_len,
            uint8_t *rk_out, uint8_t *ck_out) {
    uint8_t combined_output[64]; /* 32 bytes for RK + 32 bytes for CK */
    
    /* Use HKDF with root_key as salt, dh_output as input key material */
    hkdf_sha256(root_key, RATCHET_KEY_LEN,
                dh_output, dh_len,
                NULL, 0,  /* No info string */
                combined_output, 64);
    
    /* Split output: first 32 bytes = new root key, next 32 bytes = new chain key */
    memcpy(rk_out, combined_output, RATCHET_KEY_LEN);
    memcpy(ck_out, combined_output + RATCHET_KEY_LEN, RATCHET_KEY_LEN);
    
    /* Zero the temporary buffer */
    OPENSSL_cleanse(combined_output, 64);
}
