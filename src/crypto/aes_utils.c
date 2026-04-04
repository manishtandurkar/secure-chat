#include "crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* Generate random 16-byte IV for AES */
int aes_generate_iv(unsigned char *iv_buf) {
    if (!iv_buf) {
        return ERROR_CRYPTO;
    }
    
    if (RAND_bytes(iv_buf, AES_IV_LEN) != 1) {
        return ERROR_CRYPTO;
    }
    
    return SUCCESS;
}

/* AES-256-CBC encryption */
int aes_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *plaintext, int plaintext_len,
                unsigned char *ciphertext_buf) {
    if (!key || !iv || !plaintext || !ciphertext_buf) {
        return ERROR_CRYPTO;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ERROR_CRYPTO;
    }
    
    int len = 0;
    int ciphertext_len = 0;
    int ret = ERROR_CRYPTO;
    
    /* Initialize encryption */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        goto cleanup;
    }
    
    /* Encrypt plaintext */
    if (EVP_EncryptUpdate(ctx, ciphertext_buf, &len, plaintext, plaintext_len) != 1) {
        goto cleanup;
    }
    ciphertext_len = len;
    
    /* Finalize encryption (adds padding if needed) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext_buf + len, &len) != 1) {
        goto cleanup;
    }
    ciphertext_len += len;
    
    ret = ciphertext_len;
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* AES-256-CBC decryption */
int aes_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext_buf) {
    if (!key || !iv || !ciphertext || !plaintext_buf) {
        return ERROR_CRYPTO;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ERROR_CRYPTO;
    }
    
    int len = 0;
    int plaintext_len = 0;
    int ret = ERROR_CRYPTO;
    
    /* Initialize decryption */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        goto cleanup;
    }
    
    /* Decrypt ciphertext */
    if (EVP_DecryptUpdate(ctx, plaintext_buf, &len, ciphertext, ciphertext_len) != 1) {
        goto cleanup;
    }
    plaintext_len = len;
    
    /* Finalize decryption (removes padding) */
    if (EVP_DecryptFinal_ex(ctx, plaintext_buf + len, &len) != 1) {
        goto cleanup;
    }
    plaintext_len += len;
    
    ret = plaintext_len;
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Pad plaintext to MSG_PADDED_SIZE using length-prefix scheme
 * Format: [4-byte little-endian length][plaintext][random padding]
 * This allows messages up to MSG_PADDED_SIZE - 4 bytes */
int msg_pad(const uint8_t *plaintext, size_t plaintext_len,
            uint8_t *padded_out) {
    if (!plaintext || !padded_out || plaintext_len > MSG_PADDED_SIZE - 4) {
        return ERROR_CRYPTO;
    }
    
    /* Write 4-byte length prefix (little-endian) */
    uint32_t len32 = (uint32_t)plaintext_len;
    padded_out[0] = (uint8_t)(len32 & 0xFF);
    padded_out[1] = (uint8_t)((len32 >> 8) & 0xFF);
    padded_out[2] = (uint8_t)((len32 >> 16) & 0xFF);
    padded_out[3] = (uint8_t)((len32 >> 24) & 0xFF);
    
    /* Copy plaintext after length prefix */
    memcpy(padded_out + 4, plaintext, plaintext_len);
    
    /* Fill remaining space with random bytes for traffic analysis resistance */
    size_t padding_start = 4 + plaintext_len;
    size_t padding_len = MSG_PADDED_SIZE - padding_start;
    if (padding_len > 0) {
        RAND_bytes(padded_out + padding_start, padding_len);
    }
    
    return SUCCESS;
}

/* Strip padding using length-prefix scheme */
int msg_unpad(const uint8_t *padded, size_t padded_len,
              uint8_t *plaintext_out) {
    if (!padded || !plaintext_out || padded_len < 4) {
        return ERROR_CRYPTO;
    }
    
    /* Read 4-byte length prefix (little-endian) */
    uint32_t len32 = (uint32_t)padded[0] |
                     ((uint32_t)padded[1] << 8) |
                     ((uint32_t)padded[2] << 16) |
                     ((uint32_t)padded[3] << 24);
    
    /* Validate length */
    if (len32 > padded_len - 4) {
        return ERROR_CRYPTO;
    }
    
    /* Copy plaintext (after length prefix) */
    memcpy(plaintext_out, padded + 4, len32);
    
    return (int)len32;
}
