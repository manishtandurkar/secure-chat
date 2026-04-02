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

/* Pad plaintext to MSG_PADDED_SIZE using PKCS#7-style padding */
int msg_pad(const uint8_t *plaintext, size_t plaintext_len,
            uint8_t *padded_out) {
    if (!plaintext || !padded_out || plaintext_len > MSG_PADDED_SIZE) {
        return ERROR_CRYPTO;
    }
    
    /* Copy plaintext */
    memcpy(padded_out, plaintext, plaintext_len);
    
    /* Calculate padding length */
    size_t padding_len = MSG_PADDED_SIZE - plaintext_len;
    
    /* Apply PKCS#7 padding: fill with padding length value */
    memset(padded_out + plaintext_len, (uint8_t)padding_len, padding_len);
    
    return SUCCESS;
}

/* Strip PKCS#7 padding after decryption */
int msg_unpad(const uint8_t *padded, size_t padded_len,
              uint8_t *plaintext_out) {
    if (!padded || !plaintext_out || padded_len != MSG_PADDED_SIZE) {
        return ERROR_CRYPTO;
    }
    
    /* Get padding length from last byte */
    uint8_t padding_len = padded[padded_len - 1];
    
    /* Validate padding length */
    if (padding_len == 0 || padding_len > MSG_PADDED_SIZE) {
        return ERROR_CRYPTO;
    }
    
    /* Verify all padding bytes are correct */
    for (size_t i = padded_len - padding_len; i < padded_len; i++) {
        if (padded[i] != padding_len) {
            return ERROR_CRYPTO;
        }
    }
    
    /* Calculate original plaintext length */
    size_t plaintext_len = padded_len - padding_len;
    
    /* Copy unpadded plaintext */
    memcpy(plaintext_out, padded, plaintext_len);
    
    return (int)plaintext_len;
}
