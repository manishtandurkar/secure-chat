#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "crypto.h"
#include "common.h"

int aes_encrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *plaintext, int plaintext_len,
                unsigned char *ciphertext_buf) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0, rc = -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto done;
    if (EVP_EncryptUpdate(ctx, ciphertext_buf, &len, plaintext, plaintext_len) != 1) goto done;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext_buf + total, &len) != 1) goto done;
    total += len;
    rc = total;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (rc < 0) ERR_print_errors_fp(stderr);
    return rc;
}

int aes_decrypt(const unsigned char *key,
                const unsigned char *iv,
                const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext_buf) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0, rc = -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto done;
    if (EVP_DecryptUpdate(ctx, plaintext_buf, &len, ciphertext, ciphertext_len) != 1) goto done;
    total = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext_buf + total, &len) != 1) goto done;
    total += len;
    rc = total;

done:
    EVP_CIPHER_CTX_free(ctx);
    if (rc < 0) ERR_print_errors_fp(stderr);
    return rc;
}

int aes_generate_iv(unsigned char *iv_buf) {
    if (RAND_bytes(iv_buf, AES_IV_LEN) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int msg_pad(const uint8_t *plaintext, size_t plaintext_len,
            uint8_t *padded_out) {
    /* Layout: 4-byte LE length | message | zero padding to MSG_PADDED_SIZE */
    if (plaintext_len > MSG_PADDED_SIZE - 4) return -1;

    uint32_t len32 = (uint32_t)plaintext_len;
    memcpy(padded_out, &len32, 4);
    memcpy(padded_out + 4, plaintext, plaintext_len);
    memset(padded_out + 4 + plaintext_len, 0, MSG_PADDED_SIZE - 4 - plaintext_len);

    return 0;
}

int msg_unpad(const uint8_t *padded, size_t padded_len,
              uint8_t *plaintext_out) {
    if (padded_len < 4) return -1;

    uint32_t plain_len;
    memcpy(&plain_len, padded, 4);

    if (plain_len > padded_len - 4) return -1;

    memcpy(plaintext_out, padded + 4, plain_len);
    plaintext_out[plain_len] = '\0';
    return (int)plain_len;
}
