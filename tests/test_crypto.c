#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "crypto.h"
#include "common.h"

static int test_aes_roundtrip(void) {
    uint8_t key[AES_KEY_LEN];
    uint8_t iv[AES_IV_LEN];
    const char *msg = "Hello, secure world!";
    size_t msg_len  = strlen(msg);

    assert(random_bytes(key, sizeof(key)) == 0);
    assert(aes_generate_iv(iv) == 0);

    uint8_t padded[MSG_PADDED_SIZE];
    assert(msg_pad((uint8_t *)msg, msg_len, padded) == 0);

    uint8_t ciphertext[MSG_PADDED_SIZE + 32];
    int ct_len = aes_encrypt(key, iv, padded, MSG_PADDED_SIZE, ciphertext);
    assert(ct_len > 0);

    uint8_t decrypted[MSG_PADDED_SIZE + 32];
    int dec_len = aes_decrypt(key, iv, ciphertext, ct_len, decrypted);
    assert(dec_len > 0);

    uint8_t plain[MSG_PADDED_SIZE + 1];
    int plain_len = msg_unpad(decrypted, (size_t)dec_len, plain);
    assert(plain_len > 0);
    assert((size_t)plain_len == msg_len);
    assert(memcmp(plain, msg, msg_len) == 0);

    printf("[PASS] AES-256-CBC round-trip\n");
    OPENSSL_cleanse(key, sizeof(key));
    return 0;
}

static int test_rsa_sign_verify(void) {
    EVP_PKEY *keypair = rsa_generate_keypair();
    assert(keypair != NULL);

    const uint8_t data[] = "test challenge data";
    uint8_t sig[512];
    size_t  sig_len = sizeof(sig);

    assert(rsa_sign(keypair, data, sizeof(data), sig, &sig_len) == 0);

    char pem_buf[4096];
    assert(rsa_pubkey_to_pem(keypair, pem_buf, sizeof(pem_buf)) > 0);

    EVP_PKEY *pubkey = rsa_pubkey_from_pem(pem_buf, strlen(pem_buf));
    assert(pubkey != NULL);

    assert(rsa_verify(pubkey, data, sizeof(data), sig, sig_len) == 0);

    /* Tampered data should fail */
    uint8_t tampered[] = "tampered data!!!!";
    assert(rsa_verify(pubkey, tampered, sizeof(tampered), sig, sig_len) != 0);

    EVP_PKEY_free(keypair);
    EVP_PKEY_free(pubkey);
    printf("[PASS] RSA sign/verify\n");
    return 0;
}

static int test_msg_pad_unpad(void) {
    const char *msg = "short message";
    uint8_t padded[MSG_PADDED_SIZE];
    assert(msg_pad((uint8_t *)msg, strlen(msg), padded) == 0);

    uint8_t out[MSG_PADDED_SIZE + 1];
    int n = msg_unpad(padded, MSG_PADDED_SIZE, out);
    assert(n == (int)strlen(msg));
    assert(memcmp(out, msg, (size_t)n) == 0);

    printf("[PASS] msg_pad / msg_unpad\n");
    return 0;
}

int main(void) {
    printf("=== test_crypto ===\n");
    test_aes_roundtrip();
    test_rsa_sign_verify();
    test_msg_pad_unpad();
    printf("All crypto tests passed.\n");
    return 0;
}
