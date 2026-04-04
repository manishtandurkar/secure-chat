/**
 * Crypto Tests - Validate RSA, AES, HKDF, HMAC operations
 */

#include "../include/crypto.h"
#include "../include/common.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

int tests_passed = 0;
int tests_failed = 0;

/* Test 1: RSA Sign/Verify Round-Trip */
int test_rsa_sign_verify(void) {
    printf("\n=== Test 1: RSA Sign/Verify ===\n");
    
    EVP_PKEY *keypair = rsa_generate_keypair();
    if (!keypair) {
        printf("%s Failed to generate RSA keypair\n", TEST_FAIL);
        return 0;
    }
    
    /* Test data */
    const char *message = "Hello, World!";
    uint8_t signature[512];
    size_t sig_len = sizeof(signature);
    
    /* Sign */
    if (rsa_sign(keypair, (const uint8_t *)message, strlen(message), 
                 signature, &sig_len) != 0) {
        printf("%s RSA sign failed\n", TEST_FAIL);
        EVP_PKEY_free(keypair);
        return 0;
    }
    
    printf("    Signature length: %zu bytes\n", sig_len);
    
    /* Verify */
    if (rsa_verify(keypair, (const uint8_t *)message, strlen(message),
                   signature, sig_len) != 0) {
        printf("%s RSA verify failed\n", TEST_FAIL);
        EVP_PKEY_free(keypair);
        return 0;
    }
    
    /* Tamper with signature */
    signature[0] ^= 0xFF;
    if (rsa_verify(keypair, (const uint8_t *)message, strlen(message),
                   signature, sig_len) == 0) {
        printf("%s RSA verify accepted tampered signature\n", TEST_FAIL);
        EVP_PKEY_free(keypair);
        return 0;
    }
    
    EVP_PKEY_free(keypair);
    printf("%s RSA sign/verify works correctly\n", TEST_PASS);
    return 1;
}

/* Test 2: AES Encrypt/Decrypt Round-Trip */
int test_aes_encrypt_decrypt(void) {
    printf("\n=== Test 2: AES Encrypt/Decrypt ===\n");
    
    uint8_t key[AES_KEY_LEN];
    uint8_t iv[AES_IV_LEN];
    RAND_bytes(key, sizeof(key));
    aes_generate_iv(iv);
    
    const char *plaintext = "This is a secret message!";
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    
    /* Encrypt */
    int ct_len = aes_encrypt(key, iv, (const uint8_t *)plaintext, 
                             strlen(plaintext), ciphertext);
    if (ct_len < 0) {
        printf("%s AES encrypt failed\n", TEST_FAIL);
        return 0;
    }
    
    printf("    Plaintext:  %zu bytes\n", strlen(plaintext));
    printf("    Ciphertext: %d bytes\n", ct_len);
    
    /* Decrypt */
    int pt_len = aes_decrypt(key, iv, ciphertext, ct_len, decrypted);
    if (pt_len < 0) {
        printf("%s AES decrypt failed\n", TEST_FAIL);
        return 0;
    }
    
    decrypted[pt_len] = '\0';
    
    /* Verify */
    if (strcmp((char *)decrypted, plaintext) != 0) {
        printf("%s Decrypted text doesn't match original\n", TEST_FAIL);
        printf("    Expected: %s\n", plaintext);
        printf("    Got:      %s\n", decrypted);
        return 0;
    }
    
    printf("%s AES round-trip successful\n", TEST_PASS);
    return 1;
}

/* Test 3: Padding/Unpadding */
int test_padding(void) {
    printf("\n=== Test 3: Message Padding ===\n");
    
    const char *message = "Short message";
    uint8_t padded[MSG_PADDED_SIZE];
    uint8_t unpadded[MSG_PADDED_SIZE];
    
    /* Pad */
    if (msg_pad((const uint8_t *)message, strlen(message), padded) != 0) {
        printf("%s Padding failed\n", TEST_FAIL);
        return 0;
    }
    
    printf("    Original: %zu bytes → Padded: %d bytes\n", 
           strlen(message), MSG_PADDED_SIZE);
    
    /* Unpad */
    int unpadded_len = msg_unpad(padded, MSG_PADDED_SIZE, unpadded);
    if (unpadded_len < 0) {
        printf("%s Unpadding failed\n", TEST_FAIL);
        return 0;
    }
    
    if (unpadded_len != (int)strlen(message)) {
        printf("%s Length mismatch: %d vs %zu\n", TEST_FAIL,
               unpadded_len, strlen(message));
        return 0;
    }
    
    if (memcmp(unpadded, message, unpadded_len) != 0) {
        printf("%s Content mismatch after unpadding\n", TEST_FAIL);
        return 0;
    }
    
    printf("%s Padding/unpadding works correctly\n", TEST_PASS);
    return 1;
}

/* Test 4: HKDF Determinism */
int test_hkdf(void) {
    printf("\n=== Test 4: HKDF Determinism ===\n");
    
    uint8_t input[32];
    uint8_t salt[16];
    uint8_t output1[64];
    uint8_t output2[64];
    
    RAND_bytes(input, sizeof(input));
    RAND_bytes(salt, sizeof(salt));
    
    /* Derive twice with same inputs */
    if (hkdf_sha256(input, sizeof(input), salt, sizeof(salt),
                    (const uint8_t *)"test", 4, output1, sizeof(output1)) != 0) {
        printf("%s HKDF call 1 failed\n", TEST_FAIL);
        return 0;
    }
    
    if (hkdf_sha256(input, sizeof(input), salt, sizeof(salt),
                    (const uint8_t *)"test", 4, output2, sizeof(output2)) != 0) {
        printf("%s HKDF call 2 failed\n", TEST_FAIL);
        return 0;
    }
    
    /* Verify outputs match */
    if (memcmp(output1, output2, sizeof(output1)) != 0) {
        printf("%s HKDF outputs don't match\n", TEST_FAIL);
        return 0;
    }
    
    printf("%s HKDF produces deterministic output\n", TEST_PASS);
    return 1;
}

/* Test 5: DH Key Exchange */
int test_dh_exchange(void) {
    printf("\n=== Test 5: DH Key Exchange ===\n");
    
    /* Generate two keypairs */
    EVP_PKEY *alice_key = dh_generate_keypair();
    EVP_PKEY *bob_key = dh_generate_keypair();
    
    if (!alice_key || !bob_key) {
        printf("%s DH key generation failed\n", TEST_FAIL);
        if (alice_key) EVP_PKEY_free(alice_key);
        if (bob_key) EVP_PKEY_free(bob_key);
        return 0;
    }
    
    /* Compute shared secrets */
    uint8_t alice_shared[32];
    uint8_t bob_shared[32];
    size_t alice_shared_len = sizeof(alice_shared);
    size_t bob_shared_len = sizeof(bob_shared);
    
    if (dh_compute_shared_secret(alice_key, bob_key, alice_shared, &alice_shared_len) != 0) {
        printf("%s Alice shared secret computation failed\n", TEST_FAIL);
        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
        return 0;
    }
    
    if (dh_compute_shared_secret(bob_key, alice_key, bob_shared, &bob_shared_len) != 0) {
        printf("%s Bob shared secret computation failed\n", TEST_FAIL);
        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
        return 0;
    }
    
    /* Verify shared secrets match */
    if (memcmp(alice_shared, bob_shared, 32) != 0) {
        printf("%s Shared secrets don't match\n", TEST_FAIL);
        EVP_PKEY_free(alice_key);
        EVP_PKEY_free(bob_key);
        return 0;
    }
    
    EVP_PKEY_free(alice_key);
    EVP_PKEY_free(bob_key);
    
    printf("%s DH key exchange successful\n", TEST_PASS);
    return 1;
}

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║       Cryptography Test Suite                 ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    
    /* Initialize OpenSSL */
    if (!OPENSSL_init_ssl(0, NULL)) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }
    
    /* Run tests */
    if (test_rsa_sign_verify()) tests_passed++; else tests_failed++;
    if (test_aes_encrypt_decrypt()) tests_passed++; else tests_failed++;
    if (test_padding()) tests_passed++; else tests_failed++;
    if (test_hkdf()) tests_passed++; else tests_failed++;
    if (test_dh_exchange()) tests_passed++; else tests_failed++;
    
    /* Summary */
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║              Test Summary                    ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Passed: %2d                                  ║\n", tests_passed);
    printf("║  Failed: %2d                                  ║\n", tests_failed);
    printf("╚══════════════════════════════════════════════╝\n");
    printf("\n");
    
    return (tests_failed == 0) ? 0 : 1;
}
