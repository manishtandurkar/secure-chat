/**
 * Crypto Tests - Validate Ed25519, AES-GCM, HKDF, X3DH operations
 */

#include "../include/crypto.h"
#include "../include/common.h"
#include "../include/prekey.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

int tests_passed = 0;
int tests_failed = 0;

/* Test 1: Ed25519 Sign/Verify Round-Trip */
int test_ed25519_sign_verify(void) {
    printf("\n=== Test 1: Ed25519 Sign/Verify ===\n");
    
    EVP_PKEY *keypair = ed25519_generate_keypair();
    if (!keypair) {
        printf("%s Failed to generate Ed25519 keypair\n", TEST_FAIL);
        return 0;
    }
    
    /* Test data */
    const char *message = "Hello, World!";
    uint8_t signature[64];
    size_t sig_len = sizeof(signature);
    
    /* Sign */
    if (ed25519_sign(keypair, (const uint8_t *)message, strlen(message), 
                     signature, &sig_len) != SUCCESS) {
        printf("%s Ed25519 sign failed\n", TEST_FAIL);
        EVP_PKEY_free(keypair);
        return 0;
    }
    
    printf("    Signature length: %zu bytes (should be 64)\n", sig_len);
    
    /* Verify */
    if (ed25519_verify(keypair, (const uint8_t *)message, strlen(message),
                       signature, sig_len) != SUCCESS) {
        printf("%s Ed25519 verify failed\n", TEST_FAIL);
        EVP_PKEY_free(keypair);
        return 0;
    }
    
    /* Tamper with signature */
    signature[0] ^= 0xFF;
    if (ed25519_verify(keypair, (const uint8_t *)message, strlen(message),
                       signature, sig_len) == SUCCESS) {
        printf("%s Ed25519 verify accepted tampered signature\n", TEST_FAIL);
        EVP_PKEY_free(keypair);
        return 0;
    }
    
    EVP_PKEY_free(keypair);
    printf("%s Ed25519 sign/verify works correctly\n", TEST_PASS);
    return 1;
}

/* Test 2: AES GCM Encrypt/Decrypt Round-Trip */
int test_aes_encrypt_decrypt(void) {
    printf("\n=== Test 2: AES-256-GCM Encrypt/Decrypt ===\n");
    
    uint8_t key[AES_KEY_LEN];
    uint8_t iv[12];
    uint8_t tag[16];
    RAND_bytes(key, sizeof(key));
    aes_generate_iv(iv);
    
    const char *plaintext = "This is a secret E2EE message!";
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    
    /* Encrypt */
    int ct_len = aes_encrypt(key, iv, (const uint8_t *)plaintext, 
                             (int)strlen(plaintext), ciphertext, tag);
    if (ct_len < 0) {
        printf("%s AES-GCM encrypt failed\n", TEST_FAIL);
        return 0;
    }
    
    printf("    Plaintext:  %zu bytes\n", strlen(plaintext));
    printf("    Ciphertext: %d bytes\n", ct_len);
    printf("    GCM Tag:    16 bytes\n");
    
    /* Decrypt */
    int pt_len = aes_decrypt(key, iv, ciphertext, ct_len, tag, decrypted);
    if (pt_len < 0) {
        printf("%s AES-GCM decrypt failed\n", TEST_FAIL);
        return 0;
    }
    
    decrypted[pt_len] = '\0';
    
    /* Verify */
    if (strcmp((char *)decrypted, plaintext) != 0) {
        printf("%s Decrypted text doesn't match original\n", TEST_FAIL);
        return 0;
    }
    
    /* Tamper with tag */
    tag[0] ^= 0xFF;
    if (aes_decrypt(key, iv, ciphertext, ct_len, tag, decrypted) >= 0) {
        printf("%s Decrypted text verified successfully with corrupted tag!\n", TEST_FAIL);
        return 0;
    }
    
    printf("%s AES-GCM round-trip successful\n", TEST_PASS);
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
    
    /* Unpad */
    int unpadded_len = msg_unpad(padded, MSG_PADDED_SIZE, unpadded);
    if (unpadded_len < 0) {
        printf("%s Unpadding failed\n", TEST_FAIL);
        return 0;
    }
    
    if (unpadded_len != (int)strlen(message)) {
        printf("%s Length mismatch\n", TEST_FAIL);
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
    if (hkdf_sha256(salt, sizeof(salt), input, sizeof(input),
                    (const uint8_t *)"test", 4, output1, sizeof(output1)) != 0) {
        printf("%s HKDF call 1 failed\n", TEST_FAIL);
        return 0;
    }
    
    if (hkdf_sha256(salt, sizeof(salt), input, sizeof(input),
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

/* Test 5: X3DH Key Agreement */
int test_x3dh_agreement(void) {
    printf("\n=== Test 5: X3DH PreKey Exchange ===\n");
    
    PreKeyBundle bob_bundle;
    EVP_PKEY *bob_id_key = NULL;
    EVP_PKEY *bob_dh_id_key = NULL;
    EVP_PKEY *bob_spk_key = NULL;
    EVP_PKEY **bob_otpk_keys = NULL;
    
    /* Generate Bob's PreKey Bundle */
    if (prekey_generate_bundle(&bob_bundle, &bob_id_key, &bob_dh_id_key, &bob_spk_key, &bob_otpk_keys) != SUCCESS) {
        printf("%s Bob PreKey generation failed\n", TEST_FAIL);
        return 0;
    }
    
    /* Alice (Initiator) generates Identity and Ephemeral Keypairs */
    EVP_PKEY *alice_id_key = ed25519_generate_keypair();
    EVP_PKEY *alice_dh_id_key = dh_generate_keypair();
    EVP_PKEY *alice_ephem_key = dh_generate_keypair();
    
    if (!alice_id_key || !alice_dh_id_key || !alice_ephem_key) {
        printf("%s Alice key generation failed\n", TEST_FAIL);
        goto cleanup;
    }
    
    /* Export Alice's raw public keys for Bob */
    uint8_t alice_dh_id_pub[32];
    uint8_t alice_ephem_pub[32];
    size_t pub_len = 32;
    dh_get_public_key(alice_dh_id_key, alice_dh_id_pub, &pub_len);
    dh_get_public_key(alice_ephem_key, alice_ephem_pub, &pub_len);
    
    /* 1. Alice derives secret */
    uint8_t alice_secret[32];
    if (prekey_compute_x3dh_initiator(alice_id_key, alice_dh_id_key, alice_ephem_key, &bob_bundle, 1, alice_secret) != SUCCESS) {
        printf("%s Alice X3DH derivation failed\n", TEST_FAIL);
        goto cleanup;
    }
    
    /* 2. Bob derives secret */
    uint8_t bob_secret[32];
    if (prekey_compute_x3dh_responder(bob_id_key, bob_dh_id_key, bob_spk_key, bob_otpk_keys[0],
                                      alice_dh_id_pub, alice_ephem_pub, bob_secret) != SUCCESS) {
        printf("%s Bob X3DH derivation failed\n", TEST_FAIL);
        goto cleanup;
    }
    
    /* 3. Verify secrets match */
    if (memcmp(alice_secret, bob_secret, 32) != 0) {
        printf("%s Derived shared secrets do not match!\n", TEST_FAIL);
        goto cleanup;
    }
    
    printf("%s X3DH Session Bootstrap successful (Derived secrets match)\n", TEST_PASS);
    
    /* Cleanup */
    EVP_PKEY_free(alice_id_key);
    EVP_PKEY_free(alice_dh_id_key);
    EVP_PKEY_free(alice_ephem_key);
    EVP_PKEY_free(bob_id_key);
    EVP_PKEY_free(bob_dh_id_key);
    EVP_PKEY_free(bob_spk_key);
    for (int i = 0; i < OTPK_COUNT; i++) EVP_PKEY_free(bob_otpk_keys[i]);
    free(bob_otpk_keys);
    return 1;

cleanup:
    if (alice_id_key) EVP_PKEY_free(alice_id_key);
    if (alice_dh_id_key) EVP_PKEY_free(alice_dh_id_key);
    if (alice_ephem_key) EVP_PKEY_free(alice_ephem_key);
    if (bob_id_key) EVP_PKEY_free(bob_id_key);
    if (bob_dh_id_key) EVP_PKEY_free(bob_dh_id_key);
    if (bob_spk_key) EVP_PKEY_free(bob_spk_key);
    if (bob_otpk_keys) {
        for (int i = 0; i < OTPK_COUNT; i++) {
            if (bob_otpk_keys[i]) EVP_PKEY_free(bob_otpk_keys[i]);
        }
        free(bob_otpk_keys);
    }
    return 0;
}

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║       Cryptography Test Suite (E2EE Upgrade) ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    
    /* Initialize OpenSSL */
    if (!OPENSSL_init_ssl(0, NULL)) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }
    
    /* Run tests */
    if (test_ed25519_sign_verify()) tests_passed++; else tests_failed++;
    if (test_aes_encrypt_decrypt()) tests_passed++; else tests_failed++;
    if (test_padding()) tests_passed++; else tests_failed++;
    if (test_hkdf()) tests_passed++; else tests_failed++;
    if (test_x3dh_agreement()) tests_passed++; else tests_failed++;
    
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
