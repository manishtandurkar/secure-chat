#include "prekey.h"
#include "crypto.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/rand.h>

int prekey_generate_bundle(PreKeyBundle *bundle,
                           EVP_PKEY **identity_key_out,
                           EVP_PKEY **dh_identity_key_out,
                           EVP_PKEY **signed_prekey_out,
                           EVP_PKEY ***otpk_keys_out) {
    if (!bundle || !identity_key_out || !dh_identity_key_out || !signed_prekey_out || !otpk_keys_out) {
        return ERROR_CRYPTO;
    }

    memset(bundle, 0, sizeof(PreKeyBundle));

    /* 1. Generate Ed25519 Identity Key */
    EVP_PKEY *id_key = ed25519_generate_keypair();
    if (!id_key) return ERROR_CRYPTO;
    *identity_key_out = id_key;

    /* Extract raw public Ed25519 identity key */
    size_t id_pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(id_key, bundle->identity_pub, &id_pub_len) != 1 || id_pub_len != 32) {
        return ERROR_CRYPTO;
    }

    /* 2. Generate X25519 DH Identity Key */
    EVP_PKEY *dh_id_key = dh_generate_keypair();
    if (!dh_id_key) return ERROR_CRYPTO;
    *dh_identity_key_out = dh_id_key;

    /* Extract raw public X25519 DH identity key */
    size_t dh_id_pub_len = 32;
    if (dh_get_public_key(dh_id_key, bundle->dh_identity_pub, &dh_id_pub_len) != SUCCESS) {
        return ERROR_CRYPTO;
    }

    /* 3. Generate X25519 Signed PreKey */
    EVP_PKEY *spk_key = dh_generate_keypair();
    if (!spk_key) return ERROR_CRYPTO;
    *signed_prekey_out = spk_key;

    /* Extract raw public X25519 signed prekey */
    size_t spk_pub_len = 32;
    if (dh_get_public_key(spk_key, bundle->signed_prekey_pub, &spk_pub_len) != SUCCESS) {
        return ERROR_CRYPTO;
    }

    /* 4. Sign the raw X25519 Signed PreKey using Ed25519 Identity Key */
    size_t sig_len = 64;
    if (ed25519_sign(id_key, bundle->signed_prekey_pub, 32, bundle->signed_prekey_sig, &sig_len) != SUCCESS || sig_len != 64) {
        return ERROR_CRYPTO;
    }

    /* 5. Generate 50 One-Time PreKeys */
    EVP_PKEY **otpk_keys = malloc(sizeof(EVP_PKEY *) * OTPK_COUNT);
    if (!otpk_keys) return ERROR_MEMORY;

    for (int i = 0; i < OTPK_COUNT; i++) {
        EVP_PKEY *otpk = dh_generate_keypair();
        if (!otpk) {
            for (int j = 0; j < i; j++) {
                EVP_PKEY_free(otpk_keys[j]);
            }
            free(otpk_keys);
            return ERROR_CRYPTO;
        }
        otpk_keys[i] = otpk;

        size_t otpk_pub_len = 32;
        if (dh_get_public_key(otpk, bundle->otpk_pub[i], &otpk_pub_len) != SUCCESS) {
            for (int j = 0; j <= i; j++) {
                EVP_PKEY_free(otpk_keys[j]);
            }
            free(otpk_keys);
            return ERROR_CRYPTO;
        }
    }

    bundle->otpk_count = OTPK_COUNT;
    *otpk_keys_out = otpk_keys;

    return SUCCESS;
}

int prekey_compute_x3dh_initiator(EVP_PKEY *alice_identity_key,
                                  EVP_PKEY *alice_dh_identity_key,
                                  EVP_PKEY *alice_ephemeral_key,
                                  const PreKeyBundle *bob_bundle,
                                  int use_otpk,
                                  uint8_t *secret_out) {
    if (!alice_identity_key || !alice_dh_identity_key || !alice_ephemeral_key || !bob_bundle || !secret_out) {
        return ERROR_CRYPTO;
    }

    /* 1. Verify Bob's Signed PreKey Signature using Bob's Identity Key */
    EVP_PKEY *bob_id_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, bob_bundle->identity_pub, 32);
    if (!bob_id_pub) return ERROR_CRYPTO;

    if (ed25519_verify(bob_id_pub, bob_bundle->signed_prekey_pub, 32, bob_bundle->signed_prekey_sig, 64) != SUCCESS) {
        EVP_PKEY_free(bob_id_pub);
        return ERROR_CRYPTO; /* Signature verification failed! */
    }
    EVP_PKEY_free(bob_id_pub);

    /* 2. Reconstruct Bob's Public Keys */
    EVP_PKEY *bob_dh_id_pub = dh_pubkey_from_bytes(bob_bundle->dh_identity_pub, 32);
    EVP_PKEY *bob_spk_pub = dh_pubkey_from_bytes(bob_bundle->signed_prekey_pub, 32);
    if (!bob_dh_id_pub || !bob_spk_pub) {
        if (bob_dh_id_pub) EVP_PKEY_free(bob_dh_id_pub);
        if (bob_spk_pub) EVP_PKEY_free(bob_spk_pub);
        return ERROR_CRYPTO;
    }

    /* 3. Compute agreements */
    uint8_t dh1[32], dh2[32], dh3[32], dh4[32];
    size_t dh1_len = 32, dh2_len = 32, dh3_len = 32, dh4_len = 32;

    /* DH1 = Alice Ephemeral + Bob DH Identity */
    if (dh_compute_shared_secret(alice_ephemeral_key, bob_dh_id_pub, dh1, &dh1_len) != SUCCESS) goto err;

    /* DH2 = Alice DH Identity + Bob Signed PreKey */
    if (dh_compute_shared_secret(alice_dh_identity_key, bob_spk_pub, dh2, &dh2_len) != SUCCESS) goto err;

    /* DH3 = Alice Ephemeral + Bob Signed PreKey */
    if (dh_compute_shared_secret(alice_ephemeral_key, bob_spk_pub, dh3, &dh3_len) != SUCCESS) goto err;

    /* DH4 = Alice Ephemeral + Bob OTPK (if applicable) */
    EVP_PKEY *bob_otpk_pub = NULL;
    int concat_len = 92;
    if (use_otpk && bob_bundle->otpk_count > 0) {
        bob_otpk_pub = dh_pubkey_from_bytes(bob_bundle->otpk_pub[0], 32);
        if (!bob_otpk_pub) goto err;
        if (dh_compute_shared_secret(alice_ephemeral_key, bob_otpk_pub, dh4, &dh4_len) != SUCCESS) {
            EVP_PKEY_free(bob_otpk_pub);
            goto err;
        }
        EVP_PKEY_free(bob_otpk_pub);
        concat_len = 128;
    }

    /* 4. Concatenate and pass to HKDF */
    uint8_t input_material[128];
    memcpy(input_material, dh1, 32);
    memcpy(input_material + 32, dh2, 32);
    memcpy(input_material + 64, dh3, 32);
    if (concat_len == 128) {
        memcpy(input_material + 96, dh4, 32);
    }

    const uint8_t salt[32] = {0}; /* Empty salt */
    if (hkdf_sha256(salt, 32, input_material, concat_len, (const uint8_t *)"X3DHSharedSecret", 16, secret_out, 32) != SUCCESS) {
        OPENSSL_cleanse(input_material, sizeof(input_material));
        goto err;
    }

    OPENSSL_cleanse(input_material, sizeof(input_material));
    EVP_PKEY_free(bob_dh_id_pub);
    EVP_PKEY_free(bob_spk_pub);
    return SUCCESS;

err:
    EVP_PKEY_free(bob_dh_id_pub);
    EVP_PKEY_free(bob_spk_pub);
    return ERROR_CRYPTO;
}

int prekey_compute_x3dh_responder(EVP_PKEY *bob_identity_key,
                                  EVP_PKEY *bob_dh_identity_key,
                                  EVP_PKEY *bob_signed_prekey,
                                  EVP_PKEY *bob_otpk,
                                  const uint8_t *alice_dh_identity_pub,
                                  const uint8_t *alice_ephemeral_pub,
                                  uint8_t *secret_out) {
    if (!bob_identity_key || !bob_dh_identity_key || !bob_signed_prekey || !alice_dh_identity_pub || !alice_ephemeral_pub || !secret_out) {
        return ERROR_CRYPTO;
    }

    EVP_PKEY *alice_dh_id_pub = dh_pubkey_from_bytes(alice_dh_identity_pub, 32);
    EVP_PKEY *alice_ephem_pub = dh_pubkey_from_bytes(alice_ephemeral_pub, 32);
    if (!alice_dh_id_pub || !alice_ephem_pub) {
        if (alice_dh_id_pub) EVP_PKEY_free(alice_dh_id_pub);
        if (alice_ephem_pub) EVP_PKEY_free(alice_ephem_pub);
        return ERROR_CRYPTO;
    }

    /* DH1 = Alice Ephemeral + Bob DH Identity (computed as Bob DH Identity Priv + Alice Ephemeral Pub) */
    uint8_t dh1[32], dh2[32], dh3[32], dh4[32];
    size_t dh1_len = 32, dh2_len = 32, dh3_len = 32, dh4_len = 32;

    if (dh_compute_shared_secret(bob_dh_identity_key, alice_ephem_pub, dh1, &dh1_len) != SUCCESS) goto err;

    /* DH2 = Alice DH Identity + Bob Signed PreKey (computed as Bob Signed PreKey Priv + Alice DH Identity Pub) */
    if (dh_compute_shared_secret(bob_signed_prekey, alice_dh_id_pub, dh2, &dh2_len) != SUCCESS) goto err;

    /* DH3 = Alice Ephemeral + Bob Signed PreKey (computed as Bob Signed PreKey Priv + Alice Ephemeral Pub) */
    if (dh_compute_shared_secret(bob_signed_prekey, alice_ephem_pub, dh3, &dh3_len) != SUCCESS) goto err;

    /* DH4 = Alice Ephemeral + Bob OTPK (computed as Bob OTPK Priv + Alice Ephemeral Pub) */
    int concat_len = 96;
    if (bob_otpk) {
        if (dh_compute_shared_secret(bob_otpk, alice_ephem_pub, dh4, &dh4_len) != SUCCESS) goto err;
        concat_len = 128;
    }

    /* Concatenate and HKDF */
    uint8_t input_material[128];
    memcpy(input_material, dh1, 32);
    memcpy(input_material + 32, dh2, 32);
    memcpy(input_material + 64, dh3, 32);
    if (concat_len == 128) {
        memcpy(input_material + 96, dh4, 32);
    }

    const uint8_t salt[32] = {0}; /* Empty salt */
    if (hkdf_sha256(salt, 32, input_material, concat_len, (const uint8_t *)"X3DHSharedSecret", 16, secret_out, 32) != SUCCESS) {
        OPENSSL_cleanse(input_material, sizeof(input_material));
        goto err;
    }

    OPENSSL_cleanse(input_material, sizeof(input_material));
    EVP_PKEY_free(alice_dh_id_pub);
    EVP_PKEY_free(alice_ephem_pub);
    return SUCCESS;

err:
    EVP_PKEY_free(alice_dh_id_pub);
    EVP_PKEY_free(alice_ephem_pub);
    return ERROR_CRYPTO;
}
