#ifndef PREKEY_H
#define PREKEY_H

#include "common.h"
#include <openssl/evp.h>

#define OTPK_COUNT 50

typedef struct {
    uint8_t identity_pub[32];             /* Raw Ed25519 Public Identity Key (for signatures) */
    uint8_t dh_identity_pub[32];          /* Raw X25519 Public DH Identity Key (for X3DH) */
    uint8_t signed_prekey_pub[32];         /* Raw X25519 Public Signed PreKey */
    uint8_t signed_prekey_sig[64];         /* Ed25519 Signature of Signed PreKey */
    uint32_t otpk_count;                   /* Available One-Time PreKeys */
    uint8_t otpk_pub[OTPK_COUNT][32];      /* Raw X25519 One-Time PreKeys */
} PreKeyBundle;

/**
 * Generate a complete PreKey Bundle for a client.
 * Generates an Ed25519 Identity Key, X25519 DH Identity Key, X25519 Signed PreKey, Ed25519 Signature, and OTPKs.
 * Outputs are written to bundle_out, and the private keys are exported/returned.
 * Returns 0 on success.
 */
int prekey_generate_bundle(PreKeyBundle *bundle_out,
                           EVP_PKEY **identity_key_out,
                           EVP_PKEY **dh_identity_key_out,
                           EVP_PKEY **signed_prekey_out,
                           EVP_PKEY ***otpk_keys_out);

/**
 * Compute the X3DH shared secret as the initiator (Client A).
 * Performs ECDH key agreements:
 *   DH1 = Bob's DH Identity Pub + Alice's Ephemeral Priv
 *   DH2 = Bob's Signed PreKey Pub + Alice's DH Identity Priv
 *   DH3 = Bob's Signed PreKey Pub + Alice's Ephemeral Priv
 *   DH4 = Bob's OTPK Pub + Alice's Ephemeral Priv (if OTPK present)
 * Concatenates outputs and runs HKDF-SHA256.
 * Returns 0 on success, writes 32-byte secret to secret_out.
 */
int prekey_compute_x3dh_initiator(EVP_PKEY *alice_identity_key,
                                  EVP_PKEY *alice_dh_identity_key,
                                  EVP_PKEY *alice_ephemeral_key,
                                  const PreKeyBundle *bob_bundle,
                                  int use_otpk,
                                  uint8_t *secret_out);

/**
 * Compute the X3DH shared secret as the responder (Client B).
 * Uses their own private identity, DH identity, signed prekey, and optional OTPK to derive
 * the matching shared secret from Alice's public keys.
 * Returns 0 on success, writes 32-byte secret to secret_out.
 */
int prekey_compute_x3dh_responder(EVP_PKEY *bob_identity_key,
                                  EVP_PKEY *bob_dh_identity_key,
                                  EVP_PKEY *bob_signed_prekey,
                                  EVP_PKEY *bob_otpk,
                                  const uint8_t *alice_dh_identity_pub,
                                  const uint8_t *alice_ephemeral_pub,
                                  uint8_t *secret_out);

#endif /* PREKEY_H */
