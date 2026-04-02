#ifndef RATCHET_H
#define RATCHET_H

#include "common.h"
#include <openssl/evp.h>

/* Double Ratchet state structure */
typedef struct {
    uint8_t  root_key[RATCHET_KEY_LEN];       /* Updated on DH ratchet step */
    uint8_t  send_chain_key[RATCHET_KEY_LEN]; /* Advances with each sent msg */
    uint8_t  recv_chain_key[RATCHET_KEY_LEN]; /* Advances with each received msg */
    EVP_PKEY *dh_keypair;                      /* Our current ephemeral DH key */
    EVP_PKEY *peer_dh_pubkey;                  /* Peer's last known DH public key */
    uint32_t  send_counter;
    uint32_t  recv_counter;
    uint32_t  prev_send_counter;               /* For out-of-order handling */
} RatchetState;

/**
 * Initialize ratchet from DH shared secret (post-DH-handshake).
 * Derives initial root_key, send_chain_key, recv_chain_key via HKDF.
 * Returns 0 on success.
 */
int ratchet_init(RatchetState *state,
                 const uint8_t *shared_secret, size_t secret_len,
                 int is_initiator);

/**
 * Derive the next message key for sending.
 * Advances send_chain_key using HMAC-SHA256.
 * Writes 32-byte message key to msg_key_out.
 * Returns 0 on success.
 */
int ratchet_send_step(RatchetState *state, uint8_t *msg_key_out);

/**
 * Derive the next message key for receiving.
 * Advances recv_chain_key.
 * Returns 0 on success.
 */
int ratchet_recv_step(RatchetState *state, uint8_t *msg_key_out);

/**
 * Perform a DH ratchet step (called when a new DH public key is received
 * from peer). Generates new DH keypair, derives new root key and chain keys.
 * Returns 0 on success.
 */
int ratchet_dh_step(RatchetState *state, EVP_PKEY *peer_new_pubkey);

/**
 * Serialize ratchet state to buffer for persistence.
 * Returns bytes written or -1.
 */
int ratchet_serialize(const RatchetState *state, uint8_t *buf, size_t buf_len);

/**
 * Deserialize ratchet state from buffer. Returns 0 or -1.
 */
int ratchet_deserialize(RatchetState *state, const uint8_t *buf, size_t buf_len);

/**
 * Securely zero and free ratchet state.
 */
void ratchet_destroy(RatchetState *state);

#endif /* RATCHET_H */
