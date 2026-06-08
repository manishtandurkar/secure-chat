#ifndef RATCHET_H
#define RATCHET_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "common.h"

typedef struct {
    uint8_t   root_key[RATCHET_KEY_LEN];
    uint8_t   send_chain_key[RATCHET_KEY_LEN];
    uint8_t   recv_chain_key[RATCHET_KEY_LEN];
    EVP_PKEY *dh_keypair;
    EVP_PKEY *peer_dh_pubkey;
    uint32_t  send_counter;
    uint32_t  recv_counter;
    uint32_t  prev_send_counter;
} RatchetState;

int  ratchet_init(RatchetState *state,
                  const uint8_t *shared_secret, size_t secret_len,
                  int is_initiator);

int  ratchet_send_step(RatchetState *state, uint8_t *msg_key_out);
int  ratchet_recv_step(RatchetState *state, uint8_t *msg_key_out);
int  ratchet_dh_step(RatchetState *state, EVP_PKEY *peer_new_pubkey);

int  ratchet_serialize(const RatchetState *state, uint8_t *buf, size_t buf_len);
int  ratchet_deserialize(RatchetState *state, const uint8_t *buf, size_t buf_len);

void ratchet_destroy(RatchetState *state);

/* Get DH public key bytes for sending to peer */
int  ratchet_get_dh_pubkey_bytes(const RatchetState *state,
                                  uint8_t *buf, size_t buf_len, size_t *out_len);

/* Create EVP_PKEY from raw public key bytes */
EVP_PKEY *ratchet_pubkey_from_bytes(const uint8_t *buf, size_t len);

#endif /* RATCHET_H */
