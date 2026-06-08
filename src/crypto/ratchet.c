#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "ratchet.h"
#include "crypto.h"
#include "common.h"

int ratchet_init(RatchetState *state,
                 const uint8_t *shared_secret, size_t secret_len,
                 int is_initiator) {
    memset(state, 0, sizeof(*state));

    static const uint8_t info_root[] = "ratchet_root_init";
    static const uint8_t info_send[] = "ratchet_send_init";
    static const uint8_t info_recv[] = "ratchet_recv_init";

    uint8_t zero_salt[RATCHET_KEY_LEN] = {0};

    if (hkdf_derive(zero_salt, RATCHET_KEY_LEN,
                    shared_secret, secret_len,
                    info_root, sizeof(info_root) - 1,
                    state->root_key, RATCHET_KEY_LEN) < 0)
        return -1;

    const uint8_t *s_info = is_initiator ? info_send : info_recv;
    const uint8_t *r_info = is_initiator ? info_recv : info_send;
    size_t s_len = is_initiator ? sizeof(info_send)-1 : sizeof(info_recv)-1;
    size_t r_len = is_initiator ? sizeof(info_recv)-1 : sizeof(info_send)-1;

    if (hkdf_derive(zero_salt, RATCHET_KEY_LEN,
                    shared_secret, secret_len,
                    s_info, s_len,
                    state->send_chain_key, RATCHET_KEY_LEN) < 0)
        return -1;

    if (hkdf_derive(zero_salt, RATCHET_KEY_LEN,
                    shared_secret, secret_len,
                    r_info, r_len,
                    state->recv_chain_key, RATCHET_KEY_LEN) < 0)
        return -1;

    state->dh_keypair = dh_generate_keypair();
    if (!state->dh_keypair) return -1;

    state->send_counter = 0;
    state->recv_counter = 0;
    state->prev_send_counter = 0;

    return 0;
}

int ratchet_send_step(RatchetState *state, uint8_t *msg_key_out) {
    uint8_t new_chain_key[RATCHET_KEY_LEN];
    kdf_ck(state->send_chain_key, new_chain_key, msg_key_out);
    memcpy(state->send_chain_key, new_chain_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(new_chain_key, sizeof(new_chain_key));
    state->send_counter++;
    return 0;
}

int ratchet_recv_step(RatchetState *state, uint8_t *msg_key_out) {
    uint8_t new_chain_key[RATCHET_KEY_LEN];
    kdf_ck(state->recv_chain_key, new_chain_key, msg_key_out);
    memcpy(state->recv_chain_key, new_chain_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(new_chain_key, sizeof(new_chain_key));
    state->recv_counter++;
    return 0;
}

int ratchet_dh_step(RatchetState *state, EVP_PKEY *peer_new_pubkey) {
    if (!state->dh_keypair || !peer_new_pubkey) return -1;

    /* Update peer key */
    if (state->peer_dh_pubkey)
        EVP_PKEY_free(state->peer_dh_pubkey);
    state->peer_dh_pubkey = peer_new_pubkey;

    /* Compute DH shared secret with current keypair + new peer key */
    uint8_t dh_output[64];
    size_t  dh_len = sizeof(dh_output);
    if (dh_compute_shared_secret(state->dh_keypair, peer_new_pubkey,
                                  dh_output, &dh_len) < 0)
        return -1;

    /* Derive new root key and recv chain key */
    uint8_t new_rk[RATCHET_KEY_LEN], new_ck[RATCHET_KEY_LEN];
    kdf_rk(state->root_key, dh_output, dh_len, new_rk, new_ck);
    memcpy(state->root_key, new_rk, RATCHET_KEY_LEN);
    memcpy(state->recv_chain_key, new_ck, RATCHET_KEY_LEN);

    /* Generate new DH keypair for next step */
    EVP_PKEY_free(state->dh_keypair);
    state->dh_keypair = dh_generate_keypair();
    if (!state->dh_keypair) {
        OPENSSL_cleanse(dh_output, sizeof(dh_output));
        return -1;
    }

    /* Derive new send chain key from new keypair + same peer key */
    size_t dh_len2 = sizeof(dh_output);
    if (dh_compute_shared_secret(state->dh_keypair, peer_new_pubkey,
                                  dh_output, &dh_len2) < 0) {
        OPENSSL_cleanse(dh_output, sizeof(dh_output));
        return -1;
    }

    uint8_t new_rk2[RATCHET_KEY_LEN], new_ck2[RATCHET_KEY_LEN];
    kdf_rk(state->root_key, dh_output, dh_len2, new_rk2, new_ck2);
    memcpy(state->root_key, new_rk2, RATCHET_KEY_LEN);
    memcpy(state->send_chain_key, new_ck2, RATCHET_KEY_LEN);

    state->prev_send_counter = state->send_counter;
    state->send_counter = 0;
    state->recv_counter = 0;

    OPENSSL_cleanse(dh_output, sizeof(dh_output));
    OPENSSL_cleanse(new_rk, sizeof(new_rk));
    OPENSSL_cleanse(new_ck, sizeof(new_ck));
    OPENSSL_cleanse(new_rk2, sizeof(new_rk2));
    OPENSSL_cleanse(new_ck2, sizeof(new_ck2));

    return 0;
}

int ratchet_get_dh_pubkey_bytes(const RatchetState *state,
                                 uint8_t *buf, size_t buf_len, size_t *out_len) {
    if (!state->dh_keypair) return -1;
    *out_len = buf_len;
    if (EVP_PKEY_get_raw_public_key(state->dh_keypair, buf, out_len) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

EVP_PKEY *ratchet_pubkey_from_bytes(const uint8_t *buf, size_t len) {
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, buf, len);
}

int ratchet_serialize(const RatchetState *state, uint8_t *buf, size_t buf_len) {
    /* Format: root_key(32) + send_ck(32) + recv_ck(32) + counters(12) + pubkey(32) */
    size_t needed = RATCHET_KEY_LEN * 3 + 12 + 32;
    if (buf_len < needed) return -1;

    uint8_t *p = buf;
    memcpy(p, state->root_key, RATCHET_KEY_LEN);       p += RATCHET_KEY_LEN;
    memcpy(p, state->send_chain_key, RATCHET_KEY_LEN); p += RATCHET_KEY_LEN;
    memcpy(p, state->recv_chain_key, RATCHET_KEY_LEN); p += RATCHET_KEY_LEN;

    uint32_t sc = state->send_counter, rc = state->recv_counter, psc = state->prev_send_counter;
    memcpy(p, &sc, 4);  p += 4;
    memcpy(p, &rc, 4);  p += 4;
    memcpy(p, &psc, 4); p += 4;

    size_t pub_len = 32;
    if (state->dh_keypair) {
        if (EVP_PKEY_get_raw_public_key(state->dh_keypair, p, &pub_len) != 1)
            memset(p, 0, 32);
    } else {
        memset(p, 0, 32);
    }
    p += 32;

    return (int)(p - buf);
}

int ratchet_deserialize(RatchetState *state, const uint8_t *buf, size_t buf_len) {
    size_t needed = RATCHET_KEY_LEN * 3 + 12 + 32;
    if (buf_len < needed) return -1;

    memset(state, 0, sizeof(*state));
    const uint8_t *p = buf;

    memcpy(state->root_key, p, RATCHET_KEY_LEN);       p += RATCHET_KEY_LEN;
    memcpy(state->send_chain_key, p, RATCHET_KEY_LEN); p += RATCHET_KEY_LEN;
    memcpy(state->recv_chain_key, p, RATCHET_KEY_LEN); p += RATCHET_KEY_LEN;

    memcpy(&state->send_counter, p, 4);       p += 4;
    memcpy(&state->recv_counter, p, 4);       p += 4;
    memcpy(&state->prev_send_counter, p, 4);  p += 4;

    /* Restore DH keypair — we only stored public key, regenerate fresh */
    state->dh_keypair = dh_generate_keypair();
    state->peer_dh_pubkey = NULL;

    return 0;
}

void ratchet_destroy(RatchetState *state) {
    if (!state) return;
    OPENSSL_cleanse(state->root_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(state->send_chain_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(state->recv_chain_key, RATCHET_KEY_LEN);
    if (state->dh_keypair)    EVP_PKEY_free(state->dh_keypair);
    if (state->peer_dh_pubkey) EVP_PKEY_free(state->peer_dh_pubkey);
    memset(state, 0, sizeof(*state));
}
