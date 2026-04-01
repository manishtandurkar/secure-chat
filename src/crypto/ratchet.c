#include "ratchet.h"
#include "crypto.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Initialize ratchet from DH shared secret */
int ratchet_init(RatchetState *state,
                 const uint8_t *shared_secret, size_t secret_len,
                 int is_initiator) {
    if (!state || !shared_secret || secret_len == 0) {
        return ERROR_CRYPTO;
    }
    
    memset(state, 0, sizeof(RatchetState));
    
    /* Derive root key using HKDF from shared secret */
    uint8_t initial_material[96]; /* 32 root + 32 send chain + 32 recv chain */
    const uint8_t salt[32] = {0}; /* Empty salt for initial derivation */
    
    if (hkdf_sha256(salt, 32, shared_secret, secret_len,
                    (const uint8_t *)"DoubleRatchetInit", 17,
                    initial_material, 96) != SUCCESS) {
        return ERROR_CRYPTO;
    }
    
    /* Split derived material */
    memcpy(state->root_key, initial_material, RATCHET_KEY_LEN);
    
    /* Initiator starts with send chain, responder starts with receive chain */
    if (is_initiator) {
        memcpy(state->send_chain_key, initial_material + 32, RATCHET_KEY_LEN);
        memcpy(state->recv_chain_key, initial_material + 64, RATCHET_KEY_LEN);
    } else {
        memcpy(state->recv_chain_key, initial_material + 32, RATCHET_KEY_LEN);
        memcpy(state->send_chain_key, initial_material + 64, RATCHET_KEY_LEN);
    }
    
    /* Zero sensitive material */
    OPENSSL_cleanse(initial_material, 96);
    
    /* Generate our initial DH keypair */
    state->dh_keypair = dh_generate_keypair();
    if (!state->dh_keypair) {
        return ERROR_CRYPTO;
    }
    
    state->send_counter = 0;
    state->recv_counter = 0;
    state->prev_send_counter = 0;
    state->peer_dh_pubkey = NULL;
    
    return SUCCESS;
}

/* Derive next message key for sending */
int ratchet_send_step(RatchetState *state, uint8_t *msg_key_out) {
    if (!state || !msg_key_out) {
        return ERROR_CRYPTO;
    }
    
    uint8_t new_chain_key[RATCHET_KEY_LEN];
    
    /* Use KDF_CK to advance chain and derive message key */
    kdf_ck(state->send_chain_key, new_chain_key, msg_key_out);
    
    /* Update chain key */
    memcpy(state->send_chain_key, new_chain_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(new_chain_key, RATCHET_KEY_LEN);
    
    /* Increment counter */
    state->send_counter++;
    
    return SUCCESS;
}

/* Derive next message key for receiving */
int ratchet_recv_step(RatchetState *state, uint8_t *msg_key_out) {
    if (!state || !msg_key_out) {
        return ERROR_CRYPTO;
    }
    
    uint8_t new_chain_key[RATCHET_KEY_LEN];
    
    /* Use KDF_CK to advance chain and derive message key */
    kdf_ck(state->recv_chain_key, new_chain_key, msg_key_out);
    
    /* Update chain key */
    memcpy(state->recv_chain_key, new_chain_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(new_chain_key, RATCHET_KEY_LEN);
    
    /* Increment counter */
    state->recv_counter++;
    
    return SUCCESS;
}

/* Perform DH ratchet step */
int ratchet_dh_step(RatchetState *state, EVP_PKEY *peer_new_pubkey) {
    if (!state || !peer_new_pubkey) {
        return ERROR_CRYPTO;
    }
    
    /* Compute DH with peer's new public key and our current private key */
    uint8_t dh_output[32];
    size_t dh_len = 32;
    
    if (dh_compute_shared_secret(state->dh_keypair, peer_new_pubkey,
                                   dh_output, &dh_len) != SUCCESS) {
        return ERROR_CRYPTO;
    }
    
    /* Derive new root key and receiving chain key */
    uint8_t new_root_key[RATCHET_KEY_LEN];
    uint8_t new_recv_chain[RATCHET_KEY_LEN];
    
    kdf_rk(state->root_key, dh_output, dh_len, new_root_key, new_recv_chain);
    
    /* Update state with new receive chain */
    memcpy(state->root_key, new_root_key, RATCHET_KEY_LEN);
    memcpy(state->recv_chain_key, new_recv_chain, RATCHET_KEY_LEN);
    
    /* Update peer's public key */
    if (state->peer_dh_pubkey) {
        EVP_PKEY_free(state->peer_dh_pubkey);
    }
    state->peer_dh_pubkey = peer_new_pubkey;
    EVP_PKEY_up_ref(peer_new_pubkey); /* Increment reference count */
    
    /* Generate new DH keypair for next ratchet */
    EVP_PKEY *new_keypair = dh_generate_keypair();
    if (!new_keypair) {
        OPENSSL_cleanse(dh_output, 32);
        OPENSSL_cleanse(new_root_key, RATCHET_KEY_LEN);
        OPENSSL_cleanse(new_recv_chain, RATCHET_KEY_LEN);
        return ERROR_CRYPTO;
    }
    
    /* Compute DH with our new private key and peer's public key */
    uint8_t dh_output2[32];
    size_t dh_len2 = 32;
    
    if (dh_compute_shared_secret(new_keypair, peer_new_pubkey,
                                   dh_output2, &dh_len2) != SUCCESS) {
        EVP_PKEY_free(new_keypair);
        OPENSSL_cleanse(dh_output, 32);
        OPENSSL_cleanse(new_root_key, RATCHET_KEY_LEN);
        OPENSSL_cleanse(new_recv_chain, RATCHET_KEY_LEN);
        return ERROR_CRYPTO;
    }
    
    /* Derive new root key and sending chain key */
    uint8_t newer_root_key[RATCHET_KEY_LEN];
    uint8_t new_send_chain[RATCHET_KEY_LEN];
    
    kdf_rk(state->root_key, dh_output2, dh_len2, newer_root_key, new_send_chain);
    
    /* Update state with new send chain and root key */
    memcpy(state->root_key, newer_root_key, RATCHET_KEY_LEN);
    memcpy(state->send_chain_key, new_send_chain, RATCHET_KEY_LEN);
    
    /* Replace our keypair */
    EVP_PKEY_free(state->dh_keypair);
    state->dh_keypair = new_keypair;
    
    /* Reset counters */
    state->prev_send_counter = state->send_counter;
    state->send_counter = 0;
    state->recv_counter = 0;
    
    /* Clean up sensitive data */
    OPENSSL_cleanse(dh_output, 32);
    OPENSSL_cleanse(dh_output2, 32);
    OPENSSL_cleanse(new_root_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(new_recv_chain, RATCHET_KEY_LEN);
    OPENSSL_cleanse(newer_root_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(new_send_chain, RATCHET_KEY_LEN);
    
    return SUCCESS;
}

/* Serialize ratchet state (simplified - would need proper key serialization) */
int ratchet_serialize(const RatchetState *state, uint8_t *buf, size_t buf_len) {
    if (!state || !buf) {
        return -1;
    }
    
    /* For simplicity, serialize keys only (not EVP_PKEY structures)
       In production, would need to serialize DH keys properly */
    size_t offset = 0;
    size_t required = RATCHET_KEY_LEN * 3 + sizeof(uint32_t) * 3;
    
    if (buf_len < required) {
        return -1;
    }
    
    memcpy(buf + offset, state->root_key, RATCHET_KEY_LEN);
    offset += RATCHET_KEY_LEN;
    
    memcpy(buf + offset, state->send_chain_key, RATCHET_KEY_LEN);
    offset += RATCHET_KEY_LEN;
    
    memcpy(buf + offset, state->recv_chain_key, RATCHET_KEY_LEN);
    offset += RATCHET_KEY_LEN;
    
    memcpy(buf + offset, &state->send_counter, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(buf + offset, &state->recv_counter, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(buf + offset, &state->prev_send_counter, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    return (int)offset;
}

/* Deserialize ratchet state */
int ratchet_deserialize(RatchetState *state, const uint8_t *buf, size_t buf_len) {
    if (!state || !buf) {
        return -1;
    }
    
    size_t offset = 0;
    size_t required = RATCHET_KEY_LEN * 3 + sizeof(uint32_t) * 3;
    
    if (buf_len < required) {
        return -1;
    }
    
    memset(state, 0, sizeof(RatchetState));
    
    memcpy(state->root_key, buf + offset, RATCHET_KEY_LEN);
    offset += RATCHET_KEY_LEN;
    
    memcpy(state->send_chain_key, buf + offset, RATCHET_KEY_LEN);
    offset += RATCHET_KEY_LEN;
    
    memcpy(state->recv_chain_key, buf + offset, RATCHET_KEY_LEN);
    offset += RATCHET_KEY_LEN;
    
    memcpy(&state->send_counter, buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(&state->recv_counter, buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    memcpy(&state->prev_send_counter, buf + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    
    /* Note: DH keys would need to be regenerated or separately serialized */
    state->dh_keypair = NULL;
    state->peer_dh_pubkey = NULL;
    
    return SUCCESS;
}

/* Destroy ratchet state */
void ratchet_destroy(RatchetState *state) {
    if (!state) {
        return;
    }
    
    /* Zero all key material */
    OPENSSL_cleanse(state->root_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(state->send_chain_key, RATCHET_KEY_LEN);
    OPENSSL_cleanse(state->recv_chain_key, RATCHET_KEY_LEN);
    
    /* Free DH keys */
    if (state->dh_keypair) {
        EVP_PKEY_free(state->dh_keypair);
        state->dh_keypair = NULL;
    }
    
    if (state->peer_dh_pubkey) {
        EVP_PKEY_free(state->peer_dh_pubkey);
        state->peer_dh_pubkey = NULL;
    }
    
    /* Zero counters */
    state->send_counter = 0;
    state->recv_counter = 0;
    state->prev_send_counter = 0;
}
