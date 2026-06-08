#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "ratchet.h"
#include "crypto.h"
#include "common.h"

static int test_ratchet_key_uniqueness(void) {
    /* Simulate a DH handshake */
    EVP_PKEY *alice_dh = dh_generate_keypair();
    EVP_PKEY *bob_dh   = dh_generate_keypair();
    assert(alice_dh && bob_dh);

    uint8_t alice_pub[32], bob_pub[32];
    size_t  alice_pub_len = 32, bob_pub_len = 32;
    EVP_PKEY_get_raw_public_key(alice_dh, alice_pub, &alice_pub_len);
    EVP_PKEY_get_raw_public_key(bob_dh,   bob_pub,   &bob_pub_len);

    uint8_t shared_a[64], shared_b[64];
    size_t  shared_a_len = sizeof(shared_a), shared_b_len = sizeof(shared_b);
    assert(dh_compute_shared_secret(alice_dh, bob_dh, shared_a, &shared_a_len) == 0);

    /* For X25519, we need the peer's pubkey as EVP_PKEY */
    EVP_PKEY *alice_pub_key = ratchet_pubkey_from_bytes(alice_pub, alice_pub_len);
    assert(dh_compute_shared_secret(bob_dh, alice_pub_key, shared_b, &shared_b_len) == 0);
    EVP_PKEY_free(alice_pub_key);

    assert(shared_a_len == shared_b_len);
    assert(memcmp(shared_a, shared_b, shared_a_len) == 0);

    RatchetState alice, bob;
    assert(ratchet_init(&alice, shared_a, shared_a_len, 1) == 0);
    assert(ratchet_init(&bob,   shared_b, shared_b_len, 0) == 0);

    /* Derive 100 message keys and verify all unique */
    uint8_t keys_a[100][RATCHET_KEY_LEN];
    uint8_t keys_b[100][RATCHET_KEY_LEN];

    for (int i = 0; i < 100; i++) {
        assert(ratchet_send_step(&alice, keys_a[i]) == 0);
        assert(ratchet_recv_step(&bob,   keys_b[i]) == 0);
        /* Alice's send key should match Bob's recv key */
        assert(memcmp(keys_a[i], keys_b[i], RATCHET_KEY_LEN) == 0);
    }

    /* Verify all keys unique */
    for (int i = 0; i < 100; i++)
        for (int j = i + 1; j < 100; j++)
            assert(memcmp(keys_a[i], keys_a[j], RATCHET_KEY_LEN) != 0);

    ratchet_destroy(&alice);
    ratchet_destroy(&bob);
    EVP_PKEY_free(alice_dh);
    EVP_PKEY_free(bob_dh);

    printf("[PASS] Ratchet key uniqueness (100 keys, all distinct, send==recv)\n");
    return 0;
}

static int test_ratchet_serialize(void) {
    uint8_t shared[32];
    assert(random_bytes(shared, sizeof(shared)) == 0);

    RatchetState state;
    assert(ratchet_init(&state, shared, sizeof(shared), 1) == 0);

    /* Step a few times */
    uint8_t key[RATCHET_KEY_LEN];
    for (int i = 0; i < 5; i++) ratchet_send_step(&state, key);

    uint8_t buf[512];
    int n = ratchet_serialize(&state, buf, sizeof(buf));
    assert(n > 0);

    RatchetState state2;
    assert(ratchet_deserialize(&state2, buf, (size_t)n) == 0);

    /* Chain keys should match */
    assert(memcmp(state.send_chain_key, state2.send_chain_key, RATCHET_KEY_LEN) == 0);
    assert(memcmp(state.root_key,       state2.root_key,       RATCHET_KEY_LEN) == 0);

    ratchet_destroy(&state);
    ratchet_destroy(&state2);

    printf("[PASS] Ratchet serialize/deserialize\n");
    return 0;
}

int main(void) {
    printf("=== test_ratchet ===\n");
    test_ratchet_key_uniqueness();
    test_ratchet_serialize();
    printf("All ratchet tests passed.\n");
    return 0;
}
