#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/rand.h>
#include "multipath.h"
#include "common.h"

static int test_dedup(void) {
    dedup_init();

    uint8_t id1[MSG_ID_LEN], id2[MSG_ID_LEN];
    RAND_bytes(id1, MSG_ID_LEN);
    RAND_bytes(id2, MSG_ID_LEN);

    assert(dedup_check(id1) == 0);
    dedup_add(id1);
    assert(dedup_check(id1) == 1);
    assert(dedup_check(id2) == 0);

    /* Add id2, verify id1 still found */
    dedup_add(id2);
    assert(dedup_check(id1) == 1);
    assert(dedup_check(id2) == 1);

    /* Fill ring buffer past window, earliest IDs should be evicted */
    for (int i = 0; i < DEDUP_WINDOW + 10; i++) {
        uint8_t id[MSG_ID_LEN];
        RAND_bytes(id, MSG_ID_LEN);
        dedup_add(id);
    }
    /* id1 was added long ago — should be evicted now */
    assert(dedup_check(id1) == 0);

    printf("[PASS] Dedup ring buffer (add, check, evict)\n");
    return 0;
}

int main(void) {
    printf("=== test_multipath ===\n");
    test_dedup();
    printf("All multipath tests passed.\n");
    return 0;
}
