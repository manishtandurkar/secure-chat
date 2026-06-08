#include <stdio.h>
#include <assert.h>
#include "intrusion.h"
#include "adaptive_engine.h"
#include "common.h"

static int test_block_on_threshold(void) {
    ids_init();
    Metrics metrics = {0};

    for (int i = 0; i < AUTH_FAIL_THRESHOLD; i++) {
        ids_record_auth_fail("192.0.2.1", &metrics);
    }

    assert(ids_is_blocked("192.0.2.1") == 1);
    assert(metrics.auth_fail_count == AUTH_FAIL_THRESHOLD);

    printf("[PASS] IDS blocks IP after %d auth failures\n", AUTH_FAIL_THRESHOLD);
    return 0;
}

static int test_replay_record(void) {
    ids_init();
    Metrics metrics = {0};

    for (int i = 0; i < REPLAY_THRESHOLD; i++)
        ids_record_replay("192.0.2.2", &metrics);

    assert(metrics.replay_count == REPLAY_THRESHOLD);
    printf("[PASS] IDS replay counter\n");
    return 0;
}

int main(void) {
    printf("=== test_ids ===\n");
    test_block_on_threshold();
    test_replay_record();
    printf("All IDS tests passed.\n");
    return 0;
}
