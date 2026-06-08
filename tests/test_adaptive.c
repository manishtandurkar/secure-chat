#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "adaptive_engine.h"
#include "common.h"

static int test_mode_transitions(void) {
    EngineState state;
    Metrics     metrics = {0};

    engine_apply_mode(&state, MODE_NORMAL);
    assert(state.mode == MODE_NORMAL);
    assert(state.force_padding == 0);
    assert(state.dh_ratchet_freq == 10);

    /* Inject 25% packet loss → should go UNSTABLE */
    metrics.packet_loss_rate = 0.25f;
    engine_evaluate(&state, &metrics);
    assert(state.mode == MODE_HIGH_RISK);  /* 25% > 20% threshold → HIGH_RISK */
    assert(state.force_padding == 1);
    assert(state.dh_ratchet_freq == 1);

    /* Reset */
    engine_apply_mode(&state, MODE_NORMAL);
    metrics.packet_loss_rate = 0.07f;  /* 7% → UNSTABLE */
    engine_evaluate(&state, &metrics);
    assert(state.mode == MODE_UNSTABLE);
    assert(state.force_padding == 0);
    assert(state.max_retries == 7);

    /* Auth fails → HIGH_RISK */
    engine_apply_mode(&state, MODE_NORMAL);
    memset(&metrics, 0, sizeof(metrics));
    metrics.auth_fail_count = AUTH_FAIL_THRESHOLD;
    engine_evaluate(&state, &metrics);
    assert(state.mode == MODE_HIGH_RISK);

    /* Replay → HIGH_RISK */
    engine_apply_mode(&state, MODE_NORMAL);
    memset(&metrics, 0, sizeof(metrics));
    metrics.replay_count = REPLAY_THRESHOLD;
    engine_evaluate(&state, &metrics);
    assert(state.mode == MODE_HIGH_RISK);

    printf("[PASS] Adaptive engine mode transitions\n");
    return 0;
}

static int test_engine_config(void) {
    EngineState state;
    engine_apply_mode(&state, MODE_NORMAL);
    assert(state.max_retries == 3);
    assert(state.retry_delay_ms == 100);
    assert(state.chunk_size == MAX_MSG_LEN);

    engine_apply_mode(&state, MODE_UNSTABLE);
    assert(state.max_retries == 7);
    assert(state.chunk_size == 512);

    engine_apply_mode(&state, MODE_HIGH_RISK);
    assert(state.max_retries == 10);
    assert(state.force_padding == 1);
    assert(state.random_delay == 1);
    assert(state.dh_ratchet_freq == 1);

    printf("[PASS] Engine mode config values\n");
    return 0;
}

int main(void) {
    printf("=== test_adaptive ===\n");
    test_mode_transitions();
    test_engine_config();
    printf("All adaptive engine tests passed.\n");
    return 0;
}
