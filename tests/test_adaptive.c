/**
 * Adaptive Engine Tests - Validate mode transitions
 */

#include "../include/adaptive_engine.h"
#include "../include/common.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

int tests_passed = 0;
int tests_failed = 0;

/* Test 1: Mode Initialization */
int test_engine_init(void) {
    printf("\n=== Test 1: Engine Initialization ===\n");
    
    EngineState state;
    Metrics metrics;
    
    if (engine_init(&state) != 0) {
        printf("%s Engine init failed\n", TEST_FAIL);
        return 0;
    }
    
    if (state.mode != MODE_NORMAL) {
        printf("%s Initial mode is not NORMAL: %d\n", TEST_FAIL, state.mode);
        return 0;
    }
    
    printf("    Mode: %d (NORMAL)\n", state.mode);
    printf("    Max retries: %d\n", state.max_retries);
    printf("    Retry delay: %d ms\n", state.retry_delay_ms);
    
    printf("%s Engine initialized to NORMAL mode\n", TEST_PASS);
    return 1;
}

/* Test 2: NORMAL → UNSTABLE Transition */
int test_unstable_transition(void) {
    printf("\n=== Test 2: NORMAL → UNSTABLE Transition ===\n");
    
    EngineState state;
    Metrics metrics = {0};
    
    engine_init(&state);
    
    /* Simulate 6% packet loss (above 5% threshold) */
    metrics.packet_loss_rate = 0.06f;
    metrics.consecutive_timeouts = 0;
    
    engine_evaluate(&state, &metrics);
    
    if (state.mode != MODE_UNSTABLE) {
        printf("%s Mode did not transition to UNSTABLE: %d\n", TEST_FAIL, state.mode);
        return 0;
    }
    
    printf("    Packet loss: %.1f%% → Mode: UNSTABLE\n", 
           metrics.packet_loss_rate * 100);
    printf("    Max retries increased to: %d\n", state.max_retries);
    
    printf("%s Transitioned to UNSTABLE mode\n", TEST_PASS);
    return 1;
}

/* Test 3: UNSTABLE → HIGH_RISK Transition */
int test_high_risk_transition(void) {
    printf("\n=== Test 3: UNSTABLE → HIGH_RISK Transition ===\n");
    
    EngineState state;
    Metrics metrics = {0};
    
    engine_init(&state);
    state.mode = MODE_UNSTABLE;
    
    /* Simulate high packet loss */
    metrics.packet_loss_rate = 0.25f;  /* 25% loss */
    
    engine_evaluate(&state, &metrics);
    
    if (state.mode != MODE_HIGH_RISK) {
        printf("%s Mode did not transition to HIGH_RISK: %d\n", TEST_FAIL, state.mode);
        return 0;
    }
    
    if (state.force_padding != 1) {
        printf("%s Padding not forced in HIGH_RISK mode\n", TEST_FAIL);
        return 0;
    }
    
    printf("    Packet loss: %.1f%% → Mode: HIGH_RISK\n", 
           metrics.packet_loss_rate * 100);
    printf("    Force padding: %d\n", state.force_padding);
    printf("    Random delay: %d\n", state.random_delay);
    
    printf("%s Transitioned to HIGH_RISK mode with security measures\n", TEST_PASS);
    return 1;
}

/* Test 4: Auth Failure Trigger */
int test_auth_failure_trigger(void) {
    printf("\n=== Test 4: Auth Failure → HIGH_RISK ===\n");
    
    EngineState state;
    Metrics metrics = {0};
    
    engine_init(&state);
    
    /* Simulate 5 auth failures */
    metrics.auth_fail_count = AUTH_FAIL_THRESHOLD;
    metrics.packet_loss_rate = 0.01f;  /* Low loss, should still trigger */
    
    engine_evaluate(&state, &metrics);
    
    if (state.mode != MODE_HIGH_RISK) {
        printf("%s Auth failures did not trigger HIGH_RISK: %d\n", 
               TEST_FAIL, state.mode);
        return 0;
    }
    
    printf("    Auth failures: %u → Mode: HIGH_RISK\n", 
           metrics.auth_fail_count);
    
    printf("%s Auth failures correctly triggered HIGH_RISK mode\n", TEST_PASS);
    return 1;
}

/* Test 5: Replay Attack Trigger */
int test_replay_trigger(void) {
    printf("\n=== Test 5: Replay Detection → HIGH_RISK ===\n");
    
    EngineState state;
    Metrics metrics = {0};
    
    engine_init(&state);
    
    /* Simulate replay attacks */
    metrics.replay_count = REPLAY_THRESHOLD;
    metrics.packet_loss_rate = 0.0f;
    
    engine_evaluate(&state, &metrics);
    
    if (state.mode != MODE_HIGH_RISK) {
        printf("%s Replays did not trigger HIGH_RISK: %d\n", 
               TEST_FAIL, state.mode);
        return 0;
    }
    
    printf("    Replays detected: %u → Mode: HIGH_RISK\n", 
           metrics.replay_count);
    
    printf("%s Replay attacks correctly triggered HIGH_RISK mode\n", TEST_PASS);
    return 1;
}

/* Test 6: Mode Configuration Values */
int test_mode_configs(void) {
    printf("\n=== Test 6: Mode-Specific Configurations ===\n");
    
    EngineState state;
    
    /* NORMAL mode */
    engine_init(&state);
    if (state.max_retries != 3 || state.force_padding != 0) {
        printf("%s NORMAL mode config incorrect\n", TEST_FAIL);
        return 0;
    }
    printf("    NORMAL: retries=%d, padding=%d ✓\n", 
           state.max_retries, state.force_padding);
    
    /* UNSTABLE mode */
    engine_apply_mode(&state, MODE_UNSTABLE);
    if (state.max_retries != 7 || state.chunk_size != 512) {
        printf("%s UNSTABLE mode config incorrect\n", TEST_FAIL);
        return 0;
    }
    printf("    UNSTABLE: retries=%d, chunk_size=%d ✓\n", 
           state.max_retries, state.chunk_size);
    
    /* HIGH_RISK mode */
    engine_apply_mode(&state, MODE_HIGH_RISK);
    if (state.max_retries != 10 || state.force_padding != 1 || 
        state.random_delay != 1 || state.dh_ratchet_freq != 1) {
        printf("%s HIGH_RISK mode config incorrect\n", TEST_FAIL);
        return 0;
    }
    printf("    HIGH_RISK: retries=%d, padding=%d, delay=%d, dh_freq=%d ✓\n", 
           state.max_retries, state.force_padding, 
           state.random_delay, state.dh_ratchet_freq);
    
    printf("%s All mode configurations correct\n", TEST_PASS);
    return 1;
}

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║      Adaptive Engine Test Suite              ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    
    /* Run tests */
    if (test_engine_init()) tests_passed++; else tests_failed++;
    if (test_unstable_transition()) tests_passed++; else tests_failed++;
    if (test_high_risk_transition()) tests_passed++; else tests_failed++;
    if (test_auth_failure_trigger()) tests_passed++; else tests_failed++;
    if (test_replay_trigger()) tests_passed++; else tests_failed++;
    if (test_mode_configs()) tests_passed++; else tests_failed++;
    
    /* Summary */
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║              Test Summary                    ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Passed: %2d                                  ║\n", tests_passed);
    printf("║  Failed: %2d                                  ║\n", tests_failed);
    printf("╚══════════════════════════════════════════════╝\n");
    printf("\n");
    
    return (tests_failed == 0) ? 0 : 1;
}
