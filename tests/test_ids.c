#include "intrusion.h"
#include "common.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

int tests_passed = 0;
int tests_failed = 0;

void run_test(const char *name, int (*test_fn)(void)) {
    printf("Running %s...\n", name);
    if (test_fn()) {
        printf("%s %s passed\n", TEST_PASS, name);
        tests_passed++;
    } else {
        printf("%s %s failed\n", TEST_FAIL, name);
        tests_failed++;
    }
}

/* Test 1: Threat Scoring and Block progressive penalizations */
int test_threat_scoring_and_progressive_blocks(void) {
    Metrics m = {0};
    const char *test_ip = "192.168.1.50";
    
    /* 1. Confirm IP is allowed initially */
    if (ids_is_blocked(test_ip)) {
        return 0;
    }
    
    /* 2. Induce auth failures up to threshold */
    for (int i = 0; i < AUTH_FAIL_THRESHOLD - 1; i++) {
        ids_record_auth_fail_ex(test_ip, "testuser", &m);
    }
    
    /* Threat score should be 10 * 4 = 40 (Not yet blocked) */
    IdsStats stats;
    ids_get_stats(&stats);
    if (stats.max_threat_score < 40) {
        printf("    [Error] Max threat score was %d (expected >= 40)\n", stats.max_threat_score);
        return 0;
    }
    
    if (ids_is_blocked(test_ip)) {
        printf("    [Error] IP blocked too early\n");
        return 0;
    }
    
    /* 5th auth failure -> triggers block offense #1 (5 minutes) */
    ids_record_auth_fail_ex(test_ip, "testuser", &m);
    
    if (!ids_is_blocked(test_ip)) {
        printf("    [Error] IP not blocked at threshold\n");
        return 0;
    }
    
    printf("    Offense level 1 block successfully verified\n");
    return 1;
}

/* Test 2: Malformed Packet Checks */
int test_malformed_packet_detection(void) {
    Metrics m = {0};
    const char *test_ip = "192.168.1.60";
    
    /* malformed packet adds 25 points */
    ids_record_malformed_packet(test_ip, "Invalid CRC checksum", &m);
    
    IdsStats stats;
    ids_get_stats(&stats);
    if (stats.max_threat_score < 25) {
        printf("    [Error] Threat score should be at least 25 after malformed packet\n");
        return 0;
    }
    
    /* malformed packet #2 adds 25 points -> score 50 (UNSTABLE threshold) */
    ids_record_malformed_packet(test_ip, "Oversized payload length header", &m);
    
    int max_threat = ids_get_max_threat_score();
    if (max_threat < 50) {
        printf("    [Error] Maximum threat score should be >= 50, got %d\n", max_threat);
        return 0;
    }
    
    printf("    Malformed packet score raise successfully verified\n");
    return 1;
}

/* Test 3: Timestamp Anomaly Check */
int test_timestamp_anomaly_detection(void) {
    Metrics m = {0};
    const char *test_ip = "192.168.1.70";
    
    /* timestamp anomaly adds 10 points */
    ids_record_invalid_timestamp(test_ip, &m);
    
    IdsStats stats;
    ids_get_stats(&stats);
    if (stats.max_threat_score < 10) {
        printf("    [Error] Score should be >= 10, got %d\n", stats.max_threat_score);
        return 0;
    }
    
    printf("    Timestamp anomaly score raise successfully verified\n");
    return 1;
}

/* Test 4: User Enumeration Detection */
int test_user_enumeration_recon(void) {
    Metrics m = {0};
    const char *test_ip = "192.168.1.80";
    
    /* Failed auth on user1 */
    ids_record_auth_fail_ex(test_ip, "user1", &m);
    /* Failed auth on user2 */
    ids_record_auth_fail_ex(test_ip, "user2", &m);
    /* Failed auth on user3 */
    ids_record_auth_fail_ex(test_ip, "user3", &m);
    /* Failed auth on user4 -> unique username count > 3 triggers recon enumeration (+40) */
    ids_record_auth_fail_ex(test_ip, "user4", &m);
    
    /* Total failed auth score = 4 * 10 = 40. Recon penalty = 40. Total score >= 80 */
    int score = ids_get_max_threat_score();
    if (score < 80) {
        printf("    [Error] User enumeration score should be >= 80, got %d\n", score);
        return 0;
    }
    
    printf("    User enumeration detection successfully verified\n");
    return 1;
}

/* Test 5: Connection and Message Flooding Checks */
int test_rate_limiting_floods(void) {
    Metrics m = {0};
    const char *test_ip = "192.168.1.90";
    
    /* 1. Simulate Connection Flood (> 20 connections per minute) */
    for (int i = 0; i < 22; i++) {
        ids_record_connection(test_ip, &m);
    }
    
    /* Connection flood penalty: +15 points */
    int score = ids_get_max_threat_score();
    if (score < 15) {
        printf("    [Error] Connection flood score should be >= 15, got %d\n", score);
        return 0;
    }
    
    /* 2. Simulate Message Flood (> 100 messages per minute) */
    for (int i = 0; i < 105; i++) {
        ids_record_message(test_ip, 128, &m);
    }
    
    /* Message flood penalty: +15 points. Cumulative score >= 30 */
    score = ids_get_max_threat_score();
    if (score < 30) {
        printf("    [Error] Message flood score should be >= 30, got %d\n", score);
        return 0;
    }
    
    printf("    Connection/message rate-limiting successfully verified\n");
    return 1;
}

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║       IDS & Threat Detection Test Suite      ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    
    run_test("Threat Scoring & Progressive Blocks", test_threat_scoring_and_progressive_blocks);
    run_test("Malformed Packet Detection", test_malformed_packet_detection);
    run_test("Timestamp Anomaly Detection", test_timestamp_anomaly_detection);
    run_test("User Enumeration Reconnaissance", test_user_enumeration_recon);
    run_test("Rate Limiting & Flood Windows", test_rate_limiting_floods);
    
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║              IDS Test Summary                ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Passed:  %-34d║\n", tests_passed);
    printf("║  Failed:  %-34d║\n", tests_failed);
    printf("╚══════════════════════════════════════════════╝\n\n");
    
    return (tests_failed == 0) ? 0 : 1;
}
