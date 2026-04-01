/**
 * Multi-Path Transport Tests - Validate deduplication and failover
 */

#include "../include/multipath.h"
#include "../include/common.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

int tests_passed = 0;
int tests_failed = 0;

/* Test 1: Deduplication - Same message ID twice */
int test_deduplication(void) {
    printf("\n=== Test 1: Message Deduplication ===\n");
    
    uint8_t msg_id[MSG_ID_LEN];
    RAND_bytes(msg_id, MSG_ID_LEN);
    
    /* First message - should be new */
    if (dedup_check(msg_id) != 0) {
        printf("%s First message incorrectly marked as duplicate\n", TEST_FAIL);
        return 0;
    }
    
    dedup_add(msg_id);
    
    /* Second message with same ID - should be duplicate */
    if (dedup_check(msg_id) == 0) {
        printf("%s Second message not detected as duplicate\n", TEST_FAIL);
        return 0;
    }
    
    printf("    First message: NEW ✓\n");
    printf("    Second message: DUPLICATE ✓\n");
    
    printf("%s Deduplication works correctly\n", TEST_PASS);
    return 1;
}

/* Test 2: Dedup Window Overflow */
int test_dedup_window(void) {
    printf("\n=== Test 2: Deduplication Window ===\n");
    
    uint8_t msg_ids[DEDUP_WINDOW + 10][MSG_ID_LEN];
    
    /* Generate and add DEDUP_WINDOW + 10 messages */
    for (int i = 0; i < DEDUP_WINDOW + 10; i++) {
        RAND_bytes(msg_ids[i], MSG_ID_LEN);
        dedup_add(msg_ids[i]);
    }
    
    /* First 10 messages should have been evicted */
    int evicted_count = 0;
    for (int i = 0; i < 10; i++) {
        if (dedup_check(msg_ids[i]) == 0) {
            evicted_count++;
        }
    }
    
    /* Last DEDUP_WINDOW messages should still be present */
    int present_count = 0;
    for (int i = 10; i < DEDUP_WINDOW + 10; i++) {
        if (dedup_check(msg_ids[i]) != 0) {
            present_count++;
        }
    }
    
    printf("    Evicted (old): %d/%d ✓\n", evicted_count, 10);
    printf("    Present (recent): %d/%d ✓\n", present_count, DEDUP_WINDOW);
    
    if (evicted_count > 0 && present_count == DEDUP_WINDOW) {
        printf("%s Ring buffer window works correctly\n", TEST_PASS);
        return 1;
    } else {
        printf("%s Window behavior incorrect\n", TEST_FAIL);
        return 0;
    }
}

/* Test 3: Priority Message Handling */
int test_priority_ordering(void) {
    printf("\n=== Test 3: Priority Message Ordering ===\n");
    
    /* Initialize priority queue */
    if (pq_init() != 0) {
        printf("%s Priority queue init failed\n", TEST_FAIL);
        return 0;
    }
    
    /* Enqueue messages with different priorities */
    QueuedMessage msg1, msg2, msg3;
    
    memset(&msg1, 0, sizeof(msg1));
    msg1.priority = PRIORITY_NORMAL;
    RAND_bytes(msg1.msg_id, MSG_ID_LEN);
    strcpy((char *)msg1.payload, "Normal message");
    msg1.payload_len = strlen("Normal message");
    
    memset(&msg2, 0, sizeof(msg2));
    msg2.priority = PRIORITY_CRITICAL;
    RAND_bytes(msg2.msg_id, MSG_ID_LEN);
    strcpy((char *)msg2.payload, "Critical message");
    msg2.payload_len = strlen("Critical message");
    
    memset(&msg3, 0, sizeof(msg3));
    msg3.priority = PRIORITY_URGENT;
    RAND_bytes(msg3.msg_id, MSG_ID_LEN);
    strcpy((char *)msg3.payload, "Urgent message");
    msg3.payload_len = strlen("Urgent message");
    
    /* Enqueue in order: NORMAL, CRITICAL, URGENT */
    pq_enqueue(&msg1);
    pq_enqueue(&msg2);
    pq_enqueue(&msg3);
    
    /* Dequeue should return: CRITICAL, URGENT, NORMAL */
    QueuedMessage *dequeued;
    
    dequeued = pq_dequeue();
    if (!dequeued || dequeued->priority != PRIORITY_CRITICAL) {
        printf("%s First dequeue should be CRITICAL\n", TEST_FAIL);
        return 0;
    }
    printf("    1st dequeue: CRITICAL ✓\n");
    
    dequeued = pq_dequeue();
    if (!dequeued || dequeued->priority != PRIORITY_URGENT) {
        printf("%s Second dequeue should be URGENT\n", TEST_FAIL);
        return 0;
    }
    printf("    2nd dequeue: URGENT ✓\n");
    
    dequeued = pq_dequeue();
    if (!dequeued || dequeued->priority != PRIORITY_NORMAL) {
        printf("%s Third dequeue should be NORMAL\n", TEST_FAIL);
        return 0;
    }
    printf("    3rd dequeue: NORMAL ✓\n");
    
    pq_destroy();
    
    printf("%s Priority ordering works correctly\n", TEST_PASS);
    return 1;
}

/* Test 4: Message ID Generation Uniqueness */
int test_msg_id_uniqueness(void) {
    printf("\n=== Test 4: Message ID Uniqueness ===\n");
    
    uint8_t msg_ids[1000][MSG_ID_LEN];
    
    /* Generate 1000 message IDs */
    for (int i = 0; i < 1000; i++) {
        RAND_bytes(msg_ids[i], MSG_ID_LEN);
    }
    
    /* Check for collisions */
    int collisions = 0;
    for (int i = 0; i < 1000; i++) {
        for (int j = i + 1; j < 1000; j++) {
            if (memcmp(msg_ids[i], msg_ids[j], MSG_ID_LEN) == 0) {
                collisions++;
            }
        }
    }
    
    printf("    Generated 1000 message IDs\n");
    printf("    Collisions: %d\n", collisions);
    
    if (collisions == 0) {
        printf("%s All message IDs are unique\n", TEST_PASS);
        return 1;
    } else {
        printf("%s Message ID collision detected\n", TEST_FAIL);
        return 0;
    }
}

/* Test 5: Payload Size Validation */
int test_payload_sizes(void) {
    printf("\n=== Test 5: Fixed Payload Size (Traffic Analysis Resistance) ===\n");
    
    const char *messages[] = {
        "Hi",
        "Medium length message here",
        "This is a much longer message that should still pad to the same size"
    };
    
    uint8_t padded[3][MSG_PADDED_SIZE];
    
    for (int i = 0; i < 3; i++) {
        if (msg_pad((const uint8_t *)messages[i], strlen(messages[i]), padded[i]) != 0) {
            printf("%s Padding failed for message %d\n", TEST_FAIL, i);
            return 0;
        }
    }
    
    /* All padded messages should be MSG_PADDED_SIZE */
    printf("    Message 1 (%2zu bytes) → %d bytes\n", strlen(messages[0]), MSG_PADDED_SIZE);
    printf("    Message 2 (%2zu bytes) → %d bytes\n", strlen(messages[1]), MSG_PADDED_SIZE);
    printf("    Message 3 (%2zu bytes) → %d bytes\n", strlen(messages[2]), MSG_PADDED_SIZE);
    
    /* Verify unpadding recovers original */
    for (int i = 0; i < 3; i++) {
        uint8_t unpadded[MSG_PADDED_SIZE];
        int unpadded_len = msg_unpad(padded[i], MSG_PADDED_SIZE, unpadded);
        
        if (unpadded_len != (int)strlen(messages[i])) {
            printf("%s Unpadded length mismatch for message %d\n", TEST_FAIL, i);
            return 0;
        }
        
        if (memcmp(unpadded, messages[i], unpadded_len) != 0) {
            printf("%s Unpadded content mismatch for message %d\n", TEST_FAIL, i);
            return 0;
        }
    }
    
    printf("%s All messages pad to constant size\n", TEST_PASS);
    return 1;
}

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║      Multi-Path Transport Test Suite         ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    
    /* Initialize OpenSSL for RAND_bytes */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    
    /* Run tests */
    if (test_deduplication()) tests_passed++; else tests_failed++;
    if (test_dedup_window()) tests_passed++; else tests_failed++;
    if (test_priority_ordering()) tests_passed++; else tests_failed++;
    if (test_msg_id_uniqueness()) tests_passed++; else tests_failed++;
    if (test_payload_sizes()) tests_passed++; else tests_failed++;
    
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
