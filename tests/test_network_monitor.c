/**
 * test_network_monitor.c — Network Intelligence Layer Unit Test Suite
 *
 * Validates all monitoring subsystems introduced in network_monitor.h/c:
 *   1. Jitter calculation accuracy
 *   2. Bandwidth rate calculation
 *   3. TCP / UDP health score correctness
 *   4. Link quality score composite calculation
 *   5. Congestion detection trigger
 *   6. Trend detection (IMPROVING / STABLE / DEGRADING)
 *   7. Delivery ratio threshold warnings
 *   8. Network event framework emission and retrieval
 */

#include "network_monitor.h"
#include "adaptive_engine.h"
#include "intrusion.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define TEST_PASS "\033[32m[PASS]\033[0m"
#define TEST_FAIL "\033[31m[FAIL]\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

static void run_test(const char *name, int (*fn)(void)) {
    printf("Running %-50s", name);
    fflush(stdout);
    if (fn()) {
        printf("%s\n", TEST_PASS);
        tests_passed++;
    } else {
        printf("%s\n", TEST_FAIL);
        tests_failed++;
    }
}

/* =========================================================================
 * Test 1: Jitter Calculation
 * ========================================================================= */
static int test_jitter_accuracy(void) {
    /* Simulate RTT sequence: 100, 110, 95, 120 ms
       Expected jitters:        10,  15, 25 ms */

    /* Inject via nm_record_jitter directly */
    nm_record_jitter(10);
    nm_record_jitter(15);
    nm_record_jitter(25);

    JitterStats js;
    metrics_get_jitter_snapshot(&js);

    if (js.sample_count < 3) {
        printf("\n    [Error] Expected >= 3 jitter samples, got %llu\n",
               (unsigned long long)js.sample_count);
        return 0;
    }
    if (js.max_ms < 25) {
        printf("\n    [Error] Max jitter should be >= 25ms, got %u\n", js.max_ms);
        return 0;
    }
    if (js.current_ms != 25) {
        printf("\n    [Error] Current jitter should be 25ms, got %u\n", js.current_ms);
        return 0;
    }
    /* Average of [10, 15, 25] = 16, allow ±2 for integer rounding */
    if (js.avg_ms < 14 || js.avg_ms > 18) {
        printf("\n    [Error] Average jitter should be ~16ms, got %u\n", js.avg_ms);
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Test 2: Bandwidth Rate Calculation
 * ========================================================================= */
static int test_bandwidth_rate(void) {
    /* Record a batch of TX bytes */
    for (int i = 0; i < 100; i++) {
        metrics_record_tx_bytes(1024);    /* 100 × 1KB = 100KB */
        metrics_record_rx_bytes(512);     /* 100 × 512B = 50KB */
    }

    BandwidthStats bs;
    metrics_get_bandwidth_snapshot(&bs);

    /* Totals should accumulate */
    if (bs.bytes_sent_total < 100 * 1024) {
        printf("\n    [Error] TX total should be >= %u bytes, got %llu\n",
               100 * 1024, (unsigned long long)bs.bytes_sent_total);
        return 0;
    }
    if (bs.bytes_recv_total < 100 * 512) {
        printf("\n    [Error] RX total should be >= %u bytes, got %llu\n",
               100 * 512, (unsigned long long)bs.bytes_recv_total);
        return 0;
    }
    if (bs.messages_sent_total < 100) {
        printf("\n    [Error] Messages sent should be >= 100, got %llu\n",
               (unsigned long long)bs.messages_sent_total);
        return 0;
    }

    printf("\n    TX: %llu bytes total | RX: %llu bytes total",
           (unsigned long long)bs.bytes_sent_total,
           (unsigned long long)bs.bytes_recv_total);
    return 1;
}

/* =========================================================================
 * Test 3: TCP and UDP Health Scores
 * ========================================================================= */
static int test_transport_health_scores(void) {
    /* Scenario A: TCP with 100% success at low latency → high health */
    for (int i = 0; i < 50; i++) {
        metrics_record_tcp_send(1, 10);  /* 50 successes, 10ms */
    }

    /* Scenario B: UDP with 50% failure rate → degraded health */
    for (int i = 0; i < 20; i++) {
        metrics_record_udp_send(1, 30);  /* 10 success */
        metrics_record_udp_send(0, 0);   /* 10 failures */
    }

    TransportHealth tcp, udp;
    metrics_get_tcp_health_snapshot(&tcp);
    metrics_get_udp_health_snapshot(&udp);

    printf("\n    TCP: health=%d, success=%.0f%%, latency=%ums",
           tcp.health_score, tcp.success_rate * 100.0f, tcp.avg_latency_ms);
    printf("\n    UDP: health=%d, success=%.0f%%, failures=%llu",
           udp.health_score, udp.success_rate * 100.0f,
           (unsigned long long)udp.failures);

    if (tcp.health_score < 80) {
        printf("\n    [Error] TCP health should be >= 80 with perfect success, got %d\n",
               tcp.health_score);
        return 0;
    }
    if (udp.health_score > 70) {
        printf("\n    [Error] UDP health should be < 70 with 50%% failure rate, got %d\n",
               udp.health_score);
        return 0;
    }
    if (tcp.success_rate < 0.99f) {
        printf("\n    [Error] TCP success rate should be 1.0, got %.2f\n",
               tcp.success_rate);
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Test 4: Link Quality Score Computation
 * ========================================================================= */
static int test_link_quality_score(void) {
    Metrics m;
    memset(&m, 0, sizeof(m));

    /* Case 1: Perfect conditions → score near 100 */
    m.packet_loss_rate = 0.0f;
    m.rtt_ms           = 10;
    m.consecutive_timeouts = 0;
    /* Jitter already set to ~16ms from test 1 (smoothed is lower) */
    int score_good = metrics_calculate_link_quality(&m);
    printf("\n    Perfect conditions: score=%d", score_good);

    /* Case 2: High packet loss + high RTT + many timeouts → degraded */
    m.packet_loss_rate = 0.50f;  /* 50% loss → 20pts penalty */
    m.rtt_ms           = 600;    /* 600ms → 20pts RTT penalty (capped) */
    m.consecutive_timeouts = 10; /* 10 timeouts → 10pts penalty */
    int score_bad = metrics_calculate_link_quality(&m);
    printf("\n    Severe conditions: score=%d", score_bad);

    if (score_good < 70) {
        printf("\n    [Error] Good conditions should score >= 70, got %d\n", score_good);
        return 0;
    }
    if (score_bad > 50) {
        printf("\n    [Error] Severe conditions (50%% loss+600ms RTT+10 timeouts) should score <= 50, got %d\n",
               score_bad);
        return 0;
    }
    if (score_good <= score_bad) {
        printf("\n    [Error] Good score (%d) should exceed poor score (%d)\n",
               score_good, score_bad);
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Test 5: Congestion Detection
 * ========================================================================= */
static int test_congestion_detection(void) {
    /* Inject rising RTT sequence — each sample > previous by >10% */
    uint32_t rtt = 100;
    for (int i = 0; i < CONGESTION_TRIGGER_COUNT + 2; i++) {
        nm_record_rtt_sample(rtt);
        rtt = (uint32_t)(rtt * 1.15f);  /* 15% increase each step */
    }

    int detected = metrics_detect_congestion();
    printf("\n    Congestion detected: %s (after %d rising RTT samples)",
           detected ? "YES" : "NO", CONGESTION_TRIGGER_COUNT + 2);

    if (!detected) {
        printf("\n    [Error] Congestion should be detected after %d consecutive rising RTT samples\n",
               CONGESTION_TRIGGER_COUNT);
        return 0;
    }

    /* Inject stable/falling RTT — congestion should clear */
    for (int i = 0; i < CONGESTION_RTT_WINDOW; i++) {
        nm_record_rtt_sample(50);   /* Stable 50ms */
    }
    int still_detected = metrics_detect_congestion();
    printf("\n    Congestion after stable RTTs: %s", still_detected ? "YES" : "NO");

    if (still_detected) {
        printf("\n    [Error] Congestion should clear after stable RTT samples\n");
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Test 6: Network Trend Detection
 * ========================================================================= */
static int test_trend_detection(void) {
    /* Inject high RTT samples to prime the 5-min EMA */
    for (int i = 0; i < 60; i++) {
        nm_record_rtt_sample(300);  /* Baseline: 300ms RTT */
    }

    NetworkTrend after_high = metrics_get_trend();
    printf("\n    After 300ms RTT: trend=%s",
           after_high == NETWORK_STABLE ? "STABLE" :
           after_high == NETWORK_IMPROVING ? "IMPROVING" : "DEGRADING");

    /* Now inject significantly lower RTT samples */
    for (int i = 0; i < 100; i++) {
        nm_record_rtt_sample(50);   /* 50ms = much better */
    }

    NetworkTrend after_improve = metrics_get_trend();
    printf("\n    After 50ms RTT:  trend=%s",
           after_improve == NETWORK_STABLE ? "STABLE" :
           after_improve == NETWORK_IMPROVING ? "IMPROVING" : "DEGRADING");

    if (after_improve == NETWORK_DEGRADING) {
        printf("\n    [Error] After feeding lower RTTs the trend should not be DEGRADING\n");
        return 0;
    }

    /* Now inject very high RTT samples */
    for (int i = 0; i < 200; i++) {
        nm_record_rtt_sample(800);  /* 800ms = severe */
    }

    NetworkTrend after_degrade = metrics_get_trend();
    printf("\n    After 800ms RTT: trend=%s",
           after_degrade == NETWORK_STABLE ? "STABLE" :
           after_degrade == NETWORK_IMPROVING ? "IMPROVING" : "DEGRADING");

    if (after_degrade == NETWORK_IMPROVING) {
        printf("\n    [Error] After feeding very high RTTs the trend should not be IMPROVING\n");
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Test 7: Delivery Ratio Threshold
 * ========================================================================= */
static int test_delivery_ratio(void) {
    /* Simulate 10% loss scenario */
    for (int i = 0; i < 100; i++) {
        metrics_record_delivery(i % 10 != 0 ? 1 : 0);  /* 90% delivered */
    }

    DeliveryStats ds;
    metrics_get_delivery_snapshot(&ds);
    printf("\n    Delivery: %llu/%llu = %.1f%%",
           (unsigned long long)ds.messages_delivered,
           (unsigned long long)ds.messages_sent,
           ds.current_ratio * 100.0f);

    if (ds.messages_sent < 100) {
        printf("\n    [Error] Expected >= 100 messages tracked, got %llu\n",
               (unsigned long long)ds.messages_sent);
        return 0;
    }
    if (ds.current_ratio < 0.85f || ds.current_ratio > 0.95f) {
        printf("\n    [Error] Expected ratio ~0.90, got %.3f\n", ds.current_ratio);
        return 0;
    }

    /* Simulate 50% loss scenario → below DELIVERY_RATIO_CRITICAL */
    for (int i = 0; i < 200; i++) {
        metrics_record_delivery(i % 2);  /* Alternating 50% */
    }

    metrics_get_delivery_snapshot(&ds);
    printf("\n    After 50%% loss: ratio=%.1f%%", ds.current_ratio * 100.0f);

    if (ds.current_ratio > DELIVERY_RATIO_WARN) {
        printf("\n    [Error] After 50%% loss, ratio should be < %.2f, got %.3f\n",
               DELIVERY_RATIO_WARN, ds.current_ratio);
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Test 8: Network Event Framework
 * ========================================================================= */
static int test_event_framework(void) {
    Metrics m;
    memset(&m, 0, sizeof(m));
    m.packet_loss_rate = 0.05f;
    m.rtt_ms           = 120;

    /* Emit several distinct events */
    metrics_emit_event(NET_EVENT_HIGH_JITTER,         "Test jitter event", &m);
    metrics_emit_event(NET_EVENT_CONGESTION_DETECTED, "Test congestion event", &m);
    metrics_emit_event(NET_EVENT_DEGRADED,            "Test degraded event", &m);
    metrics_emit_event(NET_EVENT_TRANSPORT_RECOVERED, "Test recovery event", NULL);

    /* Retrieve them */
    NetworkEvent events[16];
    int count = metrics_get_events(events, 16);

    printf("\n    Events emitted and retrieved: %d", count);

    if (count < 4) {
        printf("\n    [Error] Expected >= 4 events, got %d\n", count);
        return 0;
    }

    /* Verify last event details are stored */
    int found_jitter   = 0;
    int found_recovery = 0;
    for (int i = 0; i < count; i++) {
        if (events[i].type == NET_EVENT_HIGH_JITTER)         found_jitter   = 1;
        if (events[i].type == NET_EVENT_TRANSPORT_RECOVERED) found_recovery = 1;
    }
    if (!found_jitter) {
        printf("\n    [Error] HIGH_JITTER event not found in ring buffer\n");
        return 0;
    }
    if (!found_recovery) {
        printf("\n    [Error] TRANSPORT_RECOVERED event not found in ring buffer\n");
        return 0;
    }

    /* Verify dashboard snapshot works */
    NetworkDashboard dash;
    metrics_get_dashboard(&dash, &m, MODE_NORMAL);
    printf("\n    Dashboard: RTT=%ums, LinkQuality=%d, Trend=%s, Events=%d",
           dash.rtt_current_ms,
           dash.link_quality_score,
           dash.trend == NETWORK_STABLE ? "STABLE" :
           dash.trend == NETWORK_IMPROVING ? "IMPROVING" : "DEGRADING",
           dash.event_count);

    if (dash.event_count < 4) {
        printf("\n    [Error] Dashboard event count should be >= 4, got %d\n",
               dash.event_count);
        return 0;
    }
    return 1;
}

/* =========================================================================
 * Main
 * ========================================================================= */
int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║       Network Intelligence Layer Test Suite          ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    run_test("Jitter Calculation Accuracy",           test_jitter_accuracy);
    run_test("Bandwidth Rate Calculation",            test_bandwidth_rate);
    run_test("TCP / UDP Health Scores",              test_transport_health_scores);
    run_test("Link Quality Score Computation",       test_link_quality_score);
    run_test("Congestion Detection Trigger",         test_congestion_detection);
    run_test("Network Trend Detection",              test_trend_detection);
    run_test("Delivery Ratio Threshold Warnings",   test_delivery_ratio);
    run_test("Network Event Framework",              test_event_framework);

    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║              Network Monitor Test Summary            ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Passed:  %-42d║\n", tests_passed);
    printf("║  Failed:  %-42d║\n", tests_failed);
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    return (tests_failed == 0) ? 0 : 1;
}
