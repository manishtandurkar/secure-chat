/**
 * network_monitor.c — Network Intelligence Layer Implementation
 *
 * Implements real-time jitter tracking, bandwidth estimation, per-path
 * TCP/UDP health monitoring, link quality scoring, congestion detection,
 * trend analysis, delivery tracking, and structured network event logging.
 *
 * All state is protected by a single net_monitor_mutex for simplicity and
 * to minimize lock contention overhead in production workloads.
 */

#define _POSIX_C_SOURCE 200809L
#include "network_monitor.h"
#include "platform_compat.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <math.h>

/* =========================================================================
 * Internal State
 * ========================================================================= */

static pthread_mutex_t nm_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --- Jitter --- */
static JitterStats g_jitter = {0};

/* --- RTT history for congestion & trend analysis --- */
static uint32_t g_rtt_history[CONGESTION_RTT_WINDOW];
static int       g_rtt_history_idx   = 0;
static int       g_rtt_history_count = 0;

/* Rolling averages bucketed by time (approximate EMA per sample call):
   We maintain three EMAs with different decay constants.
   alpha_1min ≈ 1/60, alpha_5min ≈ 1/300, alpha_15min ≈ 1/900
   These are updated on every RTT sample, so they represent "time-weighted"
   trend windows without requiring actual wall-clock timers. */
static float g_ema_1min  = 0.0f;
static float g_ema_5min  = 0.0f;
static float g_ema_15min = 0.0f;
static int   g_ema_initialized = 0;

/* --- Bandwidth --- */
static BandwidthStats g_bw = {0};
static time_t         g_bw_window_start   = 0;
static uint64_t       g_bw_window_tx      = 0;  /* TX bytes in current window */
static uint64_t       g_bw_window_rx      = 0;  /* RX bytes in current window */
static float          g_bw_ema_throughput = 0.0f;

/* --- Transport health --- */
static TransportHealth g_tcp = {0};
static TransportHealth g_udp = {0};

/* --- Delivery stats --- */
static DeliveryStats g_delivery = {0};

/* --- Network event ring buffer --- */
static NetworkEvent g_events[NET_EVENT_RING_SIZE];
static int          g_event_write_idx = 0;
static int          g_event_total     = 0;  /* Total ever emitted (for count) */

/* =========================================================================
 * Internal Helpers (called under nm_mutex)
 * ========================================================================= */

/** Update transport health score from current success/failure stats. */
static void _update_transport_score(TransportHealth *t) {
    uint64_t total = t->sends;
    if (total == 0) {
        t->health_score  = 100;
        t->success_rate  = 1.0f;
        t->failure_rate  = 0.0f;
        return;
    }

    uint64_t ok = total - t->failures;
    t->success_rate = (float)ok / (float)total;
    t->failure_rate = (float)t->failures / (float)total;

    /* Base score from success rate */
    float score = t->success_rate * 80.0f;

    /* Latency penalty: 0ms=0, 500ms=20pts deducted */
    float lat_penalty = (float)t->avg_latency_ms / 25.0f;  /* 500ms → 20 */
    if (lat_penalty > 20.0f) lat_penalty = 20.0f;
    score += (20.0f - lat_penalty);

    if (score < 0.0f)   score = 0.0f;
    if (score > 100.0f) score = 100.0f;
    t->health_score = (int)score;
}

/** Flush bandwidth window if BW_WINDOW_SEC seconds have elapsed. */
static void _flush_bw_window(time_t now) {
    if (g_bw_window_start == 0) {
        g_bw_window_start = now;
        return;
    }
    double elapsed = difftime(now, g_bw_window_start);
    if (elapsed < (double)BW_WINDOW_SEC) return;

    /* Compute rates for the window */
    float tx_rate = (elapsed > 0.0) ? (float)g_bw_window_tx / (float)elapsed : 0.0f;
    float rx_rate = (elapsed > 0.0) ? (float)g_bw_window_rx / (float)elapsed : 0.0f;

    g_bw.tx_bytes_per_sec = tx_rate;
    g_bw.rx_bytes_per_sec = rx_rate;
    g_bw.total_throughput_bps = tx_rate + rx_rate;

    /* Smooth total throughput */
    if (g_bw_ema_throughput == 0.0f) {
        g_bw_ema_throughput = g_bw.total_throughput_bps;
    } else {
        g_bw_ema_throughput = 0.875f * g_bw_ema_throughput
                            + 0.125f * g_bw.total_throughput_bps;
    }
    g_bw.avg_throughput_bps = g_bw_ema_throughput;

    /* Reset window */
    g_bw_window_tx    = 0;
    g_bw_window_rx    = 0;
    g_bw_window_start = now;
}

/** Map NetworkEventType to a display string. */
static const char *_event_name(NetworkEventType t) {
    switch (t) {
        case NET_EVENT_HEALTHY:              return "NETWORK_HEALTHY";
        case NET_EVENT_DEGRADED:             return "NETWORK_DEGRADED";
        case NET_EVENT_HIGH_JITTER:          return "HIGH_JITTER";
        case NET_EVENT_CONGESTION_DETECTED:  return "CONGESTION_DETECTED";
        case NET_EVENT_LINK_FAILURE:         return "LINK_FAILURE";
        case NET_EVENT_TRANSPORT_FAILURE:    return "TRANSPORT_FAILURE";
        case NET_EVENT_TRANSPORT_RECOVERED:  return "TRANSPORT_RECOVERED";
        case NET_EVENT_NETWORK_RECOVERED:    return "NETWORK_RECOVERED";
        case NET_EVENT_HIGH_PACKET_LOSS:     return "HIGH_PACKET_LOSS";
        case NET_EVENT_HIGH_RTT:             return "HIGH_RTT";
        case NET_EVENT_ENGINE_ESCALATION:    return "ENGINE_ESCALATION";
        case NET_EVENT_DELIVERY_WARN:        return "DELIVERY_WARN";
        default:                             return "UNKNOWN_EVENT";
    }
}

/* =========================================================================
 * Recording APIs
 * ========================================================================= */

void nm_record_jitter(uint32_t jitter_ms) {
    pthread_mutex_lock(&nm_mutex);

    g_jitter.current_ms = jitter_ms;
    g_jitter.sample_count++;

    /* Update max */
    if (jitter_ms > g_jitter.max_ms) {
        g_jitter.max_ms = jitter_ms;
    }

    /* Update rolling average (cumulative mean) */
    if (g_jitter.sample_count == 1) {
        g_jitter.avg_ms     = jitter_ms;
        g_jitter.smoothed_ms = jitter_ms;
    } else {
        /* Incremental mean: avg = avg + (new - avg) / n */
        uint64_t n = g_jitter.sample_count;
        g_jitter.avg_ms = (uint32_t)(g_jitter.avg_ms + (jitter_ms - (int32_t)g_jitter.avg_ms) / (int64_t)n);

        /* Exponential moving average with alpha=0.125 (same as TCP RTT smoothing) */
        g_jitter.smoothed_ms = (g_jitter.smoothed_ms * 7 + jitter_ms) / 8;
    }

    pthread_mutex_unlock(&nm_mutex);
}

void nm_record_rtt_sample(uint32_t rtt_ms) {
    pthread_mutex_lock(&nm_mutex);

    /* Store in ring buffer for congestion detection */
    g_rtt_history[g_rtt_history_idx] = rtt_ms;
    g_rtt_history_idx = (g_rtt_history_idx + 1) % CONGESTION_RTT_WINDOW;
    if (g_rtt_history_count < CONGESTION_RTT_WINDOW) {
        g_rtt_history_count++;
    }

    /* Update EMA buckets for trend analysis */
    if (!g_ema_initialized) {
        g_ema_1min  = (float)rtt_ms;
        g_ema_5min  = (float)rtt_ms;
        g_ema_15min = (float)rtt_ms;
        g_ema_initialized = 1;
    } else {
        /* alpha = 1/N for N-sample window approximation */
        g_ema_1min  = g_ema_1min  + ((float)rtt_ms - g_ema_1min)  / 60.0f;
        g_ema_5min  = g_ema_5min  + ((float)rtt_ms - g_ema_5min)  / 300.0f;
        g_ema_15min = g_ema_15min + ((float)rtt_ms - g_ema_15min) / 900.0f;
    }

    pthread_mutex_unlock(&nm_mutex);
}

void metrics_record_tx_bytes(size_t bytes) {
    pthread_mutex_lock(&nm_mutex);

    g_bw.bytes_sent_total  += (uint64_t)bytes;
    g_bw.messages_sent_total++;
    g_bw_window_tx         += (uint64_t)bytes;

    _flush_bw_window(time(NULL));

    pthread_mutex_unlock(&nm_mutex);
}

void metrics_record_rx_bytes(size_t bytes) {
    pthread_mutex_lock(&nm_mutex);

    g_bw.bytes_recv_total  += (uint64_t)bytes;
    g_bw.messages_recv_total++;
    g_bw_window_rx         += (uint64_t)bytes;

    _flush_bw_window(time(NULL));

    pthread_mutex_unlock(&nm_mutex);
}

void metrics_record_tcp_send(int success, uint32_t latency_ms) {
    pthread_mutex_lock(&nm_mutex);

    g_tcp.sends++;
    if (!success) {
        g_tcp.failures++;
    }

    /* Smooth latency with EMA (only on successful sends with known latency) */
    if (success && latency_ms > 0) {
        if (g_tcp.avg_latency_ms == 0) {
            g_tcp.avg_latency_ms = latency_ms;
        } else {
            g_tcp.avg_latency_ms = (g_tcp.avg_latency_ms * 7 + latency_ms) / 8;
        }
    }

    _update_transport_score(&g_tcp);
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_record_tcp_recv(int success) {
    pthread_mutex_lock(&nm_mutex);
    if (success) {
        g_tcp.recvs++;
    } else {
        g_tcp.failures++;
        _update_transport_score(&g_tcp);
    }
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_record_udp_send(int success, uint32_t latency_ms) {
    pthread_mutex_lock(&nm_mutex);

    g_udp.sends++;
    if (!success) {
        g_udp.failures++;
    }

    if (success && latency_ms > 0) {
        if (g_udp.avg_latency_ms == 0) {
            g_udp.avg_latency_ms = latency_ms;
        } else {
            g_udp.avg_latency_ms = (g_udp.avg_latency_ms * 7 + latency_ms) / 8;
        }
    }

    _update_transport_score(&g_udp);
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_record_udp_recv(int success) {
    pthread_mutex_lock(&nm_mutex);
    if (success) {
        g_udp.recvs++;
    } else {
        g_udp.failures++;
        _update_transport_score(&g_udp);
    }
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_record_delivery(int delivered) {
    pthread_mutex_lock(&nm_mutex);

    g_delivery.messages_sent++;
    if (delivered) {
        g_delivery.messages_delivered++;
    }

    /* Recompute current ratio */
    if (g_delivery.messages_sent > 0) {
        g_delivery.current_ratio =
            (float)g_delivery.messages_delivered / (float)g_delivery.messages_sent;
    } else {
        g_delivery.current_ratio = 1.0f;
    }

    /* Smooth average ratio (EMA alpha=0.125) */
    if (g_delivery.avg_ratio == 0.0f) {
        g_delivery.avg_ratio = g_delivery.current_ratio;
    } else {
        g_delivery.avg_ratio = 0.875f * g_delivery.avg_ratio
                             + 0.125f * g_delivery.current_ratio;
    }

    pthread_mutex_unlock(&nm_mutex);
}

/* =========================================================================
 * Query APIs
 * ========================================================================= */

int metrics_calculate_link_quality(const Metrics *m) {
    if (!m) return 50; /* Unknown — return mid-range */

    float score = 100.0f;

    /* --- Packet loss penalty (weight: 40 pts) --- */
    /* 0% loss = 0 pts, 100% loss = 40 pts */
    score -= (m->packet_loss_rate * 40.0f);

    /* --- RTT penalty (weight: 20 pts) --- */
    /* 0ms = 0 pts, 500ms = 20 pts */
    float rtt_penalty = (float)m->rtt_ms / 25.0f;
    if (rtt_penalty > 20.0f) rtt_penalty = 20.0f;
    score -= rtt_penalty;

    /* --- Jitter penalty (weight: 15 pts) --- */
    /* 0ms = 0 pts, 200ms = 15 pts */
    pthread_mutex_lock(&nm_mutex);
    float jitter_penalty = (float)g_jitter.smoothed_ms / 13.33f;
    if (jitter_penalty > 15.0f) jitter_penalty = 15.0f;
    score -= jitter_penalty;

    /* --- Timeout penalty (weight: 10 pts) --- */
    /* 0 timeouts = 0, 10+ = 10 pts */
    float timeout_penalty = (float)m->consecutive_timeouts;
    if (timeout_penalty > 10.0f) timeout_penalty = 10.0f;
    score -= timeout_penalty;

    /* --- TCP health penalty (weight: 10 pts) --- */
    float tcp_penalty = (100.0f - (float)g_tcp.health_score) * 0.10f;
    score -= tcp_penalty;

    /* --- UDP health penalty (weight: 5 pts) --- */
    float udp_penalty = (100.0f - (float)g_udp.health_score) * 0.05f;
    score -= udp_penalty;
    pthread_mutex_unlock(&nm_mutex);

    if (score < 0.0f)   score = 0.0f;
    if (score > 100.0f) score = 100.0f;

    return (int)score;
}

int metrics_detect_congestion(void) {
    pthread_mutex_lock(&nm_mutex);

    if (g_rtt_history_count < CONGESTION_TRIGGER_COUNT) {
        pthread_mutex_unlock(&nm_mutex);
        return 0;
    }

    /* Walk backwards through the history ring buffer.
       Count consecutive samples where each exceeds the previous by >10%. */
    int consecutive_rising = 0;
    int start = (g_rtt_history_idx - 1 + CONGESTION_RTT_WINDOW) % CONGESTION_RTT_WINDOW;

    for (int i = 0; i < g_rtt_history_count - 1; i++) {
        int idx_newer = (start - i + CONGESTION_RTT_WINDOW) % CONGESTION_RTT_WINDOW;
        int idx_older = (start - i - 1 + CONGESTION_RTT_WINDOW) % CONGESTION_RTT_WINDOW;

        uint32_t newer = g_rtt_history[idx_newer];
        uint32_t older = g_rtt_history[idx_older];

        if (older > 0 && newer > older + (older / 10)) {
            /* newer > older * 1.10 */
            consecutive_rising++;
        } else {
            break; /* Chain broken */
        }

        if (consecutive_rising >= CONGESTION_TRIGGER_COUNT) {
            pthread_mutex_unlock(&nm_mutex);
            return 1; /* CONGESTION_DETECTED */
        }
    }

    pthread_mutex_unlock(&nm_mutex);
    return 0;
}

NetworkTrend metrics_get_trend(void) {
    pthread_mutex_lock(&nm_mutex);

    if (!g_ema_initialized || g_rtt_history_count < 10) {
        pthread_mutex_unlock(&nm_mutex);
        return NETWORK_STABLE;
    }

    /* Compare short-window vs longer windows.
       If recent 1-min EMA is significantly better than 5-min: IMPROVING
       If recent 1-min EMA is significantly worse than 5-min: DEGRADING
       Otherwise: STABLE */
    NetworkTrend trend;
    if (g_ema_5min > 0.0f) {
        float ratio = g_ema_1min / g_ema_5min;
        if (ratio < TREND_IMPROVE_RATIO) {
            trend = NETWORK_IMPROVING;
        } else if (ratio > TREND_DEGRADE_RATIO) {
            trend = NETWORK_DEGRADING;
        } else {
            trend = NETWORK_STABLE;
        }
    } else {
        trend = NETWORK_STABLE;
    }

    pthread_mutex_unlock(&nm_mutex);
    return trend;
}

PreferredPath multipath_preferred_path(void) {
    pthread_mutex_lock(&nm_mutex);

    int tcp_score = g_tcp.health_score;
    int udp_score = g_udp.health_score;

    pthread_mutex_unlock(&nm_mutex);

    /* Both healthy (score >= 70): dual-path */
    if (tcp_score >= 70 && udp_score >= 70) {
        return PATH_BOTH;
    }

    /* UDP failing badly, TCP fine: prefer TCP */
    if (udp_score < 30 && tcp_score >= 50) {
        return PATH_TCP;
    }

    /* TCP congested/failing, UDP fine: prefer UDP */
    if (tcp_score < 30 && udp_score >= 50) {
        return PATH_UDP;
    }

    /* Default: TCP first (TLS provides authentication) */
    return PATH_TCP;
}

void metrics_emit_event(NetworkEventType type, const char *details,
                        const Metrics *m) {
    /* Log to stderr first (no lock needed for fprintf) */
    metrics_log_network_event(type, details, m);

    pthread_mutex_lock(&nm_mutex);

    NetworkEvent *ev = &g_events[g_event_write_idx];
    ev->timestamp    = time(NULL);
    ev->type         = type;
    ev->jitter_ms    = g_jitter.current_ms;

    if (m) {
        ev->packet_loss  = m->packet_loss_rate;
        ev->rtt_ms       = m->rtt_ms;
    } else {
        ev->packet_loss  = 0.0f;
        ev->rtt_ms       = 0;
    }

    /* Compute link quality inline to avoid deadlock (nm_mutex already held) */
    float score = 100.0f;
    if (m) {
        score -= (m->packet_loss_rate * 40.0f);
        float rtt_p = (float)m->rtt_ms / 25.0f;
        if (rtt_p > 20.0f) rtt_p = 20.0f;
        score -= rtt_p;
        float jit_p = (float)g_jitter.smoothed_ms / 13.33f;
        if (jit_p > 15.0f) jit_p = 15.0f;
        score -= jit_p;
        float to_p = (float)m->consecutive_timeouts;
        if (to_p > 10.0f) to_p = 10.0f;
        score -= to_p;
        score -= (100.0f - (float)g_tcp.health_score) * 0.10f;
        score -= (100.0f - (float)g_udp.health_score) * 0.05f;
        if (score < 0.0f) score = 0.0f;
        if (score > 100.0f) score = 100.0f;
    }
    ev->link_quality = (int)score;

    if (details) {
        strncpy(ev->details, details, sizeof(ev->details) - 1);
        ev->details[sizeof(ev->details) - 1] = '\0';
    } else {
        ev->details[0] = '\0';
    }

    g_event_write_idx = (g_event_write_idx + 1) % NET_EVENT_RING_SIZE;
    g_event_total++;

    pthread_mutex_unlock(&nm_mutex);
}

int metrics_get_events(NetworkEvent *out, int max_count) {
    if (!out || max_count <= 0) return 0;

    pthread_mutex_lock(&nm_mutex);

    int count = g_event_total < NET_EVENT_RING_SIZE
                ? g_event_total : NET_EVENT_RING_SIZE;
    if (count > max_count) count = max_count;

    /* Read from oldest to newest */
    int start_idx = (g_event_write_idx - count + NET_EVENT_RING_SIZE) % NET_EVENT_RING_SIZE;
    for (int i = 0; i < count; i++) {
        out[i] = g_events[(start_idx + i) % NET_EVENT_RING_SIZE];
    }

    pthread_mutex_unlock(&nm_mutex);
    return count;
}

void metrics_get_dashboard(NetworkDashboard *out, const Metrics *m,
                           AdaptiveMode mode) {
    if (!out) return;

    pthread_mutex_lock(&nm_mutex);

    /* RTT */
    out->rtt_current_ms   = m ? m->rtt_ms : 0;
    out->rtt_avg_ms       = m ? m->rtt_ms : 0;  /* Smoothed RTT stored in Metrics */

    /* Jitter */
    out->jitter           = g_jitter;

    /* Packet loss */
    out->packet_loss_rate = m ? m->packet_loss_rate : 0.0f;

    /* Transport */
    out->tcp = g_tcp;
    out->udp = g_udp;

    /* Bandwidth */
    _flush_bw_window(time(NULL));  /* Ensure rates are fresh */
    out->bandwidth = g_bw;

    /* Delivery */
    out->delivery = g_delivery;

    /* Engine mode */
    out->engine_mode = mode;

    /* Recent events — copy last 16 */
    int n = g_event_total < NET_EVENT_RING_SIZE ? g_event_total : NET_EVENT_RING_SIZE;
    int count = (n < 16) ? n : 16;
    int start = (g_event_write_idx - count + NET_EVENT_RING_SIZE) % NET_EVENT_RING_SIZE;
    for (int i = 0; i < count; i++) {
        out->recent_events[i] = g_events[(start + i) % NET_EVENT_RING_SIZE];
    }
    out->event_count = count;

    out->snapshot_time = time(NULL);

    pthread_mutex_unlock(&nm_mutex);

    /* Fields requiring nm_mutex released first */
    out->congestion_detected = metrics_detect_congestion();
    out->trend               = metrics_get_trend();
    out->link_quality_score  = metrics_calculate_link_quality(m);
}

void metrics_get_jitter_snapshot(JitterStats *out) {
    if (!out) return;
    pthread_mutex_lock(&nm_mutex);
    *out = g_jitter;
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_get_bandwidth_snapshot(BandwidthStats *out) {
    if (!out) return;
    pthread_mutex_lock(&nm_mutex);
    _flush_bw_window(time(NULL));
    *out = g_bw;
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_get_tcp_health_snapshot(TransportHealth *out) {
    if (!out) return;
    pthread_mutex_lock(&nm_mutex);
    *out = g_tcp;
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_get_udp_health_snapshot(TransportHealth *out) {
    if (!out) return;
    pthread_mutex_lock(&nm_mutex);
    *out = g_udp;
    pthread_mutex_unlock(&nm_mutex);
}

void metrics_get_delivery_snapshot(DeliveryStats *out) {
    if (!out) return;
    pthread_mutex_lock(&nm_mutex);
    *out = g_delivery;
    pthread_mutex_unlock(&nm_mutex);
}

/* =========================================================================
 * Structured Network Audit Logging
 * ========================================================================= */

void metrics_log_network_event(NetworkEventType type, const char *details,
                               const Metrics *m) {
    time_t now = time(NULL);
    char timebuf[32] = {0};

#ifdef PLATFORM_WINDOWS
    struct tm tm_info;
    localtime_s(&tm_info, &now);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);
#else
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_info);
#endif

    const char *evt_name = _event_name(type);

    if (m) {
        fprintf(stderr,
            "[NET %s] %s | RTT: %ums | Loss: %.1f%% | Details: %s\n",
            timebuf, evt_name,
            m->rtt_ms,
            m->packet_loss_rate * 100.0f,
            details ? details : "");
    } else {
        fprintf(stderr,
            "[NET %s] %s | Details: %s\n",
            timebuf, evt_name,
            details ? details : "");
    }
}
