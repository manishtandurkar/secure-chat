/**
 * network_monitor.h — Network Intelligence Layer
 *
 * Provides real-time visibility into connection quality, transport health,
 * congestion conditions, and network stability for the Adaptive Secure Chat system.
 *
 * Complements the existing adaptive_engine.h/metrics_collector.c pair with:
 *   - Jitter monitoring (current, average, max, smoothed)
 *   - Bandwidth and throughput estimation (TX/RX bytes/sec)
 *   - Per-path TCP and UDP health scores
 *   - Composite link quality score (0–100)
 *   - Congestion detection via RTT trend analysis
 *   - Rolling trend analysis (1-min / 5-min / 15-min)
 *   - Delivery success ratio tracking
 *   - Structured network event framework
 *   - Dashboard snapshot API for GTK GUI integration
 *   - Preferred multipath selector
 *
 * Thread safety: All public API functions are thread-safe.
 */

#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include "common.h"
#include "adaptive_engine.h"
#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

/* Jitter thresholds (ms) */
#define JITTER_THRESHOLD_UNSTABLE   50   /* > 50ms avg jitter → Unstable */
#define JITTER_THRESHOLD_HIGH_RISK  150  /* > 150ms avg jitter → HighRisk */

/* Link quality score thresholds */
#define LINK_QUALITY_DEGRADED       50   /* < 50 → Unstable */
#define LINK_QUALITY_POOR           30   /* < 30 → HighRisk */

/* Delivery ratio thresholds */
#define DELIVERY_RATIO_WARN         0.80f  /* < 80% → Unstable */
#define DELIVERY_RATIO_CRITICAL     0.60f  /* < 60% → HighRisk */

/* Dual-transport failure threshold */
#define TRANSPORT_HEALTH_CRITICAL   30   /* Both paths < 30 → HighRisk */

/* RTT congestion window (consecutive rising samples trigger detection) */
#define CONGESTION_RTT_WINDOW       20   /* Keep last N RTT samples */
#define CONGESTION_TRIGGER_COUNT    5    /* 5 consecutive rising samples = congestion */

/* Trend analysis */
#define TREND_IMPROVE_RATIO         0.90f  /* 10% improvement */
#define TREND_DEGRADE_RATIO         1.10f  /* 10% degradation */

/* Network event ring buffer capacity */
#define NET_EVENT_RING_SIZE         64

/* Bandwidth measurement window (seconds) */
#define BW_WINDOW_SEC               5

/* =========================================================================
 * Enumerations
 * ========================================================================= */

/**
 * Network trend relative to historical baseline.
 */
typedef enum {
    NETWORK_IMPROVING = 0,
    NETWORK_STABLE    = 1,
    NETWORK_DEGRADING = 2,
} NetworkTrend;

/**
 * Network and transport event types for the event framework.
 */
typedef enum {
    NET_EVENT_HEALTHY              = 0,
    NET_EVENT_DEGRADED             = 1,
    NET_EVENT_HIGH_JITTER          = 2,
    NET_EVENT_CONGESTION_DETECTED  = 3,
    NET_EVENT_LINK_FAILURE         = 4,
    NET_EVENT_TRANSPORT_FAILURE    = 5,
    NET_EVENT_TRANSPORT_RECOVERED  = 6,
    NET_EVENT_NETWORK_RECOVERED    = 7,
    NET_EVENT_HIGH_PACKET_LOSS     = 8,
    NET_EVENT_HIGH_RTT             = 9,
    NET_EVENT_ENGINE_ESCALATION    = 10,
    NET_EVENT_DELIVERY_WARN        = 11,
} NetworkEventType;

/**
 * Preferred multipath send path derived from per-path health scores.
 */
typedef enum {
    PATH_TCP  = 0,
    PATH_UDP  = 1,
    PATH_BOTH = 2,   /* Both healthy — use dual-path strategy */
} PreferredPath;

/* =========================================================================
 * Data Structures
 * ========================================================================= */

/**
 * Jitter statistics.
 * Jitter = |RTT[n] - RTT[n-1]|, measured in milliseconds.
 */
typedef struct {
    uint32_t current_ms;    /* Most recently measured jitter sample */
    uint32_t avg_ms;        /* Simple rolling average */
    uint32_t max_ms;        /* Maximum observed jitter */
    uint32_t smoothed_ms;   /* Exponential moving average (alpha=0.125) */
    uint64_t sample_count;  /* Total samples collected */
} JitterStats;

/**
 * Bandwidth and throughput estimation.
 * Rates are calculated over a rolling BW_WINDOW_SEC window.
 */
typedef struct {
    uint64_t bytes_sent_total;      /* Cumulative bytes transmitted */
    uint64_t bytes_recv_total;      /* Cumulative bytes received */
    uint64_t messages_sent_total;   /* Cumulative messages transmitted */
    uint64_t messages_recv_total;   /* Cumulative messages received */
    float    tx_bytes_per_sec;      /* Current TX rate */
    float    rx_bytes_per_sec;      /* Current RX rate */
    float    total_throughput_bps;  /* tx + rx rate */
    float    avg_throughput_bps;    /* Smoothed total throughput */
} BandwidthStats;

/**
 * Per-transport-path health statistics.
 * Used separately for TCP and UDP paths.
 */
typedef struct {
    uint64_t sends;             /* Total send attempts */
    uint64_t recvs;             /* Total successful receives */
    uint64_t failures;          /* Failed send/recv operations */
    uint64_t retries;           /* Retry count */
    uint32_t avg_latency_ms;    /* Smoothed per-path latency */
    float    success_rate;      /* [0.0, 1.0] */
    float    failure_rate;      /* [0.0, 1.0] */
    int      health_score;      /* Composite 0–100 score */
} TransportHealth;

/**
 * Message delivery tracking.
 */
typedef struct {
    uint64_t messages_sent;       /* Total messages dispatched */
    uint64_t messages_delivered;  /* Confirmed delivered messages */
    float    current_ratio;       /* delivered / sent */
    float    avg_ratio;           /* Smoothed delivery ratio */
} DeliveryStats;

/**
 * A single structured network event with timestamp and metric snapshot.
 */
typedef struct {
    time_t          timestamp;
    NetworkEventType type;
    float           packet_loss;     /* Snapshot at event time */
    uint32_t        rtt_ms;
    uint32_t        jitter_ms;
    int             link_quality;
    char            details[128];    /* Human-readable description */
} NetworkEvent;

/**
 * Central dashboard — complete real-time snapshot of network intelligence state.
 * Designed for clean GTK GUI integration via metrics_get_dashboard().
 */
typedef struct {
    /* RTT */
    uint32_t         rtt_current_ms;
    uint32_t         rtt_avg_ms;

    /* Jitter */
    JitterStats      jitter;

    /* Packet loss */
    float            packet_loss_rate;

    /* Transport paths */
    TransportHealth  tcp;
    TransportHealth  udp;

    /* Bandwidth */
    BandwidthStats   bandwidth;

    /* Quality signals */
    int              link_quality_score;  /* 0–100 */
    NetworkTrend     trend;
    int              congestion_detected; /* 0 or 1 */

    /* Delivery */
    DeliveryStats    delivery;

    /* Engine mode */
    AdaptiveMode     engine_mode;

    /* Recent events */
    NetworkEvent     recent_events[16];
    int              event_count;         /* Number valid in recent_events */

    /* Timestamp of this snapshot */
    time_t           snapshot_time;
} NetworkDashboard;

/* =========================================================================
 * Recording APIs — called from metrics_collector.c and multipath.c
 * ========================================================================= */

/**
 * Record a new jitter sample (|new_rtt - prev_rtt|).
 * Called automatically from within metrics_record_rtt().
 */
void nm_record_jitter(uint32_t jitter_ms);

/**
 * Feed a raw RTT sample into the RTT history ring buffer.
 * Used by congestion detector and trend analyzer.
 * Called automatically from within metrics_record_rtt().
 */
void nm_record_rtt_sample(uint32_t rtt_ms);

/**
 * Record bytes transmitted on any path.
 * Updates rolling TX throughput.
 */
void metrics_record_tx_bytes(size_t bytes);

/**
 * Record bytes received on any path.
 * Updates rolling RX throughput.
 */
void metrics_record_rx_bytes(size_t bytes);

/**
 * Record a TCP send attempt result and optional per-send latency.
 * @param success  1 = successful, 0 = failed
 * @param latency_ms  Round-trip or one-way latency in ms (0 = unknown)
 */
void metrics_record_tcp_send(int success, uint32_t latency_ms);

/**
 * Record a TCP receive event.
 * @param success  1 = data received, 0 = receive error
 */
void metrics_record_tcp_recv(int success);

/**
 * Record a UDP send attempt result and optional latency.
 */
void metrics_record_udp_send(int success, uint32_t latency_ms);

/**
 * Record a UDP receive event.
 */
void metrics_record_udp_recv(int success);

/**
 * Record a message delivery outcome.
 * @param delivered  1 = confirmed delivery, 0 = unconfirmed/lost
 */
void metrics_record_delivery(int delivered);

/* =========================================================================
 * Query APIs — called from adaptive_engine.c and display layers
 * ========================================================================= */

/**
 * Compute the composite link quality score (0–100).
 * Considers: packet loss, RTT, jitter, timeouts, TCP health, UDP health.
 * Higher = better quality.
 */
int metrics_calculate_link_quality(const Metrics *m);

/**
 * Check if congestion is currently detected based on RTT trend.
 * Returns 1 if CONGESTION_DETECTED, 0 otherwise.
 */
int metrics_detect_congestion(void);

/**
 * Determine the current network trend from rolling history windows.
 * Returns NETWORK_IMPROVING, NETWORK_STABLE, or NETWORK_DEGRADING.
 */
NetworkTrend metrics_get_trend(void);

/**
 * Return preferred multipath path based on TCP vs UDP health scores.
 * Does NOT disable the non-preferred path — only ordering preference.
 */
PreferredPath multipath_preferred_path(void);

/**
 * Emit a structured network event into the event ring buffer.
 * Also writes a formatted audit log line to stderr.
 * @param m  Optional current Metrics snapshot (may be NULL)
 */
void metrics_emit_event(NetworkEventType type, const char *details,
                        const Metrics *m);

/**
 * Copy up to max_count recent events into the caller-provided array.
 * Returns the actual number of events copied.
 */
int metrics_get_events(NetworkEvent *out, int max_count);

/**
 * Atomically populate a NetworkDashboard snapshot.
 * Safe to call from the UI thread.
 */
void metrics_get_dashboard(NetworkDashboard *out, const Metrics *m,
                           AdaptiveMode mode);

/**
 * Read-only access to jitter statistics. Caller must NOT write to the pointer.
 * Returns a static pointer — valid until the next call on any thread.
 * (Prefer metrics_get_dashboard for multi-field reads.)
 */
void metrics_get_jitter_snapshot(JitterStats *out);

/**
 * Read-only access to bandwidth statistics.
 */
void metrics_get_bandwidth_snapshot(BandwidthStats *out);

/**
 * Read-only access to TCP transport health.
 */
void metrics_get_tcp_health_snapshot(TransportHealth *out);

/**
 * Read-only access to UDP transport health.
 */
void metrics_get_udp_health_snapshot(TransportHealth *out);

/**
 * Read-only access to delivery statistics.
 */
void metrics_get_delivery_snapshot(DeliveryStats *out);

/**
 * Write a structured network audit log entry to stderr.
 * Format: [NET <timestamp>] <EVENT_TYPE> | RTT: <rtt>ms | Jitter: <jitter>ms
 *         | Loss: <loss>% | Quality: <quality> | Details: <details>
 */
void metrics_log_network_event(NetworkEventType type, const char *details,
                               const Metrics *m);

#endif /* NETWORK_MONITOR_H */
