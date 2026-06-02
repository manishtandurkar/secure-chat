# Network Intelligence Layer — Technical Specification

## Overview

The **Network Intelligence Layer** (`include/network_monitor.h`, `src/engine/network_monitor.c`) transforms the basic metrics collector into a comprehensive real-time monitoring subsystem for the Adaptive Secure Communication System.

It provides 15 monitoring capabilities operating concurrently with no external dependencies, no cloud connectivity, and full thread safety under a single `pthread_mutex_t nm_mutex`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Network Intelligence Layer                 │
│                                                             │
│  nm_record_jitter()      → JitterStats (current/avg/max)   │
│  nm_record_rtt_sample()  → RTT History (ring: 20 samples)  │
│  metrics_record_tx_bytes() → BandwidthStats (rolling 5s)   │
│  metrics_record_rx_bytes() → BandwidthStats (rolling 5s)   │
│  metrics_record_tcp_send() → TransportHealth [TCP]         │
│  metrics_record_udp_send() → TransportHealth [UDP]         │
│  metrics_record_delivery() → DeliveryStats                  │
│                                                             │
│  metrics_calculate_link_quality() → int 0-100              │
│  metrics_detect_congestion()      → int 0/1                │
│  metrics_get_trend()              → NetworkTrend enum       │
│  multipath_preferred_path()       → PreferredPath enum      │
│  metrics_emit_event()             → NetworkEvent ring[64]   │
│  metrics_get_dashboard()          → NetworkDashboard snap   │
│  metrics_log_network_event()      → stderr audit log        │
└──────────────────────────────────────┬──────────────────────┘
                                       │ (new Metrics fields)
                                       ▼
                         ┌─────────────────────────┐
                         │   Adaptive Engine        │
                         │  engine_evaluate()       │
                         │                          │
                         │  8 new escalation rules: │
                         │  • avg_jitter_ms         │
                         │  • link_quality_score    │
                         │  • congestion_detected   │
                         │  • delivery_success_ratio│
                         │  • tcp_health_score      │
                         │  • udp_health_score      │
                         └──────────────┬───────────┘
                                        │
                         ┌──────────────▼───────────┐
                         │   EngineState             │
                         │   NORMAL / UNSTABLE /    │
                         │   HIGH-RISK              │
                         └──────────────────────────┘
```

---

## Subsystem Specifications

### 1. Jitter Monitoring

**Definition:** Jitter = |RTT[n] - RTT[n-1]| (milliseconds)

**Integration:** Computed automatically inside `metrics_record_rtt()` using the Metrics struct's previous RTT value. Calls `nm_record_jitter(jitter_ms)` with no additional caller effort required.

**Statistics maintained:**
- `current_ms` — Most recent jitter sample
- `avg_ms` — Incremental rolling mean: `avg += (new - avg) / n`
- `max_ms` — All-time maximum
- `smoothed_ms` — Exponential Moving Average (EMA, α = 0.125)

**Escalation thresholds:**
| Smoothed Jitter | Engine Transition |
|---|---|
| > 50ms | → UNSTABLE |
| > 150ms | → HIGH-RISK (immediate) |

---

### 2. Bandwidth and Throughput Estimation

**Window:** 5-second rolling window (`BW_WINDOW_SEC = 5`).

**On window flush:**
```
tx_bytes_per_sec = window_tx_bytes / elapsed_seconds
rx_bytes_per_sec = window_rx_bytes / elapsed_seconds
total_throughput = tx_rate + rx_rate
avg_throughput   = EMA(total_throughput, α=0.125)
```

**Call sites:** `multipath.c` calls `metrics_record_tx_bytes(payload_len)` after every successful send.

---

### 3–4. Per-Path TCP and UDP Health Scores

Each transport path is independently tracked with a `TransportHealth` struct.

**Health score formula (0–100):**
```
base_score = success_rate × 80       /* Success is the primary factor */
lat_score  = 20 - min(avg_latency_ms / 25, 20)  /* 0ms=20pts, 500ms=0pts */
health     = base_score + lat_score
```

- TCP: TLS round-trip latency measured with `clock_gettime(CLOCK_MONOTONIC)`
- UDP: Best-effort datagram latency measured similarly

**Integration:** `multipath.c` injects `metrics_record_tcp_send()` and `metrics_record_udp_send()` inside the retry loop.

---

### 5. Link Quality Score (0–100)

Composite score aggregating all available signal quality indicators.

**Formula:**
```
score = 100
      − (packet_loss_rate × 40)         [0%→0,  100%→40]
      − min(rtt_ms / 25, 20)            [0ms→0, 500ms→20]
      − min(jitter_smoothed / 13.33, 15)[0ms→0, 200ms→15]
      − min(consecutive_timeouts, 10)   [0→0,   10+→10]
      − (1 - tcp_health) × 0.10         [up to 10]
      − (1 - udp_health) × 0.05         [up to 5]
```

Total = 100 points. Clamped to [0, 100].

**Escalation thresholds:**
| Score | Engine Transition |
|---|---|
| < 50 | → UNSTABLE |
| < 30 | → HIGH-RISK (immediate) |

---

### 6. Congestion Detection

**Algorithm:** RTT trend analysis over a sliding window of the last 20 samples.

Walk backwards through the RTT history ring buffer. Count **consecutive** samples where each is more than 10% higher than the previous:

```c
if (newer > older + (older / 10)) {
    consecutive_rising++;
} else {
    break;  /* Chain broken */
}
```

**Trigger:** `CONGESTION_TRIGGER_COUNT = 5` consecutive rising samples → `congestion_detected = 1`

**Clear:** A single non-rising sample breaks the chain → `congestion_detected = 0`

---

### 7. Trend Analysis (1-min / 5-min / 15-min)

Three EMA buckets updated on every RTT sample:

| Window | Alpha Formula |
|---|---|
| 1-minute | `ema += (rtt - ema) / 60` |
| 5-minute | `ema += (rtt - ema) / 300` |
| 15-minute | `ema += (rtt - ema) / 900` |

**Trend classification:**
```
ratio = ema_1min / ema_5min
IMPROVING  if ratio < 0.90   (10%+ better than 5-min average)
DEGRADING  if ratio > 1.10   (10%+ worse than 5-min average)
STABLE     otherwise
```

---

### 8. Delivery Success Ratio Tracking

Tracks confirmed message delivery vs. total dispatched.

**Metrics:**
- `messages_sent` — incremented on every `multipath_send` call
- `messages_delivered` — incremented only on confirmed delivery (at least one path succeeded after all retries)
- `current_ratio = delivered / sent`
- `avg_ratio` — EMA-smoothed (α=0.125)

**Escalation thresholds:**
| Ratio | Engine Transition |
|---|---|
| < 80% | → UNSTABLE |
| < 60% | → HIGH-RISK (immediate) |

---

### 9. Network Event Framework

A ring buffer of the last 64 `NetworkEvent` structs, each containing:
- `timestamp` — Unix epoch
- `type` — `NetworkEventType` enum (12 event types)
- `packet_loss`, `rtt_ms`, `jitter_ms`, `link_quality` — metric snapshot
- `details[128]` — human-readable description

**Emit:** `metrics_emit_event(type, details, metrics)` — also writes a structured stderr audit log line.

**Retrieve:** `metrics_get_events(out, max_count)` — copies events oldest-first.

---

### 10. Dashboard Snapshot API

`metrics_get_dashboard(NetworkDashboard *out, Metrics *m, AdaptiveMode mode)`

Atomically copies the complete monitoring state into a caller-allocated `NetworkDashboard` struct. Thread-safe for UI integration (GTK client). Includes the last 16 events, jitter, bandwidth, transport health, link quality, trend, delivery stats, and engine mode.

---

### 11. Multipath Path Preference

`multipath_preferred_path()` returns `PATH_TCP`, `PATH_UDP`, or `PATH_BOTH` based on live health scores:

| Condition | Preference |
|---|---|
| Both scores ≥ 70 | `PATH_BOTH` (dual-path strategy) |
| UDP score < 30, TCP ≥ 50 | `PATH_TCP` |
| TCP score < 30, UDP ≥ 50 | `PATH_UDP` |
| Default | `PATH_TCP` (TLS authentication advantage) |

This does **not** disable the non-preferred path — it only determines the order of send attempts within the retry loop.

---

### 12. Structured Network Audit Logging

All event emissions and major network state transitions are logged to stderr with the format:

```
[NET 2026-06-02 07:43:35] HIGH_JITTER | RTT: 120ms | Loss: 5.0% | Details: <message>
[NET 2026-06-02 07:43:35] CONGESTION_DETECTED | RTT: 50ms | Loss: 0.0% | Details: RTT rising
```

---

### 13. Adaptive Engine Integration (8 New Escalation Rules)

`engine_evaluate()` now accepts `Metrics *` (non-const) and refreshes all network intelligence fields at the start of each evaluation cycle before evaluating escalation conditions:

```c
/* Fields populated by engine_evaluate before evaluation */
metrics->avg_jitter_ms          /* from JitterStats.smoothed_ms */
metrics->tcp_health_score       /* from TransportHealth.health_score */
metrics->udp_health_score       /* from TransportHealth.health_score */
metrics->delivery_success_ratio /* from DeliveryStats.current_ratio */
metrics->congestion_detected    /* from metrics_detect_congestion() */
metrics->link_quality_score     /* from metrics_calculate_link_quality() */
```

---

## Thread Safety Model

Single mutex `nm_mutex` (POSIX `pthread_mutex_t`) guards all internal state in `network_monitor.c`.

**Lock order:** No lock nesting occurs. The `engine_evaluate` function temporarily releases `engine_mutex` before calling `metrics_detect_congestion()` and `metrics_calculate_link_quality()` (which acquire `nm_mutex`) to prevent potential deadlock.

**Contention:** Lock hold time is O(1) for all recording functions. Only `metrics_get_dashboard()` and congestion/trend computation hold the lock for O(N) where N ≤ 20 (RTT history window).

---

## API Summary

| Function | File | Purpose |
|---|---|---|
| `nm_record_jitter(ms)` | `network_monitor.c` | Feed raw jitter sample |
| `nm_record_rtt_sample(ms)` | `network_monitor.c` | Feed RTT into history/EMA |
| `metrics_record_tx_bytes(n)` | `network_monitor.c` | Track TX bandwidth |
| `metrics_record_rx_bytes(n)` | `network_monitor.c` | Track RX bandwidth |
| `metrics_record_tcp_send(ok, lat)` | `network_monitor.c` | TCP path health |
| `metrics_record_udp_send(ok, lat)` | `network_monitor.c` | UDP path health |
| `metrics_record_tcp_recv(ok)` | `network_monitor.c` | TCP receive health |
| `metrics_record_udp_recv(ok)` | `network_monitor.c` | UDP receive health |
| `metrics_record_delivery(ok)` | `network_monitor.c` | Delivery ratio |
| `metrics_calculate_link_quality(m)` | `network_monitor.c` | Composite score |
| `metrics_detect_congestion()` | `network_monitor.c` | RTT trend congestion |
| `metrics_get_trend()` | `network_monitor.c` | 1m/5m/15m trend |
| `multipath_preferred_path()` | `network_monitor.c` | Path selector |
| `metrics_emit_event(type,det,m)` | `network_monitor.c` | Emit network event |
| `metrics_get_events(out, n)` | `network_monitor.c` | Retrieve events |
| `metrics_get_dashboard(out,m,mode)` | `network_monitor.c` | Full snapshot |
| `metrics_get_jitter_snapshot(out)` | `network_monitor.c` | Jitter copy |
| `metrics_get_bandwidth_snapshot(out)` | `network_monitor.c` | Bandwidth copy |
| `metrics_get_tcp_health_snapshot(out)` | `network_monitor.c` | TCP health copy |
| `metrics_get_udp_health_snapshot(out)` | `network_monitor.c` | UDP health copy |
| `metrics_get_delivery_snapshot(out)` | `network_monitor.c` | Delivery copy |
| `metrics_log_network_event(t,det,m)` | `network_monitor.c` | Audit log |
