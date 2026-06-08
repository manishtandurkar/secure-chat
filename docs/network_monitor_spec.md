# Network Monitor Specification

## Purpose

`NetworkStats` tracks raw counters per-connection. `netmon_update_metrics()` converts them into the `Metrics` struct consumed by the Adaptive Engine.

## Counters

| Field | Updated by | Used for |
|-------|-----------|---------|
| `bytes_sent` / `bytes_recv` | Every send/recv call | Throughput monitoring |
| `packets_sent` / `packets_recv` | Every send/recv call | Packet rate |
| `packets_lost` | Failed TCP sends | Packet loss rate |
| `rtt_samples[16]` | RTT measurements | Smoothed RTT (ring buffer of 16) |

## Metrics Derivation

```c
packet_loss_rate = packets_lost / packets_sent
rtt_ms           = average of non-zero rtt_samples[]
```

These feed directly into `engine_evaluate()`:

| Metric | Threshold | Engine action |
|--------|-----------|---------------|
| `packet_loss_rate >= 0.05` | 5% loss | → MODE_UNSTABLE |
| `packet_loss_rate >= 0.20` | 20% loss | → MODE_HIGH_RISK |
| `auth_fail_count >= 5` | 5 failures | → MODE_HIGH_RISK |
| `replay_count >= 3` | 3 replays | → MODE_HIGH_RISK |
| `consecutive_timeouts >= 3` | 3 timeouts | → MODE_UNSTABLE |

## Thread Safety

All counter updates are protected by `netmon_lock` (pthread mutex). The engine reads metrics in its own thread via `engine_evaluate()`, which holds `g_state_lock` during evaluation.
