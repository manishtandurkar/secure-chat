#ifndef ADAPTIVE_ENGINE_H
#define ADAPTIVE_ENGINE_H

#include "common.h"
#include <stdint.h>

/* Adaptive mode enum */
typedef enum {
    MODE_NORMAL    = 0,
    MODE_UNSTABLE  = 1,
    MODE_HIGH_RISK = 2,
} AdaptiveMode;

/* Engine state struct */
typedef struct {
    AdaptiveMode mode;

    /* Transport config (read by multipath.c) */
    int     max_retries;       /* Normal: 3 | Unstable: 7 | HighRisk: 10 */
    int     retry_delay_ms;    /* Normal: 100 | Unstable: 200 | HighRisk: random(100,500) */
    int     chunk_size;        /* Normal: MAX_MSG_LEN | Unstable: 512 | HighRisk: 256 */
    int     use_udp_backup;    /* Normal: 1 | Unstable: 1 | HighRisk: 1 */

    /* Privacy config (read by multipath.c and aes_utils.c) */
    int     force_padding;     /* Normal: 0 | Unstable: 0 | HighRisk: 1 */
    int     random_delay;      /* Normal: 0 | Unstable: 0 | HighRisk: 1 */

    /* Crypto config (read by ratchet.c) */
    int     dh_ratchet_freq;   /* Normal: every 10 msgs | HighRisk: every msg */
} EngineState;

/* Metrics struct */
typedef struct {
    float    packet_loss_rate;    /* Rolling average over last 100 sends */
    uint32_t rtt_ms;              /* Smoothed round-trip time */
    uint32_t auth_fail_count;     /* Failures since last reset */
    uint32_t replay_count;        /* Replay detections since last reset */
    uint32_t consecutive_timeouts;
} Metrics;

/**
 * Initialize engine. Spawns background evaluation thread.
 * state_out written to shared memory segment for all children.
 * Returns 0 or -1.
 */
int engine_init(EngineState *state_out);

/**
 * Called by background thread every ENGINE_EVAL_INTERVAL_MS.
 * Reads current metrics, evaluates transitions, updates state.
 */
void engine_evaluate(EngineState *state, const Metrics *metrics);

/**
 * Apply mode-specific configuration to state.
 */
void engine_apply_mode(EngineState *state, AdaptiveMode new_mode);

/**
 * Query current mode. Thread-safe (atomic read).
 */
AdaptiveMode engine_get_mode(const EngineState *state);

/**
 * Update a specific metric. Thread-safe.
 */
void metrics_record_send(Metrics *m, int success);
void metrics_record_auth_fail(Metrics *m);
void metrics_record_replay(Metrics *m);
void metrics_record_rtt(Metrics *m, uint32_t rtt_ms);

#endif /* ADAPTIVE_ENGINE_H */
