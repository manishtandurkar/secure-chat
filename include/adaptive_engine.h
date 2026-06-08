#ifndef ADAPTIVE_ENGINE_H
#define ADAPTIVE_ENGINE_H

#include <stdint.h>
#include "common.h"

typedef enum {
    MODE_NORMAL    = 0,
    MODE_UNSTABLE  = 1,
    MODE_HIGH_RISK = 2,
} AdaptiveMode;

typedef struct {
    AdaptiveMode mode;

    int max_retries;
    int retry_delay_ms;
    int chunk_size;
    int use_udp_backup;

    int force_padding;
    int random_delay;

    int dh_ratchet_freq;
} EngineState;

typedef struct {
    float    packet_loss_rate;
    uint32_t rtt_ms;
    uint32_t auth_fail_count;
    uint32_t replay_count;
    uint32_t consecutive_timeouts;
} Metrics;

int          engine_init(EngineState *state_out);
void         engine_evaluate(EngineState *state, const Metrics *metrics);
void         engine_apply_mode(EngineState *state, AdaptiveMode new_mode);
AdaptiveMode engine_get_mode(const EngineState *state);
void         engine_destroy(void);

void metrics_record_send(Metrics *m, int success);
void metrics_record_auth_fail(Metrics *m);
void metrics_record_replay(Metrics *m);
void metrics_record_rtt(Metrics *m, uint32_t rtt_ms);

#endif /* ADAPTIVE_ENGINE_H */
