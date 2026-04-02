#include "adaptive_engine.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#define ENGINE_EVAL_INTERVAL_MS 1000
#define STABLE_DURATION_SEC 30

static pthread_mutex_t engine_mutex = PTHREAD_MUTEX_INITIALIZER;
static time_t last_mode_change = 0;

/* Initialize engine with default NORMAL mode settings */
int engine_init(EngineState *state_out) {
    if (!state_out) {
        return ERROR_GENERAL;
    }
    
    memset(state_out, 0, sizeof(EngineState));
    engine_apply_mode(state_out, MODE_NORMAL);
    last_mode_change = time(NULL);
    
    return SUCCESS;
}

/* Apply mode-specific configuration */
void engine_apply_mode(EngineState *state, AdaptiveMode new_mode) {
    if (!state) {
        return;
    }
    
    pthread_mutex_lock(&engine_mutex);
    
    state->mode = new_mode;
    
    switch (new_mode) {
        case MODE_NORMAL:
            state->max_retries = 3;
            state->retry_delay_ms = 100;
            state->chunk_size = MAX_MSG_LEN;
            state->use_udp_backup = 1;
            state->force_padding = 0;
            state->random_delay = 0;
            state->dh_ratchet_freq = 10;
            break;
            
        case MODE_UNSTABLE:
            state->max_retries = 7;
            state->retry_delay_ms = 200;
            state->chunk_size = 512;
            state->use_udp_backup = 1;
            state->force_padding = 0;
            state->random_delay = 0;
            state->dh_ratchet_freq = 10;
            break;
            
        case MODE_HIGH_RISK:
            state->max_retries = 10;
            state->retry_delay_ms = 250; /* Will be randomized in multipath */
            state->chunk_size = 256;
            state->use_udp_backup = 1;
            state->force_padding = 1;
            state->random_delay = 1;
            state->dh_ratchet_freq = 1;
            break;
    }
    
    pthread_mutex_unlock(&engine_mutex);
}

/* Evaluate metrics and transition modes */
void engine_evaluate(EngineState *state, const Metrics *metrics) {
    if (!state || !metrics) {
        return;
    }
    
    pthread_mutex_lock(&engine_mutex);
    
    AdaptiveMode current_mode = state->mode;
    AdaptiveMode new_mode = current_mode;
    time_t now = time(NULL);
    time_t time_since_change = now - last_mode_change;
    
    /* Determine target mode based on metrics */
    if (metrics->auth_fail_count >= AUTH_FAIL_THRESHOLD ||
        metrics->replay_count >= REPLAY_THRESHOLD ||
        metrics->packet_loss_rate >= LOSS_THRESHOLD_HIGH_RISK) {
        new_mode = MODE_HIGH_RISK;
    } else if (metrics->packet_loss_rate >= LOSS_THRESHOLD_UNSTABLE ||
               metrics->consecutive_timeouts >= 3) {
        new_mode = MODE_UNSTABLE;
    } else {
        new_mode = MODE_NORMAL;
    }
    
    /* Apply transition logic */
    if (new_mode > current_mode) {
        /* Upward transition: immediate */
        fprintf(stderr, "[Engine] Transitioning from %d to %d (threat detected)\n",
                current_mode, new_mode);
        engine_apply_mode(state, new_mode);
        last_mode_change = now;
    } else if (new_mode < current_mode) {
        /* Downward transition: require stable period */
        if (time_since_change >= STABLE_DURATION_SEC) {
            fprintf(stderr, "[Engine] Transitioning from %d to %d (stabilized)\n",
                    current_mode, new_mode);
            engine_apply_mode(state, new_mode);
            last_mode_change = now;
        }
    }
    
    pthread_mutex_unlock(&engine_mutex);
}

/* Get current mode (thread-safe) */
AdaptiveMode engine_get_mode(const EngineState *state) {
    if (!state) {
        return MODE_NORMAL;
    }
    
    pthread_mutex_lock((pthread_mutex_t *)&engine_mutex);
    AdaptiveMode mode = state->mode;
    pthread_mutex_unlock((pthread_mutex_t *)&engine_mutex);
    
    return mode;
}
