#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "adaptive_engine.h"
#include "common.h"
#include "platform_compat.h"

static pthread_t   g_engine_thread;
static EngineState *g_state = NULL;
static Metrics     *g_metrics = NULL;
static int          g_running = 0;
static pthread_mutex_t g_state_lock = PTHREAD_MUTEX_INITIALIZER;

static time_t g_stable_since = 0;
#define STABLE_GRACE_SEC  30

void engine_apply_mode(EngineState *state, AdaptiveMode new_mode) {
    AdaptiveMode old_mode = state->mode;
    state->mode = new_mode;

    switch (new_mode) {
    case MODE_NORMAL:
        state->max_retries     = 3;
        state->retry_delay_ms  = 100;
        state->chunk_size      = MAX_MSG_LEN;
        state->use_udp_backup  = 1;
        state->force_padding   = 0;
        state->random_delay    = 0;
        state->dh_ratchet_freq = 10;
        break;
    case MODE_UNSTABLE:
        state->max_retries     = 7;
        state->retry_delay_ms  = 200;
        state->chunk_size      = 512;
        state->use_udp_backup  = 1;
        state->force_padding   = 0;
        state->random_delay    = 0;
        state->dh_ratchet_freq = 10;
        break;
    case MODE_HIGH_RISK:
        state->max_retries     = 10;
        state->retry_delay_ms  = 300;
        state->chunk_size      = 256;
        state->use_udp_backup  = 1;
        state->force_padding   = 1;
        state->random_delay    = 1;
        state->dh_ratchet_freq = 1;
        break;
    }

    if (new_mode > old_mode) {
        time_t now = time(NULL);
        char tbuf[32];
        struct tm *tm_info = localtime(&now);
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm_info);
        fprintf(stderr, "[ENGINE %s] mode %d → %d\n", tbuf, old_mode, new_mode);
        g_stable_since = 0;
    } else if (new_mode < old_mode) {
        fprintf(stderr, "[ENGINE] downgrade to mode %d\n", new_mode);
    }
}

void engine_evaluate(EngineState *state, const Metrics *metrics) {
    pthread_mutex_lock(&g_state_lock);

    AdaptiveMode target;

    if (metrics->auth_fail_count >= AUTH_FAIL_THRESHOLD ||
        metrics->replay_count    >= REPLAY_THRESHOLD    ||
        metrics->packet_loss_rate >= LOSS_THRESHOLD_HIGH_RISK) {
        target = MODE_HIGH_RISK;
    } else if (metrics->packet_loss_rate >= LOSS_THRESHOLD_UNSTABLE ||
               metrics->consecutive_timeouts >= 3) {
        target = MODE_UNSTABLE;
    } else {
        target = MODE_NORMAL;
    }

    if (target > state->mode) {
        /* Escalate immediately */
        g_stable_since = 0;
        engine_apply_mode(state, target);
    } else if (target < state->mode) {
        /* Require 30s of stability before downgrade */
        if (g_stable_since == 0)
            g_stable_since = time(NULL);
        else if (difftime(time(NULL), g_stable_since) >= STABLE_GRACE_SEC)
            engine_apply_mode(state, target);
    } else {
        g_stable_since = 0;
    }

    pthread_mutex_unlock(&g_state_lock);
}

AdaptiveMode engine_get_mode(const EngineState *state) {
    return state->mode;
}

static void *engine_thread_func(void *arg) {
    (void)arg;
    while (g_running) {
        if (g_state && g_metrics)
            engine_evaluate(g_state, g_metrics);
        sleep_ms(ENGINE_EVAL_INTERVAL_MS);
    }
    return NULL;
}

int engine_init(EngineState *state_out) {
    memset(state_out, 0, sizeof(*state_out));
    engine_apply_mode(state_out, MODE_NORMAL);
    g_state   = state_out;
    g_running = 1;

    if (pthread_create(&g_engine_thread, NULL, engine_thread_func, NULL) != 0) {
        perror("engine pthread_create");
        return -1;
    }
    pthread_detach(g_engine_thread);
    return 0;
}

void engine_set_metrics(Metrics *m) {
    g_metrics = m;
}

void engine_destroy(void) {
    g_running = 0;
}
