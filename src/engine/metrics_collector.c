#include "adaptive_engine.h"
#include <pthread.h>
#include <string.h>

#define METRICS_WINDOW 100

static pthread_mutex_t metrics_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Track last N send results for packet loss calculation */
static int send_results[METRICS_WINDOW] = {0};
static int send_index = 0;
static int total_sends = 0;

/* Record send result for packet loss calculation */
void metrics_record_send(Metrics *m, int success) {
    if (!m) {
        return;
    }
    
    pthread_mutex_lock(&metrics_mutex);
    
    /* Update circular buffer */
    send_results[send_index] = success ? 1 : 0;
    send_index = (send_index + 1) % METRICS_WINDOW;
    total_sends++;
    
    /* Calculate packet loss rate */
    int successful = 0;
    int window_size = (total_sends < METRICS_WINDOW) ? total_sends : METRICS_WINDOW;
    
    for (int i = 0; i < window_size; i++) {
        if (send_results[i]) {
            successful++;
        }
    }
    
    m->packet_loss_rate = 1.0f - ((float)successful / (float)window_size);
    
    /* Update timeout counter */
    if (!success) {
        m->consecutive_timeouts++;
    } else {
        m->consecutive_timeouts = 0;
    }
    
    pthread_mutex_unlock(&metrics_mutex);
}

/* Record authentication failure */
void metrics_record_auth_fail(Metrics *m) {
    if (!m) {
        return;
    }
    
    pthread_mutex_lock(&metrics_mutex);
    m->auth_fail_count++;
    pthread_mutex_unlock(&metrics_mutex);
}

/* Record replay attack detection */
void metrics_record_replay(Metrics *m) {
    if (!m) {
        return;
    }
    
    pthread_mutex_lock(&metrics_mutex);
    m->replay_count++;
    pthread_mutex_unlock(&metrics_mutex);
}

/* Record round-trip time with smoothing */
void metrics_record_rtt(Metrics *m, uint32_t rtt_ms) {
    if (!m) {
        return;
    }
    
    pthread_mutex_lock(&metrics_mutex);
    
    /* Exponential moving average: smoothed_rtt = 0.875 * old + 0.125 * new */
    if (m->rtt_ms == 0) {
        m->rtt_ms = rtt_ms;
    } else {
        m->rtt_ms = (m->rtt_ms * 7 + rtt_ms) / 8;
    }
    
    pthread_mutex_unlock(&metrics_mutex);
}
