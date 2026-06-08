#include <string.h>
#include <pthread.h>
#include "adaptive_engine.h"

static pthread_mutex_t metrics_lock = PTHREAD_MUTEX_INITIALIZER;

/* Rolling send buffer for packet loss calculation */
#define SEND_WINDOW 100
static int   send_results[SEND_WINDOW];
static int   send_idx = 0;
static int   send_filled = 0;

void metrics_record_send(Metrics *m, int success) {
    pthread_mutex_lock(&metrics_lock);

    send_results[send_idx] = success ? 1 : 0;
    send_idx = (send_idx + 1) % SEND_WINDOW;
    if (!send_filled && send_idx == 0) send_filled = 1;

    int window = send_filled ? SEND_WINDOW : send_idx;
    int lost = 0;
    for (int i = 0; i < window; i++)
        if (!send_results[i]) lost++;

    m->packet_loss_rate = (window > 0) ? (float)lost / (float)window : 0.0f;

    if (!success)
        m->consecutive_timeouts++;
    else
        m->consecutive_timeouts = 0;

    pthread_mutex_unlock(&metrics_lock);
}

void metrics_record_auth_fail(Metrics *m) {
    pthread_mutex_lock(&metrics_lock);
    m->auth_fail_count++;
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_record_replay(Metrics *m) {
    pthread_mutex_lock(&metrics_lock);
    m->replay_count++;
    pthread_mutex_unlock(&metrics_lock);
}

void metrics_record_rtt(Metrics *m, uint32_t rtt_ms) {
    pthread_mutex_lock(&metrics_lock);
    /* Exponential moving average */
    if (m->rtt_ms == 0)
        m->rtt_ms = rtt_ms;
    else
        m->rtt_ms = (m->rtt_ms * 7 + rtt_ms) / 8;
    pthread_mutex_unlock(&metrics_lock);
}
