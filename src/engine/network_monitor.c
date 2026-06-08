#include <string.h>
#include <pthread.h>
#include "network_monitor.h"

static pthread_mutex_t netmon_lock = PTHREAD_MUTEX_INITIALIZER;

void netmon_init(NetworkStats *stats) {
    memset(stats, 0, sizeof(*stats));
}

void netmon_record_send(NetworkStats *stats, size_t bytes, int success) {
    pthread_mutex_lock(&netmon_lock);
    stats->bytes_sent += bytes;
    stats->packets_sent++;
    if (!success) stats->packets_lost++;
    pthread_mutex_unlock(&netmon_lock);
}

void netmon_record_recv(NetworkStats *stats, size_t bytes) {
    pthread_mutex_lock(&netmon_lock);
    stats->bytes_recv += bytes;
    stats->packets_recv++;
    pthread_mutex_unlock(&netmon_lock);
}

void netmon_record_rtt(NetworkStats *stats, uint32_t rtt_ms) {
    pthread_mutex_lock(&netmon_lock);
    stats->rtt_samples[stats->rtt_idx] = rtt_ms;
    stats->rtt_idx = (stats->rtt_idx + 1) % 16;
    pthread_mutex_unlock(&netmon_lock);
}

void netmon_update_metrics(const NetworkStats *stats, Metrics *metrics) {
    pthread_mutex_lock(&netmon_lock);
    if (stats->packets_sent > 0)
        metrics->packet_loss_rate = (float)stats->packets_lost / (float)stats->packets_sent;

    uint32_t rtt_sum = 0, rtt_cnt = 0;
    for (int i = 0; i < 16; i++) {
        if (stats->rtt_samples[i] > 0) {
            rtt_sum += stats->rtt_samples[i];
            rtt_cnt++;
        }
    }
    if (rtt_cnt > 0)
        metrics->rtt_ms = rtt_sum / rtt_cnt;
    pthread_mutex_unlock(&netmon_lock);
}
