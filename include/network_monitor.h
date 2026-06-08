#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <stdint.h>
#include "adaptive_engine.h"

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint32_t packets_sent;
    uint32_t packets_recv;
    uint32_t packets_lost;
    uint32_t rtt_samples[16];
    int      rtt_idx;
} NetworkStats;

void netmon_init(NetworkStats *stats);
void netmon_record_send(NetworkStats *stats, size_t bytes, int success);
void netmon_record_recv(NetworkStats *stats, size_t bytes);
void netmon_record_rtt(NetworkStats *stats, uint32_t rtt_ms);
void netmon_update_metrics(const NetworkStats *stats, Metrics *metrics);

#endif /* NETWORK_MONITOR_H */
