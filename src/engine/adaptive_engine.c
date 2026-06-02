#include "adaptive_engine.h"
#include "intrusion.h"
#include "network_monitor.h"
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
}

/* Evaluate metrics and transition modes */
void engine_evaluate(EngineState *state, Metrics *metrics) {
    if (!state || !metrics) {
        return;
    }
    
    pthread_mutex_lock(&engine_mutex);
    
    /* --- Refresh Network Intelligence fields from network_monitor --- */
    {
        JitterStats js;
        metrics_get_jitter_snapshot(&js);
        metrics->avg_jitter_ms = (float)js.smoothed_ms;
        
        TransportHealth tcp_h, udp_h;
        metrics_get_tcp_health_snapshot(&tcp_h);
        metrics_get_udp_health_snapshot(&udp_h);
        metrics->tcp_health_score = tcp_h.health_score;
        metrics->udp_health_score = udp_h.health_score;
        
        DeliveryStats ds;
        metrics_get_delivery_snapshot(&ds);
        metrics->delivery_success_ratio = (ds.messages_sent > 0)
                                         ? ds.current_ratio : 1.0f;
        
        metrics->congestion_detected = 0; /* Compute after unlock to avoid deadlock */
    }
    
    /* Unlock briefly to allow congestion + link quality computation
       (those functions acquire nm_mutex internally) */
    pthread_mutex_unlock(&engine_mutex);
    
    metrics->congestion_detected = metrics_detect_congestion();
    metrics->link_quality_score  = metrics_calculate_link_quality(metrics);
    
    pthread_mutex_lock(&engine_mutex);
    
    AdaptiveMode current_mode = state->mode;
    AdaptiveMode new_mode     = current_mode;
    time_t now                = time(NULL);
    time_t time_since_change  = now - last_mode_change;
    
    /* Determine target mode based on all metrics */
    int max_threat_score = ids_get_max_threat_score();
    
    /* ----------------------------------------------------------------
     * HIGH-RISK conditions (check first — take precedence)
     * ---------------------------------------------------------------- */
    int is_high_risk = 0;
    
    /* Legacy: auth/replay/packet-loss/threat-score */
    if (metrics->auth_fail_count >= AUTH_FAIL_THRESHOLD ||
        metrics->replay_count    >= REPLAY_THRESHOLD ||
        metrics->packet_loss_rate >= LOSS_THRESHOLD_HIGH_RISK ||
        max_threat_score >= 100) {
        is_high_risk = 1;
        if (max_threat_score >= 100 && current_mode != MODE_HIGH_RISK) {
            ids_log_event_ex("ENGINE_ESCALATION", "global", max_threat_score,
                             "Escalating to HIGH-RISK: threat score threshold");
        }
    }
    
    /* Network: severe jitter */
    if (metrics->avg_jitter_ms > (float)JITTER_THRESHOLD_HIGH_RISK) {
        is_high_risk = 1;
        if (current_mode != MODE_HIGH_RISK) {
            char det[128];
            snprintf(det, sizeof(det), "Jitter=%.0fms exceeds HIGH-RISK threshold %dms",
                     metrics->avg_jitter_ms, JITTER_THRESHOLD_HIGH_RISK);
            metrics_emit_event(NET_EVENT_HIGH_JITTER, det, metrics);
        }
    }
    
    /* Network: link quality critically low */
    if (metrics->link_quality_score < LINK_QUALITY_POOR) {
        is_high_risk = 1;
        if (current_mode != MODE_HIGH_RISK) {
            char det[128];
            snprintf(det, sizeof(det), "Link quality=%d below POOR threshold %d",
                     metrics->link_quality_score, LINK_QUALITY_POOR);
            metrics_emit_event(NET_EVENT_LINK_FAILURE, det, metrics);
        }
    }
    
    /* Network: delivery ratio critically low */
    if (metrics->delivery_success_ratio < DELIVERY_RATIO_CRITICAL &&
        metrics->delivery_success_ratio > 0.0f) {
        is_high_risk = 1;
        if (current_mode != MODE_HIGH_RISK) {
            char det[128];
            snprintf(det, sizeof(det), "Delivery ratio=%.1f%% below CRITICAL threshold %.0f%%",
                     metrics->delivery_success_ratio * 100.0f,
                     DELIVERY_RATIO_CRITICAL * 100.0f);
            metrics_emit_event(NET_EVENT_DELIVERY_WARN, det, metrics);
        }
    }
    
    /* Network: both transports failing */
    if (metrics->tcp_health_score < TRANSPORT_HEALTH_CRITICAL &&
        metrics->udp_health_score < TRANSPORT_HEALTH_CRITICAL &&
        (metrics->tcp_health_score + metrics->udp_health_score) > 0) {
        is_high_risk = 1;
        if (current_mode != MODE_HIGH_RISK) {
            char det[128];
            snprintf(det, sizeof(det),
                     "Both transports critical: TCP=%d UDP=%d",
                     metrics->tcp_health_score, metrics->udp_health_score);
            metrics_emit_event(NET_EVENT_TRANSPORT_FAILURE, det, metrics);
        }
    }
    
    if (is_high_risk) {
        new_mode = MODE_HIGH_RISK;
    }
    
    /* ----------------------------------------------------------------
     * UNSTABLE conditions (only if not already HIGH_RISK)
     * ---------------------------------------------------------------- */
    if (!is_high_risk) {
        int is_unstable = 0;
        
        /* Legacy: packet loss / timeouts / threat score */
        if (metrics->packet_loss_rate >= LOSS_THRESHOLD_UNSTABLE ||
            metrics->consecutive_timeouts >= 3 ||
            max_threat_score >= 50) {
            is_unstable = 1;
            if (max_threat_score >= 50 && current_mode < MODE_UNSTABLE) {
                ids_log_event_ex("ENGINE_ESCALATION", "global", max_threat_score,
                                 "Escalating to UNSTABLE: threat score threshold");
            }
        }
        
        /* Network: elevated jitter */
        if (metrics->avg_jitter_ms > (float)JITTER_THRESHOLD_UNSTABLE) {
            is_unstable = 1;
            if (current_mode < MODE_UNSTABLE) {
                char det[128];
                snprintf(det, sizeof(det), "Jitter=%.0fms exceeds UNSTABLE threshold %dms",
                         metrics->avg_jitter_ms, JITTER_THRESHOLD_UNSTABLE);
                metrics_emit_event(NET_EVENT_HIGH_JITTER, det, metrics);
            }
        }
        
        /* Network: degraded link quality */
        if (metrics->link_quality_score < LINK_QUALITY_DEGRADED &&
            metrics->link_quality_score > 0) {
            is_unstable = 1;
            if (current_mode < MODE_UNSTABLE) {
                char det[128];
                snprintf(det, sizeof(det), "Link quality=%d below DEGRADED threshold %d",
                         metrics->link_quality_score, LINK_QUALITY_DEGRADED);
                metrics_emit_event(NET_EVENT_DEGRADED, det, metrics);
            }
        }
        
        /* Network: congestion detected */
        if (metrics->congestion_detected) {
            is_unstable = 1;
            if (current_mode < MODE_UNSTABLE) {
                metrics_emit_event(NET_EVENT_CONGESTION_DETECTED,
                                   "RTT trend analysis detected network congestion",
                                   metrics);
            }
        }
        
        /* Network: delivery rate degraded */
        if (metrics->delivery_success_ratio < DELIVERY_RATIO_WARN &&
            metrics->delivery_success_ratio > 0.0f) {
            is_unstable = 1;
            if (current_mode < MODE_UNSTABLE) {
                char det[128];
                snprintf(det, sizeof(det), "Delivery ratio=%.1f%% below warning threshold %.0f%%",
                         metrics->delivery_success_ratio * 100.0f,
                         DELIVERY_RATIO_WARN * 100.0f);
                metrics_emit_event(NET_EVENT_DELIVERY_WARN, det, metrics);
            }
        }
        
        if (is_unstable) {
            new_mode = MODE_UNSTABLE;
        } else {
            new_mode = MODE_NORMAL;
        }
    }
    
    /* Apply transition logic */
    if (new_mode > current_mode) {
        /* Upward transition: immediate */
        fprintf(stderr, "[Engine] Transitioning from %d to %d (network/threat conditions)\n",
                current_mode, new_mode);
        engine_apply_mode(state, new_mode);
        last_mode_change = now;
    } else if (new_mode < current_mode) {
        /* Downward transition: require stable period (hysteresis) */
        if (time_since_change >= STABLE_DURATION_SEC) {
            fprintf(stderr, "[Engine] Transitioning from %d to %d (stabilized after %llds)\n",
                    current_mode, new_mode, (long long)time_since_change);
            engine_apply_mode(state, new_mode);
            last_mode_change = now;
            metrics_emit_event(NET_EVENT_NETWORK_RECOVERED,
                               "Network conditions stabilized, mode downgraded", metrics);
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
