#define _POSIX_C_SOURCE 200809L
#include "platform_compat.h"
#include "multipath.h"
#include "network_monitor.h"
#include "message.h"
#include "tls_layer.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <openssl/rand.h>

/* Deduplication ring buffer */
static uint8_t dedup_buffer[DEDUP_WINDOW][MSG_ID_LEN];
static int dedup_index = 0;
static pthread_mutex_t dedup_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Add message ID to dedup set */
void dedup_add(uint8_t id[MSG_ID_LEN]) {
    pthread_mutex_lock(&dedup_mutex);
    
    memcpy(dedup_buffer[dedup_index], id, MSG_ID_LEN);
    dedup_index = (dedup_index + 1) % DEDUP_WINDOW;
    
    pthread_mutex_unlock(&dedup_mutex);
}

/* Check if message ID seen before */
int dedup_check(const uint8_t id[MSG_ID_LEN]) {
    pthread_mutex_lock(&dedup_mutex);
    
    for (int i = 0; i < DEDUP_WINDOW; i++) {
        if (memcmp(dedup_buffer[i], id, MSG_ID_LEN) == 0) {
            pthread_mutex_unlock(&dedup_mutex);
            return 1; /* Duplicate */
        }
    }
    
    pthread_mutex_unlock(&dedup_mutex);
    return 0; /* New message */
}

/* Send over both TCP and UDP with path-intelligence ordering */
int multipath_send(SSL *ssl, int udp_fd,
                   const struct sockaddr_in *udp_dest,
                   const void *payload, size_t payload_len,
                   uint8_t priority,
                   const EngineState *engine) {
    (void)priority; /* Currently used for future priority-aware queuing */
    if (!ssl || !payload || !engine) {
        return ERROR_NETWORK;
    }
    
    int tcp_success = 0;
    int udp_success = 0;
    
    /* Determine preferred path based on transport health */
    PreferredPath pref = multipath_preferred_path();
    
    /* Attempt sends with retries */
    for (int attempt = 0; attempt < engine->max_retries; attempt++) {
        struct timespec t_start, t_end;
        
        /* --- TCP send (preferred or both) --- */
        if (!tcp_success && (pref == PATH_TCP || pref == PATH_BOTH)) {
#ifdef CLOCK_MONOTONIC
            clock_gettime(CLOCK_MONOTONIC, &t_start);
#endif
            int tcp_ok = (tls_send(ssl, payload, (int)payload_len) > 0);
#ifdef CLOCK_MONOTONIC
            clock_gettime(CLOCK_MONOTONIC, &t_end);
            uint32_t lat_ms = (uint32_t)(
                (t_end.tv_sec  - t_start.tv_sec)  * 1000 +
                (t_end.tv_nsec - t_start.tv_nsec) / 1000000);
#else
            uint32_t lat_ms = 0;
#endif
            metrics_record_tcp_send(tcp_ok, lat_ms);
            if (tcp_ok) tcp_success = 1;
        }
        
        /* --- UDP send (backup or both or preferred when TCP unhealthy) --- */
        if (!udp_success && engine->use_udp_backup &&
            udp_fd >= 0 && udp_dest &&
            (pref == PATH_UDP || pref == PATH_BOTH)) {
#ifdef CLOCK_MONOTONIC
            clock_gettime(CLOCK_MONOTONIC, &t_start);
#endif
            int udp_ok = (sendto(udp_fd, (const char *)payload, (int)payload_len, 0,
                                 (struct sockaddr *)udp_dest,
                                 sizeof(*udp_dest)) > 0);
#ifdef CLOCK_MONOTONIC
            clock_gettime(CLOCK_MONOTONIC, &t_end);
            uint32_t lat_ms = (uint32_t)(
                (t_end.tv_sec  - t_start.tv_sec)  * 1000 +
                (t_end.tv_nsec - t_start.tv_nsec) / 1000000);
#else
            uint32_t lat_ms = 0;
#endif
            metrics_record_udp_send(udp_ok, lat_ms);
            if (udp_ok) udp_success = 1;
        }
        
        /* --- Fallback: try non-preferred path if preferred failed --- */
        if (!tcp_success && !udp_success) {
            /* Try TCP regardless of preference */
            if (!tcp_success) {
                int tcp_ok = (tls_send(ssl, payload, (int)payload_len) > 0);
                metrics_record_tcp_send(tcp_ok, 0);
                if (tcp_ok) tcp_success = 1;
            }
            /* Try UDP regardless of preference */
            if (!udp_success && engine->use_udp_backup && udp_fd >= 0 && udp_dest) {
                int udp_ok = (sendto(udp_fd, (const char *)payload, (int)payload_len, 0,
                                     (struct sockaddr *)udp_dest,
                                     sizeof(*udp_dest)) > 0);
                metrics_record_udp_send(udp_ok, 0);
                if (udp_ok) udp_success = 1;
            }
        }
        
        /* If either succeeded, record bytes and stop retrying */
        if (tcp_success || udp_success) {
            metrics_record_tx_bytes(payload_len);
            metrics_record_delivery(1);
            break;
        }
        
        /* Apply delay based on engine config */
        if (engine->random_delay) {
            int delay_ms = 100 + (rand() % 400); /* 100–500ms */
            usleep(delay_ms * 1000);
        } else {
            usleep(engine->retry_delay_ms * 1000);
        }
    }
    
    if (!tcp_success && !udp_success) {
        metrics_record_delivery(0); /* Undelivered */
    }
    
    return (tcp_success || udp_success) ? SUCCESS : ERROR_NETWORK;
}

/* Receive from either TCP or UDP with deduplication */
int multipath_recv(SSL *ssl, int udp_fd,
                   void *payload_out, size_t buf_len,
                   uint8_t *msg_id_out) {
    /* Simplified implementation - in production would use select/poll */
    if (!ssl || !payload_out) {
        return ERROR_NETWORK;
    }
    
    /* Try TCP first */
    int n = tls_recv(ssl, payload_out, buf_len);
    if (n > 0) {
        /* Extract message ID from header if present */
        if (msg_id_out && (size_t)n >= sizeof(MsgHeader)) {
            MsgHeader *hdr = (MsgHeader *)payload_out;
            memcpy(msg_id_out, hdr->msg_id, MSG_ID_LEN);
            
            /* Check for duplicate */
            if (dedup_check(hdr->msg_id)) {
                return 0; /* Duplicate, discard silently */
            }
            
            /* Add to dedup set */
            dedup_add(hdr->msg_id);
        }
        
        return n;
    }
    
    return ERROR_NETWORK;
}
