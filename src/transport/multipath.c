#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include "multipath.h"
#include "tls_layer.h"
#include "udp_notify.h"
#include "common.h"
#include "platform_compat.h"

/* Dedup ring buffer */
static uint8_t  dedup_buf[DEDUP_WINDOW][MSG_ID_LEN];
static int      dedup_idx    = 0;
static int      dedup_filled = 0;
static pthread_mutex_t dedup_lock = PTHREAD_MUTEX_INITIALIZER;

void dedup_init(void) {
    pthread_mutex_lock(&dedup_lock);
    memset(dedup_buf, 0, sizeof(dedup_buf));
    dedup_idx    = 0;
    dedup_filled = 0;
    pthread_mutex_unlock(&dedup_lock);
}

int dedup_check(const uint8_t id[MSG_ID_LEN]) {
    pthread_mutex_lock(&dedup_lock);
    int window = dedup_filled ? DEDUP_WINDOW : dedup_idx;
    for (int i = 0; i < window; i++) {
        if (memcmp(dedup_buf[i], id, MSG_ID_LEN) == 0) {
            pthread_mutex_unlock(&dedup_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&dedup_lock);
    return 0;
}

void dedup_add(uint8_t id[MSG_ID_LEN]) {
    pthread_mutex_lock(&dedup_lock);
    memcpy(dedup_buf[dedup_idx], id, MSG_ID_LEN);
    dedup_idx = (dedup_idx + 1) % DEDUP_WINDOW;
    if (!dedup_filled && dedup_idx == 0) dedup_filled = 1;
    pthread_mutex_unlock(&dedup_lock);
}

static int rand_delay_ms(void) {
    return 100 + (rand() % 401);  /* 100–500 ms */
}

int multipath_send(SSL *ssl, int udp_fd,
                   const struct sockaddr_in *udp_dest,
                   const void *payload, size_t payload_len,
                   uint8_t priority,
                   const EngineState *engine) {
    int tcp_ok = 0, udp_ok = 0;
    int retries = (priority == PRIORITY_CRITICAL) ?
                      engine->max_retries + 2 : engine->max_retries;

    for (int attempt = 0; attempt < retries; attempt++) {
        if (!tcp_ok && ssl) {
            uint32_t plen_net = htonl((uint32_t)payload_len);
            if (tls_send(ssl, &plen_net, 4) > 0 &&
                tls_send(ssl, payload, (int)payload_len) > 0)
                tcp_ok = 1;
        }

        if (!udp_ok && udp_fd >= 0 && udp_dest && engine->use_udp_backup) {
            if (udp_send(udp_fd, udp_dest, payload, payload_len) > 0)
                udp_ok = 1;
        }

        if (tcp_ok) break;

        int delay = engine->random_delay ? rand_delay_ms() : engine->retry_delay_ms;
        sleep_ms(delay);
    }

    return (tcp_ok || udp_ok) ? 0 : -1;
}

int multipath_recv(SSL *ssl, int udp_fd,
                   void *payload_out, size_t buf_len,
                   uint8_t *msg_id_out) {
    if (!ssl) return -1;

    uint32_t plen_net = 0;
    if (tls_recv(ssl, &plen_net, 4) < 0) return -1;

    uint32_t plen = ntohl(plen_net);
    if (plen > buf_len || plen > (uint32_t)(MSG_PADDED_SIZE + 64)) {
        fprintf(stderr, "multipath_recv: payload too large %u\n", plen);
        return -1;
    }

    if (tls_recv(ssl, payload_out, (int)plen) < 0) return -1;

    /* msg_id_out is managed by caller from message header */
    (void)msg_id_out;
    (void)udp_fd;

    return (int)plen;
}
