#ifndef MULTIPATH_H
#define MULTIPATH_H

#include "common.h"
#include "adaptive_engine.h"
#include <openssl/ssl.h>
#include <netinet/in.h>

/**
 * Send msg over both TCP (ssl) and UDP (udp_fd) simultaneously.
 * Applies retry logic and delays based on current engine state.
 * Returns 0 if at least one path succeeded, -1 if both failed.
 */
int multipath_send(SSL *ssl, int udp_fd,
                   const struct sockaddr_in *udp_dest,
                   const void *payload, size_t payload_len,
                   uint8_t priority,
                   const EngineState *engine);

/**
 * Blocking receive. Accepts from either TCP or UDP.
 * Deduplicates by msg ID. Writes to payload_out (caller allocates).
 * Returns payload length or -1.
 */
int multipath_recv(SSL *ssl, int udp_fd,
                   void *payload_out, size_t buf_len,
                   uint8_t *msg_id_out);

/**
 * Add message ID to dedup set. Thread-safe.
 */
void dedup_add(uint8_t id[MSG_ID_LEN]);

/**
 * Check if message ID seen before. Returns 1 if duplicate, 0 if new.
 */
int dedup_check(const uint8_t id[MSG_ID_LEN]);

#endif /* MULTIPATH_H */
