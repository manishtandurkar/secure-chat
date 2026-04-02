#ifndef OFFLINE_QUEUE_H
#define OFFLINE_QUEUE_H

#include "common.h"

/**
 * Persist an encrypted message payload for offline user.
 * Creates file in data/offline_queue/<username>/.
 * Returns 0 or -1.
 */
int queue_store(const char *username,
                const void *ciphertext, size_t len,
                const uint8_t msg_id[MSG_ID_LEN]);

/**
 * Count pending messages for user.
 */
int queue_count(const char *username);

/**
 * Drain all queued messages to the now-connected user.
 * Calls send_fn(payload, len, ctx) for each message in order.
 * Deletes each file after successful delivery.
 * Returns number of messages delivered, or -1 on error.
 */
int queue_drain(const char *username,
                int (*send_fn)(const void *payload, size_t len, void *ctx),
                void *ctx);

/**
 * Delete all queued messages for user (on explicit request).
 */
int queue_clear(const char *username);

#endif /* OFFLINE_QUEUE_H */
