#ifndef OFFLINE_QUEUE_H
#define OFFLINE_QUEUE_H

#include <stdint.h>
#include <stddef.h>
#include "common.h"

int  queue_store(const char *username,
                 const void *ciphertext, size_t len,
                 const uint8_t msg_id[MSG_ID_LEN]);

int  queue_count(const char *username);

int  queue_drain(const char *username,
                 int (*send_fn)(const void *payload, size_t len, void *ctx),
                 void *ctx);

int  queue_clear(const char *username);

#endif /* OFFLINE_QUEUE_H */
