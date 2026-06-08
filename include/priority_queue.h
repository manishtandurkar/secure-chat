#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include <stdint.h>
#include <stddef.h>
#include "common.h"

typedef struct {
    uint8_t  priority;
    uint8_t  msg_id[MSG_ID_LEN];
    uint8_t  payload[MSG_PADDED_SIZE + 64];
    size_t   payload_len;
    uint64_t enqueue_time_ms;
} QueuedMessage;

int            pq_init(void);
int            pq_enqueue(QueuedMessage *msg);
QueuedMessage *pq_dequeue(void);
int            pq_size(void);
void           pq_destroy(void);

#endif /* PRIORITY_QUEUE_H */
