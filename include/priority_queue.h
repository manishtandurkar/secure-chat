#ifndef PRIORITY_QUEUE_H
#define PRIORITY_QUEUE_H

#include "common.h"

typedef struct {
    uint8_t  priority;                     /* PRIORITY_NORMAL/URGENT/CRITICAL */
    uint8_t  msg_id[MSG_ID_LEN];
    uint8_t  payload[MSG_PADDED_SIZE + 64];
    size_t   payload_len;
    uint64_t enqueue_time_ms;
} QueuedMessage;

/**
 * Initialize priority queue. Returns 0 on success, -1 on error.
 */
int pq_init(void);

/**
 * Thread-safe enqueue. CRITICAL messages bypass internal ordering
 * and go to the front. Returns 0 or -1 if queue full.
 */
int pq_enqueue(QueuedMessage *msg);

/**
 * Blocking dequeue. Returns highest-priority message.
 * Caller must not free — message is from internal pool.
 */
QueuedMessage *pq_dequeue(void);

/**
 * Current queue depth.
 */
int pq_size(void);

/**
 * Destroy/cleanup priority queue.
 */
void pq_destroy(void);

#endif /* PRIORITY_QUEUE_H */
