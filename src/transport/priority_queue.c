#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "priority_queue.h"
#include "common.h"
#include "platform_compat.h"

#define PQ_CAPACITY  (OFFLINE_QUEUE_MAX * 2)

static QueuedMessage  pq_pool[PQ_CAPACITY];
static QueuedMessage *pq_heap[PQ_CAPACITY];
static int            pq_count = 0;

static pthread_mutex_t pq_lock   = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  pq_cond   = PTHREAD_COND_INITIALIZER;
static int             pq_ready  = 0;

int pq_init(void) {
    pthread_mutex_lock(&pq_lock);
    pq_count = 0;
    pq_ready = 1;
    pthread_mutex_unlock(&pq_lock);
    return 0;
}

static int pq_cmp(const QueuedMessage *a, const QueuedMessage *b) {
    /* Higher priority value = served first */
    if (a->priority != b->priority) return (int)b->priority - (int)a->priority;
    /* Earlier enqueue time = served first */
    return (a->enqueue_time_ms < b->enqueue_time_ms) ? -1 : 1;
}

static void pq_sift_up(int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (pq_cmp(pq_heap[idx], pq_heap[parent]) < 0) break;
        QueuedMessage *tmp = pq_heap[idx];
        pq_heap[idx] = pq_heap[parent];
        pq_heap[parent] = tmp;
        idx = parent;
    }
}

static void pq_sift_down(int idx) {
    while (1) {
        int left  = 2 * idx + 1;
        int right = 2 * idx + 2;
        int best  = idx;

        if (left  < pq_count && pq_cmp(pq_heap[left],  pq_heap[best]) > 0) best = left;
        if (right < pq_count && pq_cmp(pq_heap[right], pq_heap[best]) > 0) best = right;
        if (best == idx) break;

        QueuedMessage *tmp = pq_heap[idx];
        pq_heap[idx]  = pq_heap[best];
        pq_heap[best] = tmp;
        idx = best;
    }
}

int pq_enqueue(QueuedMessage *msg) {
    pthread_mutex_lock(&pq_lock);

    if (pq_count >= PQ_CAPACITY) {
        pthread_mutex_unlock(&pq_lock);
        return -1;
    }

    /* Copy into pool slot */
    memcpy(&pq_pool[pq_count], msg, sizeof(QueuedMessage));
    pq_heap[pq_count] = &pq_pool[pq_count];
    pq_sift_up(pq_count);
    pq_count++;

    pthread_cond_signal(&pq_cond);
    pthread_mutex_unlock(&pq_lock);
    return 0;
}

QueuedMessage *pq_dequeue(void) {
    pthread_mutex_lock(&pq_lock);
    while (pq_count == 0)
        pthread_cond_wait(&pq_cond, &pq_lock);

    QueuedMessage *top = pq_heap[0];
    pq_count--;
    if (pq_count > 0) {
        pq_heap[0] = pq_heap[pq_count];
        pq_sift_down(0);
    }

    pthread_mutex_unlock(&pq_lock);
    return top;
}

int pq_size(void) {
    pthread_mutex_lock(&pq_lock);
    int sz = pq_count;
    pthread_mutex_unlock(&pq_lock);
    return sz;
}

void pq_destroy(void) {
    pthread_mutex_lock(&pq_lock);
    pq_count = 0;
    pthread_cond_broadcast(&pq_cond);
    pthread_mutex_unlock(&pq_lock);
}
