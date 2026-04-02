#include "priority_queue.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#define MAX_QUEUE_SIZE 1000

static QueuedMessage queue[MAX_QUEUE_SIZE];
static int queue_front = 0;
static int queue_rear = 0;
static int queue_count = 0;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

/* Get current time in milliseconds */
static uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Enqueue message with priority */
int pq_enqueue(QueuedMessage *msg) {
    if (!msg) {
        return ERROR_GENERAL;
    }
    
    pthread_mutex_lock(&queue_mutex);
    
    if (queue_count >= MAX_QUEUE_SIZE) {
        pthread_mutex_unlock(&queue_mutex);
        return ERROR_GENERAL; /* Queue full */
    }
    
    msg->enqueue_time_ms = get_time_ms();
    
    /* For CRITICAL priority, insert at front */
    if (msg->priority == PRIORITY_CRITICAL && queue_count > 0) {
        queue_front = (queue_front - 1 + MAX_QUEUE_SIZE) % MAX_QUEUE_SIZE;
        memcpy(&queue[queue_front], msg, sizeof(QueuedMessage));
    } else {
        /* Normal enqueue at rear */
        memcpy(&queue[queue_rear], msg, sizeof(QueuedMessage));
        queue_rear = (queue_rear + 1) % MAX_QUEUE_SIZE;
    }
    
    queue_count++;
    
    /* Signal waiting dequeue */
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
    
    return SUCCESS;
}

/* Dequeue highest priority message (blocking) */
QueuedMessage *pq_dequeue(void) {
    pthread_mutex_lock(&queue_mutex);
    
    /* Wait until queue has data */
    while (queue_count == 0) {
        pthread_cond_wait(&queue_cond, &queue_mutex);
    }
    
    /* Return pointer to front message */
    QueuedMessage *msg = &queue[queue_front];
    queue_front = (queue_front + 1) % MAX_QUEUE_SIZE;
    queue_count--;
    
    pthread_mutex_unlock(&queue_mutex);
    
    return msg;
}

/* Get current queue size */
int pq_size(void) {
    pthread_mutex_lock(&queue_mutex);
    int size = queue_count;
    pthread_mutex_unlock(&queue_mutex);
    
    return size;
}
