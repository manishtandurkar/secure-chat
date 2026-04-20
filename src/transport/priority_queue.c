#include "priority_queue.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#define MAX_QUEUE_SIZE 1000

static QueuedMessage queue[MAX_QUEUE_SIZE];
static QueuedMessage dequeued_message;
static int queue_count = 0;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
static int queue_initialized = 0;

/* Get current time in milliseconds */
static uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Initialize priority queue */
int pq_init(void) {
    if (queue_initialized) {
        return SUCCESS;
    }
    
    memset(queue, 0, sizeof(queue));
    queue_count = 0;
    queue_initialized = 1;
    
    return SUCCESS;
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

    /* Keep the queue ordered by priority while preserving FIFO within each priority. */
    int insert_index = 0;
    while (insert_index < queue_count &&
           queue[insert_index].priority > msg->priority) {
        insert_index++;
    }

    while (insert_index < queue_count &&
           queue[insert_index].priority == msg->priority) {
        insert_index++;
    }

    if (insert_index < queue_count) {
        memmove(&queue[insert_index + 1],
                &queue[insert_index],
                (size_t)(queue_count - insert_index) * sizeof(QueuedMessage));
    }

    memcpy(&queue[insert_index], msg, sizeof(QueuedMessage));
    
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
    
    /* Return pointer to a stable internal copy of the highest-priority message. */
    memcpy(&dequeued_message, &queue[0], sizeof(QueuedMessage));

    if (queue_count > 1) {
        memmove(&queue[0], &queue[1], (size_t)(queue_count - 1) * sizeof(QueuedMessage));
    }

    queue_count--;
    
    pthread_mutex_unlock(&queue_mutex);
    
    return &dequeued_message;
}

/* Get current queue size */
int pq_size(void) {
    pthread_mutex_lock(&queue_mutex);
    int size = queue_count;
    pthread_mutex_unlock(&queue_mutex);
    
    return size;
}

/* Cleanup priority queue */
void pq_destroy(void) {
    pthread_mutex_lock(&queue_mutex);
    queue_initialized = 0;
    queue_count = 0;
    memset(queue, 0, sizeof(queue));
    pthread_mutex_unlock(&queue_mutex);
}
