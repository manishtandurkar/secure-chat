#include "intrusion.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef struct {
    char ip[64];
    int auth_fail_count;
    time_t block_until;
} IPEntry;

static IPEntry blocked_ips[MAX_BLOCKED_IPS];
static int blocked_count = 0;
static pthread_mutex_t ids_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Find or create IP entry */
static IPEntry *find_ip_entry(const char *ip_str) {
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip_str) == 0) {
            return &blocked_ips[i];
        }
    }
    
    /* Create new entry if space available */
    if (blocked_count < MAX_BLOCKED_IPS) {
        strncpy(blocked_ips[blocked_count].ip, ip_str, 63);
        blocked_ips[blocked_count].auth_fail_count = 0;
        blocked_ips[blocked_count].block_until = 0;
        return &blocked_ips[blocked_count++];
    }
    
    return NULL;
}

/* Record authentication failure */
void ids_record_auth_fail(const char *ip_str, Metrics *metrics) {
    if (!ip_str || !metrics) {
        return;
    }
    
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        entry->auth_fail_count++;
        
        if (entry->auth_fail_count >= AUTH_FAIL_THRESHOLD) {
            entry->block_until = time(NULL) + BLOCK_DURATION_SEC;
            ids_log_event("AUTH_FAIL_BLOCK", ip_str);
        }
    }
    
    metrics_record_auth_fail(metrics);
    
    pthread_mutex_unlock(&ids_mutex);
}

/* Record replay attack */
void ids_record_replay(const char *ip_str, Metrics *metrics) {
    if (!ip_str || !metrics) {
        return;
    }
    
    pthread_mutex_lock(&ids_mutex);
    
    ids_log_event("REPLAY_ATTACK", ip_str);
    metrics_record_replay(metrics);
    
    pthread_mutex_unlock(&ids_mutex);
}

/* Check if IP is blocked */
int ids_is_blocked(const char *ip_str) {
    if (!ip_str) {
        return 0;
    }
    
    pthread_mutex_lock(&ids_mutex);
    
    time_t now = time(NULL);
    
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip_str) == 0) {
            if (blocked_ips[i].block_until > now) {
                pthread_mutex_unlock(&ids_mutex);
                return 1; /* Still blocked */
            }
        }
    }
    
    pthread_mutex_unlock(&ids_mutex);
    return 0;
}

/* Expire old blocks */
void ids_expire_blocks(void) {
    pthread_mutex_lock(&ids_mutex);
    
    time_t now = time(NULL);
    
    for (int i = 0; i < blocked_count; i++) {
        if (blocked_ips[i].block_until > 0 && blocked_ips[i].block_until <= now) {
            blocked_ips[i].block_until = 0;
            blocked_ips[i].auth_fail_count = 0;
            ids_log_event("BLOCK_EXPIRED", blocked_ips[i].ip);
        }
    }
    
    pthread_mutex_unlock(&ids_mutex);
}

/* Log security event */
void ids_log_event(const char *event_type, const char *ip_str) {
    time_t now = time(NULL);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(stderr, "[IDS %s] %s from %s\n", time_buf, event_type, ip_str);
}
