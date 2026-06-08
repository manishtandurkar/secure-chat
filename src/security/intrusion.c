#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "intrusion.h"
#include "adaptive_engine.h"
#include "common.h"

typedef struct {
    char   ip[48];
    int    auth_fail_count;
    int    blocked;
    time_t blocked_at;
} IpRecord;

static IpRecord  ip_table[MAX_BLOCKED_IPS];
static int       ip_count = 0;
static pthread_mutex_t ids_lock = PTHREAD_MUTEX_INITIALIZER;

void ids_init(void) {
    pthread_mutex_lock(&ids_lock);
    memset(ip_table, 0, sizeof(ip_table));
    ip_count = 0;
    pthread_mutex_unlock(&ids_lock);
}

static IpRecord *find_or_create(const char *ip_str) {
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ip_table[i].ip, ip_str) == 0)
            return &ip_table[i];
    }
    if (ip_count >= MAX_BLOCKED_IPS) return NULL;
    IpRecord *rec = &ip_table[ip_count++];
    memset(rec, 0, sizeof(*rec));
    strncpy(rec->ip, ip_str, sizeof(rec->ip) - 1);
    return rec;
}

void ids_record_auth_fail(const char *ip_str, Metrics *metrics) {
    pthread_mutex_lock(&ids_lock);

    IpRecord *rec = find_or_create(ip_str);
    if (rec) {
        rec->auth_fail_count++;
        if (rec->auth_fail_count >= AUTH_FAIL_THRESHOLD && !rec->blocked) {
            rec->blocked    = 1;
            rec->blocked_at = time(NULL);
            ids_log_event("BLOCK", ip_str);
        }
    }

    pthread_mutex_unlock(&ids_lock);
    metrics_record_auth_fail(metrics);
}

void ids_record_replay(const char *ip_str, Metrics *metrics) {
    ids_log_event("REPLAY", ip_str);
    metrics_record_replay(metrics);
}

int ids_is_blocked(const char *ip_str) {
    pthread_mutex_lock(&ids_lock);
    int blocked = 0;
    for (int i = 0; i < ip_count; i++) {
        if (strcmp(ip_table[i].ip, ip_str) == 0) {
            blocked = ip_table[i].blocked;
            break;
        }
    }
    pthread_mutex_unlock(&ids_lock);
    return blocked;
}

void ids_expire_blocks(void) {
    pthread_mutex_lock(&ids_lock);
    time_t now = time(NULL);
    for (int i = 0; i < ip_count; i++) {
        if (ip_table[i].blocked &&
            difftime(now, ip_table[i].blocked_at) >= BLOCK_DURATION_SEC) {
            ip_table[i].blocked         = 0;
            ip_table[i].auth_fail_count = 0;
            ids_log_event("UNBLOCK", ip_table[i].ip);
        }
    }
    pthread_mutex_unlock(&ids_lock);
}

void ids_log_event(const char *event_type, const char *ip_str) {
    time_t now = time(NULL);
    char tbuf[32];
    struct tm *tm_info = localtime(&now);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(stderr, "[IDS %s] %s from %s\n", tbuf, event_type, ip_str);
}
