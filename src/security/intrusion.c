#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "platform_compat.h"
#include "intrusion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef struct {
    char ip[64];
    int auth_fail_count;
    time_t block_until;
    
    /* progressive block state */
    int offense_count;
    time_t last_offense_time;

    /* Threat score */
    int threat_score;
    time_t last_decay_time;

    /* Rate limiting sliding window data: connection tracking */
    time_t conn_window_start;
    int conn_count;

    /* Auth tracking */
    time_t auth_window_start;
    int auth_count;

    /* Message tracking */
    time_t msg_window_start;
    int msg_count;
    size_t msg_bytes_in_window;

    /* User enumeration tracking */
    time_t enum_window_start;
    char last_attempted_username[MAX_USERNAME_LEN];
    int unique_username_count;
} IPEntry;

static IPEntry blocked_ips[MAX_BLOCKED_IPS];
static int blocked_count = 0;
static pthread_mutex_t ids_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Stats counters */
static int total_replay_attempts = 0;
static int total_auth_failures = 0;
static int total_flood_attempts = 0;
static int total_malformed_packets = 0;

/* Find or create IP entry (assumes ids_mutex is held) */
static IPEntry *find_ip_entry(const char *ip_str) {
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip_str) == 0) {
            return &blocked_ips[i];
        }
    }
    
    /* Create new entry if space available */
    if (blocked_count < MAX_BLOCKED_IPS) {
        memset(&blocked_ips[blocked_count], 0, sizeof(IPEntry));
        strncpy(blocked_ips[blocked_count].ip, ip_str, 63);
        blocked_ips[blocked_count].last_decay_time = time(NULL);
        blocked_ips[blocked_count].conn_window_start = time(NULL);
        blocked_ips[blocked_count].auth_window_start = time(NULL);
        blocked_ips[blocked_count].msg_window_start = time(NULL);
        blocked_ips[blocked_count].enum_window_start = time(NULL);
        return &blocked_ips[blocked_count++];
    }
    
    return NULL;
}

/* Apply decay to threat score of a clean IP (assumes ids_mutex is held) */
static void apply_decay(IPEntry *entry) {
    time_t now = time(NULL);
    if (entry->threat_score <= 0) {
        entry->last_decay_time = now;
        return;
    }
    
    long long seconds_passed = (long long)(now - entry->last_decay_time);
    if (seconds_passed >= 60) {
        int minutes = seconds_passed / 60;
        int decay_amount = minutes * 5;
        entry->threat_score -= decay_amount;
        if (entry->threat_score < 0) {
            entry->threat_score = 0;
        }
        entry->last_decay_time += minutes * 60;
    }
}

/* Expire history of offense penalties after 1 hour clean (assumes ids_mutex is held) */
static void apply_offense_decay(IPEntry *entry) {
    time_t now = time(NULL);
    if (entry->offense_count > 0 && (now - entry->last_offense_time) >= 3600) {
        entry->offense_count = 0; /* Reset progressive penalty level */
    }
}

/* Format and log structured security event */
void ids_log_event_ex(const char *event_type, const char *ip_str, int threat_score, const char *details) {
    time_t now = time(NULL);
    char time_buf[64];
    struct tm tm_val;
#ifdef PLATFORM_WINDOWS
    localtime_s(&tm_val, &now);
#else
    localtime_r(&now, &tm_val);
#endif
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_val);
    
    fprintf(stderr, "[IDS %s] %s from %s | Score: %d | Details: %s\n", 
            time_buf, event_type, ip_str, threat_score, details ? details : "None");
    fflush(stderr);
}

void ids_log_event(const char *event_type, const char *ip_str) {
    ids_log_event_ex(event_type, ip_str, 0, "Legacy Event");
}

/* Perform progressive IP blocking and log (assumes ids_mutex is held) */
static void block_ip(IPEntry *entry, const char *ip_str, const char *reason) {
    entry->offense_count++;
    entry->last_offense_time = time(NULL);
    
    int duration = 300; /* Default 5 minutes */
    if (entry->offense_count == 2) duration = 900;       /* 15 minutes */
    else if (entry->offense_count == 3) duration = 1800;  /* 30 minutes */
    else if (entry->offense_count >= 4) duration = 3600;  /* 60 minutes */
    
    entry->block_until = time(NULL) + duration;
    
    char details[256];
    snprintf(details, sizeof(details), "IP blocked for %d sec (progressive level %d) | Reason: %s", 
             duration, entry->offense_count, reason);
    
    ids_log_event_ex("IP_BLOCKED", ip_str, entry->threat_score, details);
}

/* Connection attempt rate checking and sliding window Connections-Per-Minute */
void ids_record_connection(const char *ip_str, Metrics *metrics) {
    if (!ip_str) return;
    (void)metrics;
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        apply_decay(entry);
        apply_offense_decay(entry);
        
        time_t now = time(NULL);
        if (now - entry->conn_window_start >= 60) {
            entry->conn_window_start = now;
            entry->conn_count = 1;
        } else {
            entry->conn_count++;
        }
        
        if (entry->conn_count > 20) { /* Burst Connection Flood > 20/min */
            entry->threat_score += 15;
            total_flood_attempts++;
            ids_log_event_ex("CONNECTION_FLOOD", ip_str, entry->threat_score, "DoS Burst: > 20 connections per minute");
            
            if (entry->threat_score >= 150) {
                block_ip(entry, ip_str, "Cumulative Connection Flood Score");
            }
        }
    }
    pthread_mutex_unlock(&ids_mutex);
}

/* Authentication rate check (sliding-window Auths-Per-Minute) */
void ids_record_auth_attempt(const char *ip_str, Metrics *metrics) {
    if (!ip_str) return;
    (void)metrics;
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        apply_decay(entry);
        apply_offense_decay(entry);
        
        time_t now = time(NULL);
        if (now - entry->auth_window_start >= 60) {
            entry->auth_window_start = now;
            entry->auth_count = 1;
        } else {
            entry->auth_count++;
        }
        
        if (entry->auth_count > 5) { /* Burst Auth Floods > 5/min */
            entry->threat_score += 10;
            ids_log_event_ex("CONNECTION_FLOOD", ip_str, entry->threat_score, "Excessive authentication requests per minute");
            
            if (entry->threat_score >= 150) {
                block_ip(entry, ip_str, "Cumulative Auth Flood Score");
            }
        }
    }
    pthread_mutex_unlock(&ids_mutex);
}

/* Auth failure and User Enumeration detection */
void ids_record_auth_fail_ex(const char *ip_str, const char *attempted_username, Metrics *metrics) {
    if (!ip_str) return;
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        apply_decay(entry);
        apply_offense_decay(entry);
        
        entry->auth_fail_count++;
        entry->threat_score += 10; /* Auth Failure penalty: +10 */
        total_auth_failures++;
        
        char details[128];
        snprintf(details, sizeof(details), "Failed auth attempt for username: %s", attempted_username ? attempted_username : "unknown");
        ids_log_event_ex("AUTH_FAILURE", ip_str, entry->threat_score, details);
        
        /* Sliding-window User Enumeration Tracking (60s) */
        time_t now = time(NULL);
        if (now - entry->enum_window_start >= 60) {
            entry->enum_window_start = now;
            entry->unique_username_count = 1;
            if (attempted_username && attempted_username[0] != '\0') {
                strncpy(entry->last_attempted_username, attempted_username, MAX_USERNAME_LEN - 1);
                entry->last_attempted_username[MAX_USERNAME_LEN - 1] = '\0';
            } else {
                entry->last_attempted_username[0] = '\0';
            }
        } else {
            if (attempted_username && attempted_username[0] != '\0') {
                if (strcmp(entry->last_attempted_username, attempted_username) != 0) {
                    entry->unique_username_count++;
                    strncpy(entry->last_attempted_username, attempted_username, MAX_USERNAME_LEN - 1);
                    entry->last_attempted_username[MAX_USERNAME_LEN - 1] = '\0';
                }
            }
        }
        
        if (entry->unique_username_count > 3) {
            entry->threat_score += 40; /* Enumeration payload recon penalty: +40 */
            ids_log_event_ex("ENUMERATION_ATTEMPT", ip_str, entry->threat_score, "Multiple unique usernames tested in 60s");
        }
        
        if (entry->threat_score >= 150) {
            block_ip(entry, ip_str, "Cumulative score after auth failures");
        } else if (entry->auth_fail_count >= AUTH_FAIL_THRESHOLD) {
            block_ip(entry, ip_str, "Auth Failures Count Threshold reached");
        }
    }
    
    if (metrics) {
        metrics_record_auth_fail(metrics);
    }
    pthread_mutex_unlock(&ids_mutex);
}

void ids_record_auth_fail(const char *ip_str, Metrics *metrics) {
    ids_record_auth_fail_ex(ip_str, NULL, metrics);
}

/* Replay attack record */
void ids_record_replay(const char *ip_str, Metrics *metrics) {
    if (!ip_str) return;
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        apply_decay(entry);
        apply_offense_decay(entry);
        
        entry->threat_score += 20; /* Replay Attack: +20 */
        total_replay_attempts++;
        ids_log_event_ex("REPLAY_ATTACK", ip_str, entry->threat_score, "Duplicate message ID detected");
        
        if (entry->threat_score >= 150) {
            block_ip(entry, ip_str, "Cumulative Replay Score");
        }
    }
    
    if (metrics) {
        metrics_record_replay(metrics);
    }
    pthread_mutex_unlock(&ids_mutex);
}

/* Message flood check (sliding window frequency + size bandwidth) */
void ids_record_message(const char *ip_str, size_t bytes, Metrics *metrics) {
    if (!ip_str) return;
    (void)metrics;
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        apply_decay(entry);
        apply_offense_decay(entry);
        
        time_t now = time(NULL);
        if (now - entry->msg_window_start >= 60) {
            entry->msg_window_start = now;
            entry->msg_count = 1;
            entry->msg_bytes_in_window = bytes;
        } else {
            entry->msg_count++;
            entry->msg_bytes_in_window += bytes;
        }
        
        int triggered = 0;
        if (entry->msg_count > 100) { /* > 100 messages/minute */
            entry->threat_score += 15;
            ids_log_event_ex("MESSAGE_FLOOD", ip_str, entry->threat_score, "Rate limit exceeded (> 100 messages/min)");
            triggered = 1;
        }
        
        if (entry->msg_bytes_in_window > 5 * 1024 * 1024) { /* > 5 MB/minute */
            if (!triggered) {
                entry->threat_score += 15;
                ids_log_event_ex("MESSAGE_FLOOD", ip_str, entry->threat_score, "Bandwidth limit exceeded (> 5MB/min)");
                triggered = 1;
            }
        }
        
        if (triggered) {
            total_flood_attempts++;
            if (entry->threat_score >= 150) {
                block_ip(entry, ip_str, "Cumulative Message Flood Score");
            }
        }
    }
    pthread_mutex_unlock(&ids_mutex);
}

/* Malformed packets */
void ids_record_malformed_packet(const char *ip_str, const char *reason, Metrics *metrics) {
    if (!ip_str) return;
    (void)metrics;
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        apply_decay(entry);
        apply_offense_decay(entry);
        
        entry->threat_score += 25; /* Malformed packet: +25 */
        total_malformed_packets++;
        
        char details[256];
        snprintf(details, sizeof(details), "Malformed packet received: %s", reason ? reason : "unknown violation");
        ids_log_event_ex("MALFORMED_PACKET", ip_str, entry->threat_score, details);
        
        if (entry->threat_score >= 150) {
            block_ip(entry, ip_str, "Malformed Packet Score");
        }
    }
    pthread_mutex_unlock(&ids_mutex);
}

/* Timestamp skew */
void ids_record_invalid_timestamp(const char *ip_str, Metrics *metrics) {
    if (!ip_str) return;
    (void)metrics;
    pthread_mutex_lock(&ids_mutex);
    
    IPEntry *entry = find_ip_entry(ip_str);
    if (entry) {
        apply_decay(entry);
        apply_offense_decay(entry);
        
        entry->threat_score += 10; /* Skew timestamp anomaly: +10 */
        ids_log_event_ex("TIMESTAMP_ANOMALY", ip_str, entry->threat_score, "Client timestamp drift exceeds +/- 300s");
        
        if (entry->threat_score >= 150) {
            block_ip(entry, ip_str, "Invalid Timestamp Score");
        }
    }
    pthread_mutex_unlock(&ids_mutex);
}

/* Check if IP is currently blocked */
int ids_is_blocked(const char *ip_str) {
    if (!ip_str) return 0;
    pthread_mutex_lock(&ids_mutex);
    
    time_t now = time(NULL);
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip_str) == 0) {
            if (blocked_ips[i].block_until > now) {
                pthread_mutex_unlock(&ids_mutex);
                return 1;
            }
        }
    }
    
    pthread_mutex_unlock(&ids_mutex);
    return 0;
}

/* Expire progressive IP blocks dynamically */
void ids_expire_blocks(void) {
    pthread_mutex_lock(&ids_mutex);
    
    time_t now = time(NULL);
    for (int i = 0; i < blocked_count; i++) {
        apply_decay(&blocked_ips[i]);
        apply_offense_decay(&blocked_ips[i]);
        
        if (blocked_ips[i].block_until > 0 && blocked_ips[i].block_until <= now) {
            blocked_ips[i].block_until = 0;
            blocked_ips[i].auth_fail_count = 0;
            ids_log_event_ex("IP_UNBLOCKED", blocked_ips[i].ip, blocked_ips[i].threat_score, 
                             "Cooldown block expired automatically");
        }
    }
    
    pthread_mutex_unlock(&ids_mutex);
}

/* Get maximum threat score across all active IPs */
int ids_get_max_threat_score(void) {
    pthread_mutex_lock(&ids_mutex);
    int max_score = 0;
    for (int i = 0; i < blocked_count; i++) {
        apply_decay(&blocked_ips[i]);
        if (blocked_ips[i].threat_score > max_score) {
            max_score = blocked_ips[i].threat_score;
        }
    }
    pthread_mutex_unlock(&ids_mutex);
    return max_score;
}

/* Get stats dashboard structure */
void ids_get_stats(IdsStats *stats_out) {
    if (!stats_out) return;
    pthread_mutex_lock(&ids_mutex);
    
    stats_out->active_blocked_ips = 0;
    stats_out->max_threat_score = 0;
    
    time_t now = time(NULL);
    for (int i = 0; i < blocked_count; i++) {
        apply_decay(&blocked_ips[i]);
        if (blocked_ips[i].block_until > now) {
            stats_out->active_blocked_ips++;
        }
        if (blocked_ips[i].threat_score > stats_out->max_threat_score) {
            stats_out->max_threat_score = blocked_ips[i].threat_score;
        }
    }
    
    stats_out->total_replay_attempts = total_replay_attempts;
    stats_out->total_auth_failures = total_auth_failures;
    stats_out->total_flood_attempts = total_flood_attempts;
    stats_out->total_malformed_packets = total_malformed_packets;
    stats_out->current_engine_mode = 0; /* Evaluated and populated externally */
    
    pthread_mutex_unlock(&ids_mutex);
}
