#ifndef INTRUSION_H
#define INTRUSION_H

#include "common.h"
#include "adaptive_engine.h"

typedef struct {
    int active_blocked_ips;
    int max_threat_score;
    int total_replay_attempts;
    int total_auth_failures;
    int total_flood_attempts;
    int total_malformed_packets;
    int current_engine_mode;
} IdsStats;

/* Record connection and connection flood check */
void ids_record_connection(const char *ip_str, Metrics *metrics);

/* Record authentication attempt (rate-limiting) */
void ids_record_auth_attempt(const char *ip_str, Metrics *metrics);

/* Record failed authentication attempt with username (enumeration detection) */
void ids_record_auth_fail_ex(const char *ip_str, const char *attempted_username, Metrics *metrics);

/* Kept for backward compatibility */
void ids_record_auth_fail(const char *ip_str, Metrics *metrics);

/* Record a detected replay attack */
void ids_record_replay(const char *ip_str, Metrics *metrics);

/* Record incoming message packet details (message flood check) */
void ids_record_message(const char *ip_str, size_t bytes, Metrics *metrics);

/* Record detected malformed packet */
void ids_record_malformed_packet(const char *ip_str, const char *reason, Metrics *metrics);

/* Record timestamp anomaly */
void ids_record_invalid_timestamp(const char *ip_str, Metrics *metrics);

/* Check if ip_str is currently blocked. Returns 1 if blocked, 0 if allowed. */
int ids_is_blocked(const char *ip_str);

/* Unblock after progressive delay expires. Called periodically by server main loop. */
void ids_expire_blocks(void);

/* Log security event to stderr with timestamp, type, and details. */
void ids_log_event_ex(const char *event_type, const char *ip_str, int threat_score, const char *details);
void ids_log_event(const char *event_type, const char *ip_str); /* Backward compatibility */

/* Get maximum threat score across all active IPs */
int ids_get_max_threat_score(void);

/* Get all runtime IDS stats */
void ids_get_stats(IdsStats *stats_out);

#endif /* INTRUSION_H */
