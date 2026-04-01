#ifndef INTRUSION_H
#define INTRUSION_H

#include "common.h"
#include "adaptive_engine.h"

/**
 * Record a failed authentication attempt from ip_str.
 * If count exceeds AUTH_FAIL_THRESHOLD, adds to block list.
 * Calls metrics_record_auth_fail() to update engine metrics.
 */
void ids_record_auth_fail(const char *ip_str, Metrics *metrics);

/**
 * Record a detected replay attack (duplicate msg ID from unexpected source).
 * Calls metrics_record_replay().
 */
void ids_record_replay(const char *ip_str, Metrics *metrics);

/**
 * Check if ip_str is currently blocked.
 * Returns 1 if blocked, 0 if allowed.
 */
int ids_is_blocked(const char *ip_str);

/**
 * Unblock after BLOCK_DURATION_SEC seconds.
 * Called periodically by server main loop.
 */
void ids_expire_blocks(void);

/**
 * Log security event to stderr with timestamp, type, and source IP.
 */
void ids_log_event(const char *event_type, const char *ip_str);

#endif /* INTRUSION_H */
