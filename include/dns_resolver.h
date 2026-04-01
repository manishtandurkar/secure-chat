#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include "common.h"

/**
 * Resolve hostname to IPv4 address string (e.g. "192.168.1.10").
 * Uses getaddrinfo() internally. Writes to ip_out (at least 16 bytes).
 * Returns 0 on success, non-zero (gai error code) on failure.
 */
int dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len);

/**
 * Reverse lookup: IP string → hostname.
 * Returns 0 on success, non-zero on failure.
 */
int dns_reverse_lookup(const char *ip_str, char *hostname_out, size_t len);

/**
 * Print human-readable gai error. Wraps gai_strerror().
 */
void dns_print_error(int gai_error_code);

/**
 * Validate if a string contains a valid IPv4 address
 * Returns 1 if valid, 0 if invalid
 */
int is_valid_ipv4(const char *ip_str);

#endif /* DNS_RESOLVER_H */