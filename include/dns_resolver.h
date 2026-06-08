#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stddef.h>

int  dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len);
int  dns_reverse_lookup(const char *ip_str, char *hostname_out, size_t len);
void dns_print_error(int gai_error_code);

#endif /* DNS_RESOLVER_H */
