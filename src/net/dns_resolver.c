#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "dns_resolver.h"

int dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0) {
        dns_print_error(rc);
        return -1;
    }

    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    if (!inet_ntop(AF_INET, &sa->sin_addr, ip_out, (socklen_t)ip_out_len)) {
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return 0;
}

int dns_reverse_lookup(const char *ip_str, char *hostname_out, size_t len) {
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_str, &sa.sin_addr) <= 0) return -1;

    int rc = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                          hostname_out, (socklen_t)len, NULL, 0, 0);
    if (rc != 0) {
        dns_print_error(rc);
        return -1;
    }
    return 0;
}

void dns_print_error(int gai_error_code) {
    fprintf(stderr, "DNS error: %s\n", gai_strerror(gai_error_code));
}
