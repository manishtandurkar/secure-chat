#include "dns_resolver.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len) {
    if (!hostname || !ip_out || ip_out_len < INET_ADDRSTRLEN) {
        return EAI_FAIL;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       /* IPv4 only */
    hints.ai_socktype = SOCK_STREAM; /* TCP */

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0) {
        return status;
    }

    /* Extract IP address from first result */
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
    if (!inet_ntop(AF_INET, &(ipv4->sin_addr), ip_out, ip_out_len)) {
        freeaddrinfo(res);
        return EAI_SYSTEM;
    }

    freeaddrinfo(res);
    return 0;
}

int dns_reverse_lookup(const char *ip_str, char *hostname_out, size_t len) {
    if (!ip_str || !hostname_out || len == 0) {
        return EAI_FAIL;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;

    if (inet_pton(AF_INET, ip_str, &(sa.sin_addr)) != 1) {
        return EAI_FAIL;
    }

    int status = getnameinfo((struct sockaddr *)&sa, sizeof(sa),
                            hostname_out, len, NULL, 0, 0);
    return status;
}

void dns_print_error(int gai_error_code) {
    fprintf(stderr, "DNS error: %s\n", gai_strerror(gai_error_code));
}

int is_valid_ipv4(const char *ip_str) {
    if (!ip_str) {
        return 0;
    }

    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_str, &(sa.sin_addr)) == 1;
}
