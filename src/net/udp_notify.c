#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "udp_notify.h"
#include "common.h"

int udp_socket_create(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("udp socket"); return -1; }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("udp bind"); close(fd); return -1;
    }
    return fd;
}

int udp_send(int fd, const struct sockaddr_in *dest,
             const void *buf, size_t len) {
    ssize_t n = sendto(fd, buf, len, 0,
                       (const struct sockaddr *)dest, sizeof(*dest));
    if (n < 0) { perror("udp_send"); return -1; }
    return (int)n;
}

int udp_recv(int fd, void *buf, size_t len,
             struct sockaddr_in *src_addr) {
    socklen_t addr_len = sizeof(*src_addr);
    ssize_t n = recvfrom(fd, buf, len, 0,
                          (struct sockaddr *)src_addr, &addr_len);
    if (n < 0) { perror("udp_recv"); return -1; }
    return (int)n;
}

int udp_send_presence(int fd, const struct sockaddr_in *dest,
                      const char *username) {
    char buf[MAX_USERNAME_LEN + 8];
    int len = snprintf(buf, sizeof(buf), "PRESENT:%s", username);
    return udp_send(fd, dest, buf, (size_t)len);
}
