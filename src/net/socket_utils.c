#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include "socket_utils.h"
#include "tls_layer.h"
#include "message.h"
#include "common.h"

int socket_create_server(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    socket_set_reuseaddr(fd);

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, 32) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

int socket_create_client(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        perror("inet_pton"); close(fd); return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(fd); return -1;
    }
    return fd;
}

int socket_create_udp(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket udp"); return -1; }

    socket_set_reuseaddr(fd);

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind udp"); close(fd); return -1;
    }
    return fd;
}

void socket_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void socket_set_reuseaddr(int fd) {
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

int send_all(int fd, const void *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, (const char *)buf + sent, len - sent);
        if (n <= 0) { perror("send_all"); return -1; }
        sent += (size_t)n;
    }
    return 0;
}

int recv_all(int fd, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char *)buf + got, len - got);
        if (n <= 0) { if (n < 0) perror("recv_all"); return -1; }
        got += (size_t)n;
    }
    return 0;
}

int send_message(SSL *ssl, uint8_t msg_type, uint8_t priority,
                 uint8_t flags, const uint8_t msg_id[MSG_ID_LEN],
                 const void *payload, uint32_t payload_len) {
    MsgHeader hdr = {0};
    hdr.version     = 0x02;
    hdr.msg_type    = msg_type;
    hdr.priority    = priority;
    hdr.flags       = flags;
    hdr.payload_len = htonl(payload_len);
    hdr.checksum    = htonl(msg_crc32(payload, payload_len));
    if (msg_id) memcpy(hdr.msg_id, msg_id, MSG_ID_LEN);

    if (tls_send(ssl, &hdr, MSG_HEADER_SIZE) < 0) return -1;
    if (payload_len > 0 && payload) {
        if (tls_send(ssl, payload, (int)payload_len) < 0) return -1;
    }
    return 0;
}

int recv_message(SSL *ssl, MsgHeader *hdr_out,
                 void *payload_buf, size_t buf_len) {
    if (tls_recv(ssl, hdr_out, MSG_HEADER_SIZE) < 0) return -1;

    hdr_out->payload_len = ntohl(hdr_out->payload_len);
    hdr_out->checksum    = ntohl(hdr_out->checksum);

    if (hdr_out->payload_len > buf_len) {
        fprintf(stderr, "recv_message: payload too large %u\n", hdr_out->payload_len);
        return -1;
    }
    if (hdr_out->payload_len > 0) {
        if (tls_recv(ssl, payload_buf, (int)hdr_out->payload_len) < 0) return -1;
        uint32_t got_crc = msg_crc32(payload_buf, hdr_out->payload_len);
        if (got_crc != hdr_out->checksum) {
            fprintf(stderr, "recv_message: CRC mismatch\n");
            return -1;
        }
    }
    return 0;
}
