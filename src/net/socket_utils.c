#include "socket_utils.h"
#include "message.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    int opt = 1;

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    /* Set SO_REUSEADDR option */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sockfd);
        return -1;
    }

    /* Initialize server address structure */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    /* Bind socket to address */
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    /* Start listening for connections */
    if (listen(sockfd, MAX_CLIENTS) < 0) {
        perror("listen");
        close(sockfd);
        return -1;
    }

    printf("Server listening on port %d\n", port);
    return sockfd;
}

int create_client_socket(void) {
    int sockfd;

    /* Create socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    return sockfd;
}

int connect_to_server(int sockfd, const char *hostname, int port) {
    struct sockaddr_in server_addr;
    struct hostent *server;

    /* Get server hostname */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR: no such host %s\n", hostname);
        return -1;
    }

    /* Initialize server address structure */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(port);

    /* Connect to server */
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return -1;
    }

    printf("Connected to %s:%d\n", hostname, port);
    return 0;
}

/* Phase 1: Regular socket send_all (no TLS) */
int send_all(int sockfd, const void *buf, size_t len) {
    size_t total_sent = 0;
    const char *data = (const char*)buf;

    while (total_sent < len) {
        ssize_t sent = send(sockfd, data + total_sent, len - total_sent, 0);
        if (sent < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            perror("send");
            return -1;
        }
        if (sent == 0) {
            fprintf(stderr, "Connection closed by peer\n");
            return -1;
        }

        total_sent += sent;
    }

    return 0;
}

/* Phase 1: Regular socket recv_all (no TLS) */
int recv_all(int sockfd, void *buf, size_t len) {
    size_t total_received = 0;
    char *data = (char*)buf;

    while (total_received < len) {
        ssize_t received = recv(sockfd, data + total_received, len - total_received, 0);
        if (received < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            perror("recv");
            return -1;
        }
        if (received == 0) {
            fprintf(stderr, "Connection closed by peer\n");
            return -1;
        }

        total_received += received;
    }

    return 0;
}

/* Phase 1: Send message using regular socket (no TLS) */
int send_message(int sockfd, MsgType type, const void *payload, uint32_t payload_len) {
    MsgHeader header;
    
    /* Validate payload length */
    if (payload_len > MAX_MSG_LEN) {
        fprintf(stderr, "Payload too large: %u bytes\n", payload_len);
        return -1;
    }

    /* Build header */
    header.version = PROTOCOL_VERSION;
    header.msg_type = (uint8_t)type;
    header.flags = 0;
    header.payload_len = htonl(payload_len);
    header.checksum = payload ? htonl(calculate_crc32(payload, payload_len)) : 0;

    /* Send header */
    if (send_all(sockfd, &header, sizeof(header)) < 0) {
        return -1;
    }

    /* Send payload if present */
    if (payload_len > 0 && payload) {
        if (send_all(sockfd, payload, payload_len) < 0) {
            return -1;
        }
    }

    return 0;
}

/* Phase 1: Receive message using regular socket (no TLS) */
int recv_message(int sockfd, MsgHeader *header_out, void **payload_out) {
    uint32_t payload_len;
    uint32_t checksum;
    void *payload = NULL;

    /* Receive header */
    if (recv_all(sockfd, header_out, sizeof(*header_out)) < 0) {
        return -1;
    }

    /* Validate header */
    if (header_out->version != PROTOCOL_VERSION) {
        fprintf(stderr, "Invalid protocol version: %u\n", header_out->version);
        return -1;
    }

    /* Convert from network byte order */
    payload_len = ntohl(header_out->payload_len);
    checksum = ntohl(header_out->checksum);

    /* Validate payload length */
    if (payload_len > MAX_MSG_LEN) {
        fprintf(stderr, "Payload too large: %u bytes\n", payload_len);
        return -1;
    }

    /* Receive payload if present */
    if (payload_len > 0) {
        payload = malloc(payload_len);
        if (!payload) {
            perror("malloc");
            return -1;
        }

        if (recv_all(sockfd, payload, payload_len) < 0) {
            free(payload);
            return -1;
        }

        /* Verify checksum */
        if (checksum != calculate_crc32(payload, payload_len)) {
            fprintf(stderr, "Checksum mismatch\n");
            free(payload);
            return -1;
        }
    }

    /* Update header to host byte order */
    header_out->payload_len = payload_len;
    header_out->checksum = checksum;
    *payload_out = payload;

    return 0;
}

int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl F_GETFL");
        return -1;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("fcntl F_SETFL");
        return -1;
    }

    return 0;
}

int set_reuseaddr(int sockfd) {
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        return -1;
    }
    return 0;
}