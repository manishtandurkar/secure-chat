#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include "message.h"
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * Create a TCP socket for server use
 * Returns socket fd or -1 on error
 */
int create_server_socket(int port);

/**
 * Create a TCP socket for client use
 * Returns socket fd or -1 on error
 */
int create_client_socket(void);

/**
 * Connect client socket to server
 * Returns 0 on success, -1 on error
 */
int connect_to_server(int sockfd, const char *hostname, int port);

/**
 * Phase 1: Send exactly len bytes over regular socket. Handles partial sends (EINTR safe).
 * Returns 0 on success, -1 on error.
 * TODO Phase 5: Convert to SSL version
 */
int send_all(int sockfd, const void *buf, size_t len);

/**
 * Phase 1: Read exactly len bytes over regular socket. Handles partial reads.
 * Returns 0 on success, -1 on error / connection closed.
 * TODO Phase 5: Convert to SSL version
 */
int recv_all(int sockfd, void *buf, size_t len);

/**
 * Phase 1: Send a complete message: write header then payload.
 * payload may be NULL if payload_len == 0.
 * Returns 0 on success, -1 on error.
 * TODO Phase 5: Convert to SSL version
 */
int send_message(int sockfd, MsgType type, const void *payload, uint32_t payload_len);

/**
 * Phase 1: Read one complete message. Allocates *payload_out with malloc().
 * Caller must free(*payload_out). Returns 0 or -1.
 * TODO Phase 5: Convert to SSL version
 */
int recv_message(int sockfd, MsgHeader *header_out, void **payload_out);

/**
 * Set socket to non-blocking mode
 * Returns 0 on success, -1 on error
 */
int set_nonblocking(int sockfd);

/**
 * Set SO_REUSEADDR option on socket
 * Returns 0 on success, -1 on error
 */
int set_reuseaddr(int sockfd);

#endif /* SOCKET_UTILS_H */