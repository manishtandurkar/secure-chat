#ifndef SOCKET_UTILS_H
#define SOCKET_UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/ssl.h>
#include "message.h"

int  socket_create_server(int port);
int  socket_create_client(const char *host, int port);
int  socket_create_udp(int port);

int  send_all(int fd, const void *buf, size_t len);
int  recv_all(int fd, void *buf, size_t len);

int  send_message(SSL *ssl, uint8_t msg_type, uint8_t priority,
                  uint8_t flags, const uint8_t msg_id[MSG_ID_LEN],
                  const void *payload, uint32_t payload_len);

int  recv_message(SSL *ssl, MsgHeader *hdr_out,
                  void *payload_buf, size_t buf_len);

void socket_set_nonblocking(int fd);
void socket_set_reuseaddr(int fd);

#endif /* SOCKET_UTILS_H */
