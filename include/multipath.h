#ifndef MULTIPATH_H
#define MULTIPATH_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include "common.h"
#include "adaptive_engine.h"

int  multipath_send(SSL *ssl, int udp_fd,
                    const struct sockaddr_in *udp_dest,
                    const void *payload, size_t payload_len,
                    uint8_t priority,
                    const EngineState *engine);

int  multipath_recv(SSL *ssl, int udp_fd,
                    void *payload_out, size_t buf_len,
                    uint8_t *msg_id_out);

void dedup_add(uint8_t id[MSG_ID_LEN]);
int  dedup_check(const uint8_t id[MSG_ID_LEN]);
void dedup_init(void);

#endif /* MULTIPATH_H */
