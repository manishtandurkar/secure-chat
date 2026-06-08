#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h>
#include "ratchet.h"
#include "adaptive_engine.h"
#include "common.h"

typedef struct {
    SSL        *ssl;
    int         udp_fd;
    char        username[MAX_USERNAME_LEN];
    char        server_host[256];
    int         server_port;
    RatchetState ratchet;
    EngineState  engine;
    int          running;
    void (*log_callback)(const char *msg);
    void (*message_callback)(const char *sender, const char *text, uint8_t priority, uint8_t flags);
    void (*system_callback)(const char *msg);
    void (*users_callback)(const char *user_list);
    char connect_error[256];
} ClientContext;

int  client_connect(ClientContext *ctx,
                    const char *host, int port, const char *username);

int  client_send_chat_message(ClientContext *ctx,
                               const char *recipient,
                               const char *message);

int  client_send_chat_message_ex(ClientContext *ctx,
                                  const char *recipient,
                                  const char *message,
                                  uint8_t priority);

int  client_request_user_list(ClientContext *ctx);

void client_set_log_callback(ClientContext *ctx,
                              void (*cb)(const char *msg));

void client_disconnect(ClientContext *ctx);

#endif /* CLIENT_H */
