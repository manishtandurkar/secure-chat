#ifndef SERVER_H
#define SERVER_H

#include <pthread.h>
#include <openssl/ssl.h>
#include "ratchet.h"
#include "adaptive_engine.h"
#include "common.h"

typedef struct {
    int         fd;
    SSL        *ssl;
    char        username[MAX_USERNAME_LEN];
    char        ip_str[48];
    RatchetState ratchet;
    int         active;
    pthread_t   thread_id;
} ClientEntry;

/* Server-wide shared state */
extern EngineState g_engine_state;
extern Metrics     g_metrics;

typedef struct {
    int    connfd;
    SSL   *ssl;
    char   ip_str[48];
} HandlerArg;

void *handle_client(void *arg);

/* Room management */
int  room_join(const char *room, const char *username);
int  room_leave(const char *room, const char *username);
void room_broadcast(const char *room, const char *sender,
                    const void *payload, size_t len, SSL_CTX *ctx);

/* Auth */
int  auth_verify(const char *username, const uint8_t *sig, size_t sig_len,
                 const uint8_t *challenge, size_t challenge_len);
int  auth_register_pubkey(const char *username, const char *pem_pubkey);

/* Client table */
void     client_table_init(void);
int      client_table_add(ClientEntry *entry);
void     client_table_remove(const char *username);
ClientEntry *client_table_find(const char *username);
int      client_table_list(char *buf, size_t buf_len);

#endif /* SERVER_H */
