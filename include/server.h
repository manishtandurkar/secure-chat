#ifndef SERVER_H
#define SERVER_H

#include "common.h"
#include "tls_layer.h"
#include "adaptive_engine.h"

/* Forward declarations */
typedef struct evp_pkey_st EVP_PKEY;

/**
 * Main server entry point
 * Binds to SERVER_PORT and handles incoming connections
 */
int server_main(int argc, char *argv[]);

/**
 * Handle a client connection (called in child process after fork)
 * Performs TLS handshake, DH exchange, authentication, and message routing
 */
void handle_client(int connfd, SSL_CTX *ssl_ctx, EngineState *engine, Metrics *metrics);

/**
 * Signal handler for SIGCHLD to reap zombie processes
 */
void sigchld_handler(int sig);

/**
 * Initialize server resources (TLS context, UDP socket, etc.)
 */
int server_init(void);

/**
 * Cleanup server resources
 */
void server_cleanup(void);

/* Authentication manager functions */

/**
 * Register user public key for authentication
 */
int auth_register_pubkey(const char *username, EVP_PKEY *pubkey);

/**
 * Verify RSA signature for authentication
 */
int auth_verify_login(const char *username, const unsigned char *data,
                      size_t data_len, const unsigned char *signature,
                      size_t sig_len);

/* Room manager functions */

/**
 * Add user to chat room
 */
int room_add_member(const char *room_name, const char *username);

/**
 * Remove user from chat room
 */
int room_remove_member(const char *room_name, const char *username);

/**
 * Get list of room members
 */
int room_get_members(const char *room_name, char members[][MAX_USERNAME_LEN], int max_members);

#endif /* SERVER_H */