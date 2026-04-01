#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include "tls_layer.h"
#include <pthread.h>

/* Client state structure */
typedef struct {
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    char username[MAX_USERNAME_LEN];
    char current_room[MAX_ROOM_NAME_LEN];
    int udp_socket;
    int running;
    pthread_t recv_thread;
    pthread_t send_thread;
    unsigned char aes_key[AES_KEY_LEN];
} ClientState;

/**
 * Main client entry point
 * Usage: ./client <hostname> <port> <username>
 */
int client_main(int argc, char *argv[]);

/**
 * Initialize client state and connect to server
 */
int client_init(ClientState *client, const char *hostname, int port, const char *username);

/**
 * Start client threads (recv and send)
 */
int client_start_threads(ClientState *client);

/**
 * Wait for client threads to finish
 */
void client_join_threads(ClientState *client);

/**
 * Cleanup client resources
 */
void client_cleanup(ClientState *client);

/**
 * Thread function for receiving messages from server
 */
void *recv_thread_func(void *arg);

/**
 * Thread function for sending messages to server
 */
void *send_thread_func(void *arg);

/**
 * Perform DH key exchange with server
 */
int perform_dh_exchange(ClientState *client);

/**
 * Authenticate with server using RSA signature
 */
int authenticate_with_server(ClientState *client);

#endif /* CLIENT_H */