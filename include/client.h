#ifndef CLIENT_H
#define CLIENT_H

#include "platform_compat.h"
#include "common.h"
#include "tls_layer.h"
#include "ratchet.h"
#include "priority_queue.h"
#include <pthread.h>
#include <openssl/evp.h>

/* Client state structure */
typedef struct {
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    char username[MAX_USERNAME_LEN];
    char current_room[MAX_ROOM_NAME_LEN];
    int tcp_socket;
    int udp_socket;
    struct sockaddr_in server_addr;
    int running;
    pthread_t recv_thread;
    pthread_t send_thread;
    pthread_t udp_thread;
    RatchetState ratchet;
    EVP_PKEY *rsa_keypair;
    uint8_t dedup_set[DEDUP_WINDOW][MSG_ID_LEN];
    int dedup_idx;
    pthread_mutex_t ratchet_lock;
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
 * Thread function for UDP presence and backup messages
 */
void *udp_thread_func(void *arg);

/**
 * Perform DH key exchange with server
 */
int perform_dh_exchange(ClientState *client);

/**
 * Authenticate with server using RSA signature
 */
int authenticate_with_server(ClientState *client);

/**
 * Save ratchet state to encrypted file
 */
int save_ratchet_state(ClientState *client);

/**
 * Load ratchet state from encrypted file
 */
int load_ratchet_state(ClientState *client);

/**
 * Check if message ID is in dedup set
 */
int is_duplicate(ClientState *client, const uint8_t *msg_id);

/**
 * Add message ID to dedup set
 */
void add_to_dedup(ClientState *client, const uint8_t *msg_id);

#endif /* CLIENT_H */