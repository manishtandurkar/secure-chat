#include "server.h"
#include "crypto.h"
#include "ratchet.h"
#include "message.h"
#include "tls_layer.h"
#include "adaptive_engine.h"
#include "multipath.h"
#include "offline_queue.h"
#include "intrusion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

/* Handle individual client connection (runs in child process) */
void handle_client(int connfd, SSL_CTX *tls_ctx, EngineState *engine, Metrics *metrics) {
    SSL *ssl = NULL;
    RatchetState ratchet;
    char username[MAX_USERNAME_LEN] = {0};
    int authenticated = 0;
    
    /* Get client IP for IDS */
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(connfd, (struct sockaddr *)&client_addr, &addr_len);
    char client_ip[64];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    
    /* Check if IP is blocked */
    if (ids_is_blocked(client_ip)) {
        fprintf(stderr, "[Server] Blocked IP attempted connection: %s\n", client_ip);
        close(connfd);
        return;
    }
    
    /* Wrap connection with TLS */
    ssl = tls_wrap_server_socket(tls_ctx, connfd);
    if (!ssl) {
        fprintf(stderr, "[Server] TLS handshake failed\n");
        close(connfd);
        return;
    }
    
    printf("[Server] TLS connection established from %s\n", client_ip);
    
    /* ===== DH Exchange Phase ===== */
    
    /* Generate server DH keypair */
    EVP_PKEY *server_dh = dh_generate_keypair();
    if (!server_dh) {
        fprintf(stderr, "[Server] Failed to generate DH keypair\n");
        goto cleanup;
    }
    
    /* Receive MSG_DH_INIT from client */
    MsgHeader dh_init_hdr;
    if (tls_recv(ssl, &dh_init_hdr, sizeof(dh_init_hdr)) != sizeof(dh_init_hdr)) {
        fprintf(stderr, "[Server] Failed to receive DH_INIT\n");
        goto cleanup;
    }
    
    if (dh_init_hdr.msg_type != MSG_DH_INIT) {
        fprintf(stderr, "[Server] Expected DH_INIT, got type %d\n", dh_init_hdr.msg_type);
        goto cleanup;
    }
    
    /* Receive client's DH public key */
    uint8_t client_dh_pubkey[32];
    uint32_t payload_len = ntohl(dh_init_hdr.payload_len);
    if (payload_len != 32 || tls_recv(ssl, client_dh_pubkey, 32) != 32) {
        fprintf(stderr, "[Server] Failed to receive client DH pubkey\n");
        goto cleanup;
    }
    
    /* Send MSG_DH_RESP with our public key */
    uint8_t server_dh_pubkey[32];
    size_t pubkey_len = 32;
    if (dh_get_public_key(server_dh, server_dh_pubkey, &pubkey_len) != SUCCESS) {
        fprintf(stderr, "[Server] Failed to extract DH pubkey\n");
        goto cleanup;
    }
    
    MsgHeader dh_resp_hdr = {
        .version = PROTOCOL_VERSION,
        .msg_type = MSG_DH_RESP,
        .priority = PRIORITY_NORMAL,
        .flags = 0,
        .payload_len = htonl(32),
        .checksum = 0
    };
    
    generate_random_bytes(dh_resp_hdr.msg_id, MSG_ID_LEN);
    
    if (tls_send(ssl, &dh_resp_hdr, sizeof(dh_resp_hdr)) <= 0 ||
        tls_send(ssl, server_dh_pubkey, 32) <= 0) {
        fprintf(stderr, "[Server] Failed to send DH_RESP\n");
        goto cleanup;
    }
    
    /* Compute shared secret and initialize ratchet */
    EVP_PKEY *client_dh = dh_pubkey_from_bytes(client_dh_pubkey, 32);
    if (!client_dh) {
        fprintf(stderr, "[Server] Failed to parse client DH pubkey\n");
        goto cleanup;
    }
    
    uint8_t shared_secret[32];
    size_t secret_len = 32;
    if (dh_compute_shared_secret(server_dh, client_dh, shared_secret, &secret_len) != SUCCESS) {
        fprintf(stderr, "[Server] Failed to compute shared secret\n");
        EVP_PKEY_free(client_dh);
        goto cleanup;
    }
    
    /* Initialize ratchet (server is responder) */
    if (ratchet_init(&ratchet, shared_secret, secret_len, 0) != SUCCESS) {
        fprintf(stderr, "[Server] Failed to initialize ratchet\n");
        OPENSSL_cleanse(shared_secret, 32);
        EVP_PKEY_free(client_dh);
        goto cleanup;
    }
    
    OPENSSL_cleanse(shared_secret, 32);
    EVP_PKEY_free(client_dh);
    
    printf("[Server] Ratchet initialized\n");
    
    /* ===== Authentication Phase ===== */
    
    /* Receive MSG_AUTH_REQ */
    MsgHeader auth_hdr;
    if (tls_recv(ssl, &auth_hdr, sizeof(auth_hdr)) != sizeof(auth_hdr)) {
        fprintf(stderr, "[Server] Failed to receive AUTH_REQ\n");
        goto cleanup;
    }
    
    if (auth_hdr.msg_type != MSG_AUTH_REQ) {
        fprintf(stderr, "[Server] Expected AUTH_REQ\n");
        goto cleanup;
    }
    
    /* For simplicity, accept any username (in production would verify RSA signature) */
    payload_len = ntohl(auth_hdr.payload_len);
    uint8_t *auth_payload = malloc(payload_len);
    if (!auth_payload || tls_recv(ssl, auth_payload, payload_len) != (int)payload_len) {
        fprintf(stderr, "[Server] Failed to receive auth payload\n");
        free(auth_payload);
        goto cleanup;
    }
    
    /* Extract username (simplified - would parse AuthRequest struct) */
    if (payload_len >= MAX_USERNAME_LEN) {
        strncpy(username, (char *)auth_payload, MAX_USERNAME_LEN - 1);
        authenticated = 1;
        printf("[Server] Client authenticated as: %s\n", username);
    }
    
    free(auth_payload);
    
    /* Send MSG_AUTH_OK */
    MsgHeader auth_ok_hdr = {
        .version = PROTOCOL_VERSION,
        .msg_type = MSG_AUTH_OK,
        .priority = PRIORITY_NORMAL,
        .flags = 0,
        .payload_len = 0,
        .checksum = 0
    };
    
    generate_random_bytes(auth_ok_hdr.msg_id, MSG_ID_LEN);
    
    if (tls_send(ssl, &auth_ok_hdr, sizeof(auth_ok_hdr)) <= 0) {
        fprintf(stderr, "[Server] Failed to send AUTH_OK\n");
        goto cleanup;
    }
    
    /* ===== Drain offline queue ===== */
    
    int queued_count = queue_count(username);
    if (queued_count > 0) {
        printf("[Server] Draining %d offline messages for %s\n", queued_count, username);
        /* Would implement queue_drain here with proper callback */
    }
    
    /* ===== Message Loop ===== */
    
    printf("[Server] Entering message loop for %s\n", username);
    
    while (1) {
        MsgHeader hdr;
        int n = tls_recv(ssl, &hdr, sizeof(hdr));
        
        if (n <= 0) {
            printf("[Server] Client %s disconnected\n", username);
            break;
        }
        
        if (n != sizeof(hdr)) {
            fprintf(stderr, "[Server] Incomplete header received\n");
            break;
        }
        
        /* Handle different message types */
        switch (hdr.msg_type) {
            case MSG_CHAT: {
                /* Receive encrypted message payload */
                payload_len = ntohl(hdr.payload_len);
                uint8_t *encrypted = malloc(payload_len);
                
                if (!encrypted || tls_recv(ssl, encrypted, payload_len) != (int)payload_len) {
                    fprintf(stderr, "[Server] Failed to receive chat payload\n");
                    free(encrypted);
                    continue;
                }
                
                /* Echo back (simplified - would route to recipient) */
                printf("[Server] Echoing message from %s (len=%u)\n", username, payload_len);
                
                tls_send(ssl, &hdr, sizeof(hdr));
                tls_send(ssl, encrypted, payload_len);
                
                free(encrypted);
                break;
            }
            
            case MSG_JOIN_ROOM:
            case MSG_LEAVE_ROOM:
                /* Would handle room management */
                printf("[Server] Room operation from %s\n", username);
                break;
                
            default:
                fprintf(stderr, "[Server] Unknown message type: %d\n", hdr.msg_type);
                break;
        }
    }
    
cleanup:
    if (authenticated) {
        printf("[Server] Client %s logged out\n", username);
    }
    
    ratchet_destroy(&ratchet);
    
    if (server_dh) {
        EVP_PKEY_free(server_dh);
    }
    
    if (ssl) {
        tls_close(ssl);
    }
    
    close(connfd);
}
