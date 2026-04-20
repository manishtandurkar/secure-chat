#include "platform_compat.h"
#include "server.h"
#include "crypto.h"
#include "ratchet.h"
#include "message.h"
#include "tls_layer.h"
#include "adaptive_engine.h"
#include "offline_queue.h"
#include "intrusion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DIRECTED_MSG_LEN (MAX_MSG_LEN - MAX_USERNAME_LEN - 4)

typedef struct {
    int active;
    char username[MAX_USERNAME_LEN];
    SSL *ssl;
    RatchetState *ratchet;
    pthread_mutex_t *ratchet_lock;
    pthread_mutex_t send_lock;
} ConnectedClient;

static ConnectedClient g_connected[MAX_CLIENTS];
static pthread_mutex_t g_connected_lock = PTHREAD_MUTEX_INITIALIZER;

static void build_online_user_list(char *out, size_t out_len, const char *exclude_username) {
    out[0] = '\0';

    pthread_mutex_lock(&g_connected_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_connected[i].active) {
            continue;
        }

        if (exclude_username && strcmp(g_connected[i].username, exclude_username) == 0) {
            continue;
        }

        if (out[0] != '\0') {
            strncat(out, ",", out_len - strlen(out) - 1);
        }
        strncat(out, g_connected[i].username, out_len - strlen(out) - 1);
    }
    pthread_mutex_unlock(&g_connected_lock);
}

static void send_control_message(SSL *ssl, uint8_t msg_type, const uint8_t *payload, uint32_t payload_len) {
    MsgHeader hdr = {0};
    hdr.version = PROTOCOL_VERSION;
    hdr.msg_type = msg_type;
    hdr.priority = PRIORITY_NORMAL;
    hdr.flags = 0;
    hdr.payload_len = htonl(payload_len);
    hdr.checksum = 0;
    generate_random_bytes(hdr.msg_id, MSG_ID_LEN);

    (void)tls_send(ssl, &hdr, sizeof(hdr));
    if (payload_len > 0 && payload != NULL) {
        (void)tls_send(ssl, payload, (int)payload_len);
    }
}

static void register_connected_client(const char *username,
                                      SSL *ssl,
                                      RatchetState *ratchet,
                                      pthread_mutex_t *ratchet_lock) {
    pthread_mutex_lock(&g_connected_lock);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_connected[i].active && strcmp(g_connected[i].username, username) == 0) {
            g_connected[i].ssl = ssl;
            g_connected[i].ratchet = ratchet;
            g_connected[i].ratchet_lock = ratchet_lock;
            pthread_mutex_unlock(&g_connected_lock);
            return;
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_connected[i].active) {
            g_connected[i].active = 1;
            strncpy(g_connected[i].username, username, MAX_USERNAME_LEN - 1);
            g_connected[i].username[MAX_USERNAME_LEN - 1] = '\0';
            g_connected[i].ssl = ssl;
            g_connected[i].ratchet = ratchet;
            g_connected[i].ratchet_lock = ratchet_lock;
            pthread_mutex_init(&g_connected[i].send_lock, NULL);
            pthread_mutex_unlock(&g_connected_lock);
            return;
        }
    }

    pthread_mutex_unlock(&g_connected_lock);
}

static void unregister_connected_client(const char *username) {
    pthread_mutex_lock(&g_connected_lock);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_connected[i].active && strcmp(g_connected[i].username, username) == 0) {
            g_connected[i].active = 0;
            g_connected[i].username[0] = '\0';
            g_connected[i].ssl = NULL;
            g_connected[i].ratchet = NULL;
            g_connected[i].ratchet_lock = NULL;
            pthread_mutex_destroy(&g_connected[i].send_lock);
            break;
        }
    }

    pthread_mutex_unlock(&g_connected_lock);
}

static int parse_directed_message(const uint8_t *plaintext,
                                  int plaintext_len,
                                  char *recipient_out,
                                  size_t recipient_len,
                                  char *body_out,
                                  size_t body_len) {
    if (plaintext_len <= 0 || plaintext[0] != '@') {
        return -1;
    }

    const char *text = (const char *)plaintext;
    const char *space = strchr(text, ' ');
    if (!space) {
        return -1;
    }

    size_t user_len = (size_t)(space - (text + 1));
    if (user_len == 0 || user_len >= recipient_len) {
        return -1;
    }

    memcpy(recipient_out, text + 1, user_len);
    recipient_out[user_len] = '\0';

    const char *body = space + 1;
    while (*body == ' ') {
        body++;
    }

    if (*body == '\0') {
        return -1;
    }

    strncpy(body_out, body, body_len - 1);
    body_out[body_len - 1] = '\0';
    return 0;
}

static int route_directed_message(const char *sender,
                                  const char *recipient,
                                  const char *body,
                                  uint8_t priority,
                                  const uint8_t msg_id[MSG_ID_LEN]) {
    char delivered_text[MAX_MSG_LEN];
    snprintf(delivered_text, sizeof(delivered_text), "%s: %s", sender, body);

    pthread_mutex_lock(&g_connected_lock);

    if (strcmp(recipient, "all") == 0) {
        int delivered_count = 0;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!g_connected[i].active || strcmp(g_connected[i].username, sender) == 0) {
                continue;
            }

            ConnectedClient *target = &g_connected[i];

            uint8_t padded[MSG_PADDED_SIZE];
            if (msg_pad((const uint8_t *)delivered_text, strlen(delivered_text), padded) != SUCCESS) {
                continue;
            }

            uint8_t iv[AES_IV_LEN];
            if (aes_generate_iv(iv) != SUCCESS) {
                continue;
            }

            uint8_t msg_key[RATCHET_KEY_LEN];
            pthread_mutex_lock(target->ratchet_lock);
            if (ratchet_send_step(target->ratchet, msg_key) != SUCCESS) {
                pthread_mutex_unlock(target->ratchet_lock);
                OPENSSL_cleanse(msg_key, sizeof(msg_key));
                continue;
            }
            pthread_mutex_unlock(target->ratchet_lock);

            uint8_t ciphertext[MSG_PADDED_SIZE + 64];
            int ciphertext_len = aes_encrypt(msg_key, iv, padded, MSG_PADDED_SIZE, ciphertext);
            OPENSSL_cleanse(msg_key, sizeof(msg_key));
            if (ciphertext_len < 0) {
                continue;
            }

            uint32_t payload_len = AES_IV_LEN + (uint32_t)ciphertext_len;
            uint8_t *payload = malloc(payload_len);
            if (!payload) {
                continue;
            }

            memcpy(payload, iv, AES_IV_LEN);
            memcpy(payload + AES_IV_LEN, ciphertext, (size_t)ciphertext_len);

            MsgHeader out_hdr = {0};
            out_hdr.version = PROTOCOL_VERSION;
            out_hdr.msg_type = MSG_CHAT;
            out_hdr.priority = priority;
            out_hdr.flags = 0;
            out_hdr.payload_len = htonl(payload_len);
            out_hdr.checksum = 0;
            generate_random_bytes(out_hdr.msg_id, MSG_ID_LEN);

            pthread_mutex_lock(&target->send_lock);
            int ok = (tls_send(target->ssl, &out_hdr, sizeof(out_hdr)) == (int)sizeof(out_hdr) &&
                      tls_send(target->ssl, payload, (int)payload_len) == (int)payload_len);
            pthread_mutex_unlock(&target->send_lock);

            free(payload);
            if (ok) {
                delivered_count++;
            }
        }

        pthread_mutex_unlock(&g_connected_lock);
        return delivered_count > 0 ? 0 : -1;
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_connected[i].active && strcmp(g_connected[i].username, recipient) == 0) {
            ConnectedClient *target = &g_connected[i];

            uint8_t padded[MSG_PADDED_SIZE];
            if (msg_pad((const uint8_t *)delivered_text, strlen(delivered_text), padded) != SUCCESS) {
                pthread_mutex_unlock(&g_connected_lock);
                return -1;
            }

            uint8_t iv[AES_IV_LEN];
            if (aes_generate_iv(iv) != SUCCESS) {
                pthread_mutex_unlock(&g_connected_lock);
                return -1;
            }

            uint8_t msg_key[RATCHET_KEY_LEN];
            pthread_mutex_lock(target->ratchet_lock);
            if (ratchet_send_step(target->ratchet, msg_key) != SUCCESS) {
                pthread_mutex_unlock(target->ratchet_lock);
                OPENSSL_cleanse(msg_key, sizeof(msg_key));
                pthread_mutex_unlock(&g_connected_lock);
                return -1;
            }
            pthread_mutex_unlock(target->ratchet_lock);

            uint8_t ciphertext[MSG_PADDED_SIZE + 64];
            int ciphertext_len = aes_encrypt(msg_key, iv, padded, MSG_PADDED_SIZE, ciphertext);
            OPENSSL_cleanse(msg_key, sizeof(msg_key));

            if (ciphertext_len < 0) {
                pthread_mutex_unlock(&g_connected_lock);
                return -1;
            }

            uint32_t payload_len = AES_IV_LEN + (uint32_t)ciphertext_len;
            uint8_t *payload = malloc(payload_len);
            if (!payload) {
                pthread_mutex_unlock(&g_connected_lock);
                return -1;
            }

            memcpy(payload, iv, AES_IV_LEN);
            memcpy(payload + AES_IV_LEN, ciphertext, (size_t)ciphertext_len);

            MsgHeader out_hdr = {0};
            out_hdr.version = PROTOCOL_VERSION;
            out_hdr.msg_type = MSG_CHAT;
            out_hdr.priority = priority;
            out_hdr.flags = 0;
            out_hdr.payload_len = htonl(payload_len);
            out_hdr.checksum = 0;
            generate_random_bytes(out_hdr.msg_id, MSG_ID_LEN);

            pthread_mutex_lock(&target->send_lock);
            int ok = (tls_send(target->ssl, &out_hdr, sizeof(out_hdr)) == (int)sizeof(out_hdr) &&
                      tls_send(target->ssl, payload, (int)payload_len) == (int)payload_len);
            pthread_mutex_unlock(&target->send_lock);

            free(payload);
            pthread_mutex_unlock(&g_connected_lock);
            return ok ? 0 : -1;
        }
    }

    pthread_mutex_unlock(&g_connected_lock);

    if (queue_store(recipient, body, strlen(body), msg_id) == SUCCESS) {
        return 1;
    }

    return -1;
}

/* Handle individual client connection (runs in thread) */
void handle_client(int connfd, SSL_CTX *tls_ctx, EngineState *engine, Metrics *metrics) {
    (void)engine;
    SSL *ssl = NULL;
    RatchetState ratchet;
    pthread_mutex_t ratchet_lock = PTHREAD_MUTEX_INITIALIZER;
    EVP_PKEY *server_dh = NULL;
    char username[MAX_USERNAME_LEN] = {0};
    int authenticated = 0;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(connfd, (struct sockaddr *)&client_addr, &addr_len);
    char client_ip[64];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

    if (ids_is_blocked(client_ip)) {
        fprintf(stderr, "[Server] Blocked IP attempted connection: %s\n", client_ip);
        socket_close(connfd);
        return;
    }

    ssl = tls_wrap_server_socket(tls_ctx, connfd);
    if (!ssl) {
        fprintf(stderr, "[Server] TLS handshake failed\n");
        socket_close(connfd);
        return;
    }

    printf("[Server] TLS connection established from %s\n", client_ip);

    server_dh = dh_generate_keypair();
    if (!server_dh) {
        fprintf(stderr, "[Server] Failed to generate DH keypair\n");
        goto cleanup;
    }

    MsgHeader dh_init_hdr;
    if (tls_recv(ssl, &dh_init_hdr, sizeof(dh_init_hdr)) != (int)sizeof(dh_init_hdr)) {
        fprintf(stderr, "[Server] Failed to receive DH_INIT\n");
        goto cleanup;
    }

    if (dh_init_hdr.msg_type != MSG_DH_INIT) {
        fprintf(stderr, "[Server] Expected DH_INIT, got type %d\n", dh_init_hdr.msg_type);
        goto cleanup;
    }

    uint8_t client_dh_pubkey[32];
    uint32_t payload_len = ntohl(dh_init_hdr.payload_len);
    if (payload_len != 32 || tls_recv(ssl, client_dh_pubkey, 32) != 32) {
        fprintf(stderr, "[Server] Failed to receive client DH pubkey\n");
        goto cleanup;
    }

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

    if (ratchet_init(&ratchet, shared_secret, secret_len, 0) != SUCCESS) {
        fprintf(stderr, "[Server] Failed to initialize ratchet\n");
        OPENSSL_cleanse(shared_secret, 32);
        EVP_PKEY_free(client_dh);
        goto cleanup;
    }

    OPENSSL_cleanse(shared_secret, 32);
    EVP_PKEY_free(client_dh);

    printf("[Server] Ratchet initialized\n");

    MsgHeader auth_hdr;
    if (tls_recv(ssl, &auth_hdr, sizeof(auth_hdr)) != (int)sizeof(auth_hdr)) {
        fprintf(stderr, "[Server] Failed to receive AUTH_REQ\n");
        goto cleanup;
    }

    if (auth_hdr.msg_type != MSG_AUTH_REQ) {
        fprintf(stderr, "[Server] Expected AUTH_REQ\n");
        goto cleanup;
    }

    payload_len = ntohl(auth_hdr.payload_len);
    uint8_t *auth_payload = malloc(payload_len);
    if (!auth_payload || tls_recv(ssl, auth_payload, (int)payload_len) != (int)payload_len) {
        fprintf(stderr, "[Server] Failed to receive auth payload\n");
        free(auth_payload);
        goto cleanup;
    }

    if (payload_len >= MAX_USERNAME_LEN) {
        strncpy(username, (char *)auth_payload, MAX_USERNAME_LEN - 1);
        username[MAX_USERNAME_LEN - 1] = '\0';
        authenticated = 1;
        printf("[Server] Client authenticated as: %s\n", username);
    }

    free(auth_payload);

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

    register_connected_client(username, ssl, &ratchet, &ratchet_lock);

    int queued_count = queue_count(username);
    if (queued_count > 0) {
        printf("[Server] Pending offline messages for %s: %d\n", username, queued_count);
    }

    printf("[Server] Entering message loop for %s\n", username);

    while (1) {
        MsgHeader hdr;
        int n = tls_recv(ssl, &hdr, sizeof(hdr));

        if (n <= 0) {
            printf("[Server] Client %s disconnected\n", username);
            break;
        }

        if (n != (int)sizeof(hdr)) {
            fprintf(stderr, "[Server] Incomplete header received\n");
            break;
        }

        if (hdr.msg_type == MSG_CHAT) {
            payload_len = ntohl(hdr.payload_len);
            uint8_t *encrypted = malloc(payload_len);

            if (!encrypted || tls_recv(ssl, encrypted, (int)payload_len) != (int)payload_len) {
                fprintf(stderr, "[Server] Failed to receive chat payload\n");
                free(encrypted);
                continue;
            }

            uint8_t *recv_iv = encrypted;
            uint8_t *recv_ciphertext = encrypted + AES_IV_LEN;
            int recv_ciphertext_len = (int)payload_len - AES_IV_LEN;

            uint8_t recv_msg_key[RATCHET_KEY_LEN];
            pthread_mutex_lock(&ratchet_lock);
            if (ratchet_recv_step(&ratchet, recv_msg_key) != SUCCESS) {
                pthread_mutex_unlock(&ratchet_lock);
                fprintf(stderr, "[Server] Ratchet recv step failed\n");
                OPENSSL_cleanse(recv_msg_key, sizeof(recv_msg_key));
                free(encrypted);
                continue;
            }
            pthread_mutex_unlock(&ratchet_lock);

            uint8_t plaintext_buf[MSG_PADDED_SIZE + 64];
            int plaintext_len = aes_decrypt(recv_msg_key, recv_iv, recv_ciphertext,
                                            recv_ciphertext_len, plaintext_buf);
            OPENSSL_cleanse(recv_msg_key, sizeof(recv_msg_key));

            if (plaintext_len < 0) {
                fprintf(stderr, "[Server] Decryption failed\n");
                free(encrypted);
                continue;
            }

            uint8_t unpadded[MSG_PADDED_SIZE];
            int unpadded_len = msg_unpad(plaintext_buf, plaintext_len, unpadded);
            if (unpadded_len < 0) {
                fprintf(stderr, "[Server] Unpadding failed\n");
                free(encrypted);
                continue;
            }
            unpadded[unpadded_len] = '\0';

            char recipient[MAX_USERNAME_LEN] = {0};
            char body[MAX_DIRECTED_MSG_LEN] = {0};
            if (parse_directed_message(unpadded, unpadded_len,
                                       recipient, sizeof(recipient),
                                       body, sizeof(body)) != 0) {
                const char *usage = "Use directed format: @username message";
                send_control_message(ssl, MSG_ERROR, (const uint8_t *)usage, (uint32_t)strlen(usage));
                free(encrypted);
                continue;
            }

            if (strcmp(recipient, username) == 0) {
                const char *msg = "Self-target is blocked. Choose another client.";
                send_control_message(ssl, MSG_ERROR, (const uint8_t *)msg, (uint32_t)strlen(msg));
                free(encrypted);
                continue;
            }

            int route_result = route_directed_message(username, recipient, body, hdr.priority, hdr.msg_id);
            if (route_result == 0) {
                printf("[Server] Routed message %s -> %s\n", username, recipient);
            } else if (route_result == 1) {
                const char *queued = "Recipient offline. Message queued.";
                send_control_message(ssl, MSG_OFFLINE_STORED, (const uint8_t *)queued, (uint32_t)strlen(queued));
                printf("[Server] Recipient %s offline; queued message from %s\n", recipient, username);
            } else {
                const char *err = "Delivery failed for recipient.";
                send_control_message(ssl, MSG_ERROR, (const uint8_t *)err, (uint32_t)strlen(err));
                fprintf(stderr, "[Server] Failed to route message %s -> %s\n", username, recipient);
            }

            free(encrypted);
            continue;
        }

        if (hdr.msg_type == MSG_JOIN_ROOM || hdr.msg_type == MSG_LEAVE_ROOM) {
            printf("[Server] Room operation from %s\n", username);
            continue;
        }

        if (hdr.msg_type == MSG_USER_LIST_REQ) {
            char user_list[1024];
            build_online_user_list(user_list, sizeof(user_list), username);
            send_control_message(ssl, MSG_USER_LIST_RESP,
                                 (const uint8_t *)user_list,
                                 (uint32_t)strlen(user_list));
            continue;
        }

        fprintf(stderr, "[Server] Unknown message type: %d\n", hdr.msg_type);
    }

cleanup:
    if (authenticated) {
        unregister_connected_client(username);
        printf("[Server] Client %s logged out\n", username);
    }

    ratchet_destroy(&ratchet);
    pthread_mutex_destroy(&ratchet_lock);

    if (server_dh) {
        EVP_PKEY_free(server_dh);
    }

    if (ssl) {
        tls_close(ssl);
    }

    close(connfd);
    (void)metrics;
}
