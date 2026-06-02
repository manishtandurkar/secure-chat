#include "platform_compat.h"
#include "server.h"
#include "crypto.h"
#include "prekey.h"
#include "message.h"
#include "tls_layer.h"
#include "adaptive_engine.h"
#include "offline_queue.h"
#include "intrusion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int active;
    char username[MAX_USERNAME_LEN];
    SSL *ssl;
    pthread_mutex_t send_lock;
} ConnectedClient;

static ConnectedClient g_connected[MAX_CLIENTS];
static pthread_mutex_t g_connected_lock = PTHREAD_MUTEX_INITIALIZER;

/* Static cache for Client PreKey Bundles */
static struct {
    char username[MAX_USERNAME_LEN];
    PreKeyBundle bundle;
    int has_bundle;
} g_client_prekeys[MAX_CLIENTS];
static pthread_mutex_t g_prekeys_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void register_connected_client(const char *username, SSL *ssl) {
    pthread_mutex_lock(&g_connected_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_connected[i].active && strcmp(g_connected[i].username, username) == 0) {
            g_connected[i].ssl = ssl;
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
            pthread_mutex_destroy(&g_connected[i].send_lock);
            break;
        }
    }
    pthread_mutex_unlock(&g_connected_lock);
}

void broadcast_engine_state(AdaptiveMode new_mode) {
    uint8_t mode_byte = (uint8_t)new_mode;
    pthread_mutex_lock(&g_connected_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_connected[i].active) continue;
        send_control_message(g_connected[i].ssl, MSG_ENGINE_STATE, &mode_byte, 1);
    }
    pthread_mutex_unlock(&g_connected_lock);
    fprintf(stderr, "[Engine] Broadcast mode=%d to connected clients\n", (int)new_mode);
}

/* Offline delivery helper: relays ciphertext blindly */
static int offline_delivery_callback(const void *payload, size_t len, void *ctx) {
    SSL *ssl = (SSL *)ctx;
    MsgHeader out_hdr = {0};
    out_hdr.version = PROTOCOL_VERSION;
    out_hdr.msg_type = MSG_CHAT;
    out_hdr.priority = PRIORITY_NORMAL;
    out_hdr.flags = 0x02; /* Indicate offline recovery */
    out_hdr.payload_len = htonl((uint32_t)len);
    generate_random_bytes(out_hdr.msg_id, MSG_ID_LEN);

    int ok = (tls_send(ssl, &out_hdr, sizeof(out_hdr)) == (int)sizeof(out_hdr) &&
              tls_send(ssl, payload, (int)len) == (int)len);
    return ok ? SUCCESS : ERROR_NETWORK;
}

/* Blind routing of E2EE payload to active user or offline queue */
static int route_directed_message(const char *sender,
                                  const char *recipient,
                                  const E2EEChatPayload *payload,
                                  uint8_t priority,
                                  const uint8_t msg_id[MSG_ID_LEN]) {
    pthread_mutex_lock(&g_connected_lock);

    /* Broadcast blind relay to '@all' */
    if (strcmp(recipient, "all") == 0) {
        int delivered_count = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!g_connected[i].active || strcmp(g_connected[i].username, sender) == 0) {
                continue;
            }

            ConnectedClient *target = &g_connected[i];
            MsgHeader out_hdr = {0};
            out_hdr.version = PROTOCOL_VERSION;
            out_hdr.msg_type = MSG_CHAT;
            out_hdr.priority = priority;
            out_hdr.flags = 0;
            out_hdr.payload_len = htonl(sizeof(E2EEChatPayload));
            memcpy(out_hdr.msg_id, msg_id, MSG_ID_LEN);

            pthread_mutex_lock(&target->send_lock);
            int ok = (tls_send(target->ssl, &out_hdr, sizeof(out_hdr)) == (int)sizeof(out_hdr) &&
                      tls_send(target->ssl, payload, sizeof(E2EEChatPayload)) == (int)sizeof(E2EEChatPayload));
            pthread_mutex_unlock(&target->send_lock);

            if (ok) delivered_count++;
        }
        pthread_mutex_unlock(&g_connected_lock);
        return delivered_count > 0 ? 0 : -1;
    }

    /* Directed relay to specific online target */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_connected[i].active && strcmp(g_connected[i].username, recipient) == 0) {
            ConnectedClient *target = &g_connected[i];
            MsgHeader out_hdr = {0};
            out_hdr.version = PROTOCOL_VERSION;
            out_hdr.msg_type = MSG_CHAT;
            out_hdr.priority = priority;
            out_hdr.flags = 0;
            out_hdr.payload_len = htonl(sizeof(E2EEChatPayload));
            memcpy(out_hdr.msg_id, msg_id, MSG_ID_LEN);

            pthread_mutex_lock(&target->send_lock);
            int ok = (tls_send(target->ssl, &out_hdr, sizeof(out_hdr)) == (int)sizeof(out_hdr) &&
                      tls_send(target->ssl, payload, sizeof(E2EEChatPayload)) == (int)sizeof(E2EEChatPayload));
            pthread_mutex_unlock(&target->send_lock);

            pthread_mutex_unlock(&g_connected_lock);
            return ok ? 0 : -1;
        }
    }
    pthread_mutex_unlock(&g_connected_lock);

    /* Recipient offline: store exact encrypted end-to-end payload unmodified */
    if (queue_store(recipient, payload, sizeof(E2EEChatPayload), msg_id) == SUCCESS) {
        return 1;
    }

    return -1;
}

void handle_client(int connfd, SSL_CTX *tls_ctx, EngineState *engine, Metrics *metrics) {
    (void)engine;
    SSL *ssl = NULL;
    char username[MAX_USERNAME_LEN] = {0};
    int authenticated = 0;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(connfd, (struct sockaddr *)&client_addr, &addr_len);
    char client_ip[64];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

    ids_record_connection(client_ip, metrics);
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

    /* Challenge-Response Authentication Handshake Loop */
    uint8_t challenge[32];
    generate_random_bytes(challenge, 32);

    /* Step 1: Client uploads their public PreKey bundle or initiates handshake */
    MsgHeader upload_hdr;
    if (tls_recv(ssl, &upload_hdr, sizeof(upload_hdr)) != (int)sizeof(upload_hdr)) {
        fprintf(stderr, "[Server] Failed to receive handshake header\n");
        goto cleanup;
    }

    if (upload_hdr.msg_type != MSG_PREKEY_UPLOAD) {
        fprintf(stderr, "[Server] Expected MSG_PREKEY_UPLOAD, got %d\n", upload_hdr.msg_type);
        goto cleanup;
    }

    uint32_t payload_len = ntohl(upload_hdr.payload_len);
    if (payload_len != sizeof(PreKeyBundle)) {
        fprintf(stderr, "[Server] Invalid PreKey bundle size: %u\n", payload_len);
        goto cleanup;
    }

    PreKeyBundle received_bundle;
    if (tls_recv(ssl, &received_bundle, sizeof(PreKeyBundle)) != sizeof(PreKeyBundle)) {
        fprintf(stderr, "[Server] Failed to receive PreKey bundle\n");
        goto cleanup;
    }

    /* Challenge-Response request setup */
    MsgHeader challenge_hdr = {
        .version = PROTOCOL_VERSION,
        .msg_type = MSG_AUTH_REQ, /* Serve as authentication challenge */
        .priority = PRIORITY_NORMAL,
        .flags = 0,
        .payload_len = htonl(32),
        .checksum = 0
    };
    generate_random_bytes(challenge_hdr.msg_id, MSG_ID_LEN);

    if (tls_send(ssl, &challenge_hdr, sizeof(challenge_hdr)) <= 0 ||
        tls_send(ssl, challenge, 32) <= 0) {
        fprintf(stderr, "[Server] Failed to transmit challenge\n");
        goto cleanup;
    }

    /* Step 2: Receive Client auth response signature */
    MsgHeader auth_resp_hdr;
    if (tls_recv(ssl, &auth_resp_hdr, sizeof(auth_resp_hdr)) != sizeof(auth_resp_hdr)) {
        fprintf(stderr, "[Server] Failed to receive AUTH_RESP header\n");
        goto cleanup;
    }

    if (auth_resp_hdr.msg_type != MSG_AUTH_REQ) {
        fprintf(stderr, "[Server] Expected MSG_AUTH_REQ signature frame\n");
        goto cleanup;
    }

    payload_len = ntohl(auth_resp_hdr.payload_len);
    if (payload_len != sizeof(AuthRequest)) {
        fprintf(stderr, "[Server] Invalid AuthRequest payload size\n");
        goto cleanup;
    }

    AuthRequest auth_req;
    if (tls_recv(ssl, &auth_req, sizeof(AuthRequest)) != sizeof(AuthRequest)) {
        fprintf(stderr, "[Server] Failed to read AuthRequest\n");
        goto cleanup;
    }

    /* Record authentication attempt (Brute force flood check) */
    ids_record_auth_attempt(client_ip, metrics);
    if (ids_is_blocked(client_ip)) {
        fprintf(stderr, "[Server] Blocked IP attempted authentication: %s\n", client_ip);
        goto cleanup;
    }

    strncpy(username, auth_req.username, MAX_USERNAME_LEN - 1);
    username[MAX_USERNAME_LEN - 1] = '\0';

    /* Validate authentication timestamp drift (Timestamp Anomaly Check) */
    uint64_t client_ts = be64toh(auth_req.timestamp);
    time_t now = time(NULL);
    uint64_t now_ms = (uint64_t)now * 1000;
    long long diff = (long long)client_ts - (long long)now_ms;
    if (diff < 0) diff = -diff;
    if (diff > 300 * 1000) { /* > 300 seconds (5 minutes) drift */
        fprintf(stderr, "[Server] Authentication failed for user: %s (Timestamp anomaly: diff=%lld ms)\n", 
                username, diff);
        ids_record_invalid_timestamp(client_ip, metrics);
        send_control_message(ssl, MSG_AUTH_FAIL, NULL, 0);
        goto cleanup;
    }

    /* Dynamically register user Identity public key inside auth manager */
    EVP_PKEY *user_id_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, received_bundle.identity_pub, 32);
    if (!user_id_pub) {
        goto cleanup;
    }
    auth_register_pubkey(username, user_id_pub);
    EVP_PKEY_free(user_id_pub);

    /* Verify signature of 32-byte challenge payload */
    if (auth_verify_login(username, challenge, 32, auth_req.signature, 64) != SUCCESS) {
        fprintf(stderr, "[Server] Authentication failed for user: %s\n", username);
        send_control_message(ssl, MSG_AUTH_FAIL, NULL, 0);
        ids_record_auth_fail_ex(client_ip, username, metrics);
        goto cleanup;
    }

    /* Auth successful: store PreKey Bundle in static lookup segment */
    pthread_mutex_lock(&g_prekeys_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_client_prekeys[i].has_bundle || strcmp(g_client_prekeys[i].username, username) == 0) {
            strncpy(g_client_prekeys[i].username, username, MAX_USERNAME_LEN - 1);
            g_client_prekeys[i].bundle = received_bundle;
            g_client_prekeys[i].has_bundle = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_prekeys_lock);

    authenticated = 1;
    printf("[Server] User authenticated: %s (Ed25519 Identity Registered)\n", username);
    send_control_message(ssl, MSG_AUTH_OK, NULL, 0);

    register_connected_client(username, ssl);

    /* Drain E2EE offline queue blindly */
    int queued_count = queue_count(username);
    if (queued_count > 0) {
        printf("[Server] Draining %d encrypted messages to reconnecting client %s\n", queued_count, username);
        queue_drain(username, offline_delivery_callback, ssl);
    }

    /* Active client message processing loop */
    while (1) {
        MsgHeader hdr;
        int n = tls_recv(ssl, &hdr, sizeof(hdr));

        if (n <= 0) {
            printf("[Server] Client %s disconnected\n", username);
            break;
        }

        if (n != (int)sizeof(hdr)) {
            fprintf(stderr, "[Server] Incomplete header\n");
            ids_record_malformed_packet(client_ip, "Incomplete wire header block", metrics);
            break;
        }

        /* Validate header fields strictly (Malformed Packet Check) */
        int valid_type = (hdr.msg_type >= MSG_PREKEY_UPLOAD && hdr.msg_type <= MSG_USER_LIST_RESP) || hdr.msg_type == MSG_ERROR;
        if (hdr.version != PROTOCOL_VERSION) {
            ids_record_malformed_packet(client_ip, "Invalid protocol header version", metrics);
            break;
        }
        if (!valid_type) {
            ids_record_malformed_packet(client_ip, "Unknown/invalid message type field", metrics);
            break;
        }
        uint32_t incoming_payload_len = ntohl(hdr.payload_len);
        if (incoming_payload_len > RECV_BUFFER_SIZE) {
            ids_record_malformed_packet(client_ip, "Oversized payload length header", metrics);
            break;
        }

        /* Record received message details (Message rate checks) */
        ids_record_message(client_ip, incoming_payload_len, metrics);
        if (ids_is_blocked(client_ip)) {
            fprintf(stderr, "[Server] IP is blocked due to message flood: %s\n", client_ip);
            break;
        }

        /* Server-Blind E2EE Routing */
        if (hdr.msg_type == MSG_CHAT) {
            payload_len = ntohl(hdr.payload_len);
            if (payload_len != sizeof(E2EEChatPayload)) {
                fprintf(stderr, "[Server] Invalid E2EE payload length: %u\n", payload_len);
                ids_record_malformed_packet(client_ip, "Invalid MSG_CHAT payload size", metrics);
                break;
            }

            E2EEChatPayload chat_payload;
            if (tls_recv(ssl, &chat_payload, sizeof(E2EEChatPayload)) != sizeof(E2EEChatPayload)) {
                fprintf(stderr, "[Server] Failed to receive E2EE chat payload\n");
                break;
            }

            /* Identify recipient from ciphertext payload header cleanly */
            char recipient[MAX_USERNAME_LEN] = {0};
            char *space = strchr(chat_payload.sender, ' ');
            if (space) {
                /* Target parsing from custom layout: sender is written as "sender recipient" for routing */
                *space = '\0';
                strncpy(recipient, space + 1, MAX_USERNAME_LEN - 1);
            } else {
                /* Fallback to broadcast */
                strcpy(recipient, "all");
            }

            /* Blind route the payload */
            int route_result = route_directed_message(username, recipient, &chat_payload, hdr.priority, hdr.msg_id);
            if (route_result == 0) {
                printf("[Server] Blind routed E2EE message %s -> %s\n", username, recipient);
            } else if (route_result == 1) {
                const char *queued = "Recipient offline. Message queued E2EE.";
                send_control_message(ssl, MSG_OFFLINE_STORED, (const uint8_t *)queued, (uint32_t)strlen(queued));
                printf("[Server] Queued E2EE frame for offline recipient: %s\n", recipient);
            } else {
                const char *err = "E2EE delivery failed.";
                send_control_message(ssl, MSG_ERROR, (const uint8_t *)err, (uint32_t)strlen(err));
            }
            continue;
        }

        /* Signal-Style PreKey bundle vending */
        if (hdr.msg_type == MSG_PREKEY_REQ) {
            payload_len = ntohl(hdr.payload_len);
            char req_user[MAX_USERNAME_LEN] = {0};
            if (payload_len < MAX_USERNAME_LEN && tls_recv(ssl, req_user, payload_len) == (int)payload_len) {
                req_user[payload_len] = '\0';

                PreKeyBundle response_bundle;
                int found = 0;

                pthread_mutex_lock(&g_prekeys_lock);
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (g_client_prekeys[i].has_bundle && strcmp(g_client_prekeys[i].username, req_user) == 0) {
                        response_bundle = g_client_prekeys[i].bundle;
                        
                        /* Vend/consume exactly one One-Time PreKey (OTPK) */
                        if (g_client_prekeys[i].bundle.otpk_count > 0) {
                            g_client_prekeys[i].bundle.otpk_count--;
                            response_bundle.otpk_count = 1; /* Indicate one OTPK returned */
                        } else {
                            response_bundle.otpk_count = 0;
                        }
                        found = 1;
                        break;
                    }
                }
                pthread_mutex_unlock(&g_prekeys_lock);

                if (found) {
                    MsgHeader resp_hdr = {
                        .version = PROTOCOL_VERSION,
                        .msg_type = MSG_PREKEY_RESP,
                        .priority = PRIORITY_NORMAL,
                        .flags = 0,
                        .payload_len = htonl(sizeof(PreKeyBundle)),
                        .checksum = 0
                    };
                    generate_random_bytes(resp_hdr.msg_id, MSG_ID_LEN);
                    tls_send(ssl, &resp_hdr, sizeof(resp_hdr));
                    tls_send(ssl, &response_bundle, sizeof(PreKeyBundle));
                    printf("[Server] Vended PreKey bundle of %s to requesting client %s\n", req_user, username);
                } else {
                    const char *err = "PreKey bundle not found for user.";
                    send_control_message(ssl, MSG_ERROR, (const uint8_t *)err, (uint32_t)strlen(err));
                }
            }
            continue;
        }

        if (hdr.msg_type == MSG_USER_LIST_REQ) {
            char user_list[1024];
            build_online_user_list(user_list, sizeof(user_list), username);
            send_control_message(ssl, MSG_USER_LIST_RESP, (const uint8_t *)user_list, (uint32_t)strlen(user_list));
            continue;
        }

        if (hdr.msg_type == MSG_RATCHET_DH) {
            /* Relay Ephemeral Ratchet DH key refresh directly to target peer */
            payload_len = ntohl(hdr.payload_len);
            if (payload_len != 32) continue;
            uint8_t key_bytes[32];
            if (tls_recv(ssl, key_bytes, 32) == 32) {
                /* Broadcast to all peers or direct recipient - simplified relay */
                pthread_mutex_lock(&g_connected_lock);
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (g_connected[i].active && strcmp(g_connected[i].username, username) != 0) {
                        MsgHeader dh_hdr = {
                            .version = PROTOCOL_VERSION,
                            .msg_type = MSG_RATCHET_DH,
                            .priority = PRIORITY_NORMAL,
                            .payload_len = htonl(32)
                        };
                        generate_random_bytes(dh_hdr.msg_id, MSG_ID_LEN);
                        pthread_mutex_lock(&g_connected[i].send_lock);
                        tls_send(g_connected[i].ssl, &dh_hdr, sizeof(dh_hdr));
                        tls_send(g_connected[i].ssl, key_bytes, 32);
                        pthread_mutex_unlock(&g_connected[i].send_lock);
                    }
                }
                pthread_mutex_unlock(&g_connected_lock);
            }
            continue;
        }
    }

cleanup:
    if (authenticated) {
        unregister_connected_client(username);
        printf("[Server] Client %s logged out\n", username);
    }
    if (ssl) {
        tls_close(ssl);
    }
    close(connfd);
    (void)metrics;
}
