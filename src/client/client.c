#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include "client.h"
#include "socket_utils.h"
#include "tls_layer.h"
#include "ratchet.h"
#include "crypto.h"
#include "message.h"
#include "priority_queue.h"
#include "multipath.h"
#include "dns_resolver.h"
#include "common.h"
#include "platform_compat.h"

/* Forward declarations for display functions */
void display_message(const char *sender, const char *text, uint8_t priority);
void display_system(const char *msg);
void display_users(const char *user_list);
void *input_thread_func(void *arg);

static ClientContext *g_ctx = NULL;

static int crypto_verbose(void) { return 1; }

static void log_hex(const char *label, const uint8_t *buf, size_t len) {
    size_t show = len < 32 ? len : 32;
    fprintf(stderr, "%s", label);
    for (size_t i = 0; i < show; i++) fprintf(stderr, "%02x", buf[i]);
    if (len > 32) fprintf(stderr, "...[%zu bytes total]", len);
    fprintf(stderr, "\n");
}

/* Called from input_handler.c for /users command */
int client_request_user_list_g(void) {
    if (!g_ctx || !g_ctx->ssl) return -1;
    return client_request_user_list(g_ctx);
}

/* Recv thread: reads from TLS, decrypts, displays */
static void *recv_thread(void *arg) {
    ClientContext *ctx = (ClientContext *)arg;
    MsgHeader hdr;
    uint8_t   payload[MSG_PADDED_SIZE + 256];

    while (ctx->running) {
        memset(&hdr, 0, sizeof(hdr));
        if (recv_message(ctx->ssl, &hdr, payload, sizeof(payload)) < 0) {
            if (ctx->running) fprintf(stderr, "[CLIENT] Connection lost\n");
            ctx->running = 0;
            break;
        }

        switch (hdr.msg_type) {
        case MSG_CHAT: {
            if (hdr.payload_len < AES_IV_LEN) break;

            /* Dedup check */
            if (dedup_check(hdr.msg_id)) break;
            dedup_add(hdr.msg_id);

            uint8_t *iv         = payload;
            uint8_t *ciphertext = payload + AES_IV_LEN;
            int      ct_len     = (int)(hdr.payload_len - AES_IV_LEN);

            if (crypto_verbose())
                log_hex("[CLIENT-RECV]   Ciphertext: ", ciphertext, (size_t)ct_len);

            uint8_t msg_key[RATCHET_KEY_LEN];
            ratchet_recv_step(&ctx->ratchet, msg_key);

            uint8_t padded[MSG_PADDED_SIZE + 16];
            int     dec_len = aes_decrypt(msg_key, iv, ciphertext, ct_len, padded);
            OPENSSL_cleanse(msg_key, sizeof(msg_key));
            if (dec_len < 0) break;

            uint8_t plain[MSG_PADDED_SIZE + 1];
            int plain_len = msg_unpad(padded, (size_t)dec_len, plain);
            if (plain_len < 0) break;
            plain[plain_len] = '\0';

            if (crypto_verbose())
                fprintf(stderr, "[CLIENT-RECV]   Decrypted:  \"%s\"\n", (char *)plain);

            /* Parse "sender\nmessage" */
            char sender[MAX_USERNAME_LEN + 1] = "peer";
            const char *msg_text = (char *)plain;
            char *nl = memchr(plain, '\n', (size_t)plain_len);
            if (nl) {
                size_t slen = (size_t)(nl - (char *)plain);
                if (slen < MAX_USERNAME_LEN) {
                    memcpy(sender, plain, slen);
                    sender[slen] = '\0';
                }
                msg_text = nl + 1;
            }

            if (ctx->message_callback)
                ctx->message_callback(sender, msg_text, hdr.priority, hdr.flags);
            else
                display_message(sender, msg_text, hdr.priority);
            break;
        }

        case MSG_OFFLINE_STORED: {
            payload[hdr.payload_len] = '\0';
            char sys_msg[MAX_USERNAME_LEN + 64];
            snprintf(sys_msg, sizeof(sys_msg),
                     "Message queued for offline user: %.32s", (char *)payload);
            if (ctx->system_callback)
                ctx->system_callback(sys_msg);
            else
                printf("[QUEUE] %s\n", sys_msg);
            break;
        }

        case MSG_USER_LIST_RESP:
            payload[hdr.payload_len] = '\0';
            display_users((char *)payload);
            if (ctx->users_callback) ctx->users_callback((char *)payload);
            break;

        case MSG_ENGINE_STATE:
            if (hdr.payload_len >= 1)
                printf("[ENGINE] Server mode: %d\n", payload[0]);
            break;

        case MSG_ERROR:
            payload[hdr.payload_len] = '\0';
            fprintf(stderr, "[ERROR] %s\n", (char *)payload);
            break;

        default:
            break;
        }
    }
    return NULL;
}

/* Send thread: drains priority queue, encrypts, sends */
static void *send_thread(void *arg) {
    ClientContext *ctx = (ClientContext *)arg;

    while (ctx->running) {
        QueuedMessage *qm = pq_dequeue();
        if (!qm) continue;

        /* Encrypt the full "recipient\nmessage" payload so server can route it */
        const char *text = (char *)qm->payload;

        /* Pad plaintext — includes recipient prefix so server can parse */
        uint8_t padded[MSG_PADDED_SIZE];
        if (msg_pad((const uint8_t *)text, strlen(text), padded) < 0) continue;

        /* Get msg key */
        uint8_t msg_key[RATCHET_KEY_LEN];
        ratchet_send_step(&ctx->ratchet, msg_key);

        /* Encrypt */
        uint8_t iv[AES_IV_LEN];
        aes_generate_iv(iv);

        uint8_t ciphertext[MSG_PADDED_SIZE + 32];
        int ct_len = aes_encrypt(msg_key, iv, padded, MSG_PADDED_SIZE, ciphertext);
        OPENSSL_cleanse(msg_key, sizeof(msg_key));
        if (ct_len < 0) continue;

        if (crypto_verbose()) {
            fprintf(stderr, "\n[CLIENT-SEND] E2EE encrypt:\n");
            fprintf(stderr, "[CLIENT-SEND]   Plaintext:  \"%s\"\n", text);
            log_hex("[CLIENT-SEND]   Ciphertext: ", ciphertext, (size_t)ct_len);
        }

        /* Build payload: IV + ciphertext */
        uint8_t wire_payload[AES_IV_LEN + MSG_PADDED_SIZE + 32];
        memcpy(wire_payload, iv, AES_IV_LEN);
        memcpy(wire_payload + AES_IV_LEN, ciphertext, (size_t)ct_len);
        size_t wire_len = AES_IV_LEN + (size_t)ct_len;

        uint8_t msg_id[MSG_ID_LEN];
        RAND_bytes(msg_id, MSG_ID_LEN);

        send_message(ctx->ssl, MSG_CHAT, qm->priority,
                     0, msg_id, wire_payload, (uint32_t)wire_len);

        /* DH ratchet step based on engine config */
        if ((ctx->ratchet.send_counter % (uint32_t)ctx->engine.dh_ratchet_freq) == 0) {
            uint8_t pub_bytes[32];
            size_t  pub_len = sizeof(pub_bytes);
            if (ratchet_get_dh_pubkey_bytes(&ctx->ratchet, pub_bytes, pub_len, &pub_len) == 0) {
                RAND_bytes(msg_id, MSG_ID_LEN);
                send_message(ctx->ssl, MSG_RATCHET_DH, PRIORITY_NORMAL,
                             0, msg_id, pub_bytes, (uint32_t)pub_len);
            }
        }
    }
    return NULL;
}

int client_connect(ClientContext *ctx,
                   const char *host, int port, const char *username) {
    /* Resolve hostname */
    char ip_str[64];
    if (dns_resolve(host, ip_str, sizeof(ip_str)) < 0) {
        strncpy(ip_str, host, sizeof(ip_str) - 1);
    }

    int sockfd = socket_create_client(ip_str, port);
    if (sockfd < 0) return -1;

    SSL_CTX *ssl_ctx = tls_create_client_ctx("certs/ca.crt");
    if (!ssl_ctx) { close(sockfd); return -1; }

    ctx->ssl = tls_wrap_client_socket(ssl_ctx, sockfd, host);
    SSL_CTX_free(ssl_ctx);
    if (!ctx->ssl) { close(sockfd); return -1; }

    strncpy(ctx->username, username, MAX_USERNAME_LEN - 1);
    ctx->running = 1;

    /* DH handshake */
    EVP_PKEY *dh_kp = dh_generate_keypair();
    if (!dh_kp) { tls_close(ctx->ssl); return -1; }

    uint8_t our_pub[32];
    size_t  our_pub_len = sizeof(our_pub);
    EVP_PKEY_get_raw_public_key(dh_kp, our_pub, &our_pub_len);

    uint8_t msg_id[MSG_ID_LEN];
    RAND_bytes(msg_id, MSG_ID_LEN);
    send_message(ctx->ssl, MSG_DH_INIT, PRIORITY_NORMAL, 0, msg_id,
                 our_pub, (uint32_t)our_pub_len);

    /* Receive server DH pubkey */
    MsgHeader hdr;
    uint8_t   payload[256];
    if (recv_message(ctx->ssl, &hdr, payload, sizeof(payload)) < 0) {
        EVP_PKEY_free(dh_kp); tls_close(ctx->ssl); return -1;
    }
    if (hdr.msg_type != MSG_DH_RESP) {
        EVP_PKEY_free(dh_kp); tls_close(ctx->ssl); return -1;
    }

    EVP_PKEY *server_pub = ratchet_pubkey_from_bytes(payload, hdr.payload_len);
    if (!server_pub) { EVP_PKEY_free(dh_kp); tls_close(ctx->ssl); return -1; }

    uint8_t shared[64];
    size_t  shared_len = sizeof(shared);
    if (dh_compute_shared_secret(dh_kp, server_pub, shared, &shared_len) < 0) {
        EVP_PKEY_free(dh_kp); EVP_PKEY_free(server_pub); tls_close(ctx->ssl); return -1;
    }
    EVP_PKEY_free(dh_kp);
    EVP_PKEY_free(server_pub);

    if (ratchet_init(&ctx->ratchet, shared, shared_len, 1 /* initiator */) < 0) {
        OPENSSL_cleanse(shared, sizeof(shared)); tls_close(ctx->ssl); return -1;
    }
    OPENSSL_cleanse(shared, sizeof(shared));

    /* RSA keypair for auth */
    EVP_PKEY *rsa_key = rsa_generate_keypair();
    if (!rsa_key) { tls_close(ctx->ssl); return -1; }

    char pem_pubkey[4096] = {0};
    rsa_pubkey_to_pem(rsa_key, pem_pubkey, sizeof(pem_pubkey));

    uint8_t sig[512];
    size_t  sig_len = sizeof(sig);
    rsa_sign(rsa_key, (uint8_t *)username, strlen(username), sig, &sig_len);
    EVP_PKEY_free(rsa_key);

    /* Auth payload: username(32) + pubkey_pem(2048) + sig(512) + sig_len(4) */
    uint8_t auth_payload[MAX_USERNAME_LEN + 2048 + 512 + 4];
    memset(auth_payload, 0, sizeof(auth_payload));
    strncpy((char *)auth_payload, username, MAX_USERNAME_LEN - 1);
    strncpy((char *)auth_payload + MAX_USERNAME_LEN, pem_pubkey, 2047);
    uint32_t sig_len_net = htonl((uint32_t)sig_len);
    memcpy(auth_payload + MAX_USERNAME_LEN + 2048, &sig_len_net, 4);
    memcpy(auth_payload + MAX_USERNAME_LEN + 2048 + 4, sig, sig_len);

    RAND_bytes(msg_id, MSG_ID_LEN);
    send_message(ctx->ssl, MSG_AUTH_REQ, PRIORITY_NORMAL, 0, msg_id,
                 auth_payload, (uint32_t)sizeof(auth_payload));

    /* Wait synchronously for auth response before spawning threads */
    {
        MsgHeader   auth_hdr;
        uint8_t     auth_resp[512];
        if (recv_message(ctx->ssl, &auth_hdr, auth_resp, sizeof(auth_resp)) < 0) {
            tls_close(ctx->ssl); return -1;
        }
        if (auth_hdr.msg_type == MSG_AUTH_FAIL) {
            strncpy(ctx->connect_error, "Authentication failed",
                    sizeof(ctx->connect_error) - 1);
            tls_close(ctx->ssl); return -1;
        }
        if (auth_hdr.msg_type == MSG_ERROR) {
            auth_resp[auth_hdr.payload_len] = '\0';
            strncpy(ctx->connect_error, (char *)auth_resp,
                    sizeof(ctx->connect_error) - 1);
            tls_close(ctx->ssl); return -1;
        }
        if (auth_hdr.msg_type != MSG_AUTH_OK) {
            strncpy(ctx->connect_error, "Unexpected server response",
                    sizeof(ctx->connect_error) - 1);
            tls_close(ctx->ssl); return -1;
        }
        /* MSG_AUTH_OK — proceed */
    }

    /* Init priority queue and dedup */
    pq_init();
    dedup_init();

    /* Init engine */
    engine_init(&ctx->engine);

    g_ctx = ctx;

    /* Spawn threads */
    pthread_t recv_tid, send_tid;
    pthread_create(&recv_tid, NULL, recv_thread, ctx);
    pthread_create(&send_tid, NULL, send_thread, ctx);
    pthread_detach(recv_tid);
    pthread_detach(send_tid);

#ifndef HAVE_GTK
    pthread_t input_tid;
    pthread_create(&input_tid, NULL, input_thread_func, NULL);
    pthread_detach(input_tid);
#endif

    return 0;
}

int client_send_chat_message(ClientContext *ctx,
                              const char *recipient,
                              const char *message) {
    return client_send_chat_message_ex(ctx, recipient, message, PRIORITY_NORMAL);
}

int client_send_chat_message_ex(ClientContext *ctx,
                                 const char *recipient,
                                 const char *message,
                                 uint8_t priority) {
    (void)ctx;
    QueuedMessage qm = {0};
    qm.priority = priority;
    qm.enqueue_time_ms = get_time_ms();

    /* Format: "recipient\nmessage" */
    int n = snprintf((char *)qm.payload, sizeof(qm.payload),
                     "%s\n%s", recipient ? recipient : "", message);
    if (n < 0) return -1;
    qm.payload_len = (size_t)n;

    return pq_enqueue(&qm);
}

int client_request_user_list(ClientContext *ctx) {
    uint8_t msg_id[MSG_ID_LEN];
    RAND_bytes(msg_id, MSG_ID_LEN);
    return send_message(ctx->ssl, MSG_USER_LIST_REQ,
                        PRIORITY_NORMAL, 0, msg_id, NULL, 0);
}

void client_set_log_callback(ClientContext *ctx,
                              void (*cb)(const char *msg)) {
    ctx->log_callback = cb;
}

void client_disconnect(ClientContext *ctx) {
    ctx->running = 0;
    pq_destroy();
    ratchet_destroy(&ctx->ratchet);
    tls_close(ctx->ssl);
    ctx->ssl = NULL;
}

#ifndef HAVE_GTK
int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <host> <port> <username>\n", argv[0]);
        return 1;
    }

    const char *host     = argv[1];
    int         port     = atoi(argv[2]);
    const char *username = argv[3];

    ClientContext ctx = {0};
    if (client_connect(&ctx, host, port, username) < 0) {
        fprintf(stderr, "Connection failed\n");
        return 1;
    }

    printf("[CLIENT] Connected as %s. Type messages (prefix with @user to direct).\n", username);
    printf("  Use '!urgent <msg>' or '!critical <msg>' for priority sends.\n");
    printf("  Type '/users' to list online users.\n");

    /* Wait until disconnected */
    while (ctx.running) sleep_ms(500);

    client_disconnect(&ctx);
    return 0;
}
#endif /* HAVE_GTK */
