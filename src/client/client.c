/**
 * Full Protocol Client with TLS, Double Ratchet, and Multi-Path
 * Implements AGENTS.md specification for client-side operations
 */

#define _POSIX_C_SOURCE 200809L
#include "platform_compat.h"
#include "client.h"
#include "crypto.h"
#include "message.h"
#include "ratchet.h"
#include "adaptive_engine.h"
#include "priority_queue.h"
#include "socket_utils.h"
#include "dns_resolver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifndef PLATFORM_WINDOWS
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#endif

/* Global client state for signal handlers */
static ClientState *g_client = NULL;
static ClientLogCallback g_log_callback = NULL;
static void *g_log_user_data = NULL;

void client_set_log_callback(ClientLogCallback callback, void *user_data) {
    g_log_callback = callback;
    g_log_user_data = user_data;
}

static void client_log_line(const char *line) {
    if (g_log_callback) {
        g_log_callback(line, g_log_user_data);
        return;
    }

    printf("%s\n", line);
    fflush(stdout);
}

static void client_log_format(const char *format, ...) {
    char buffer[1024];
    va_list args;

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    client_log_line(buffer);
}

/* Signal handler for graceful shutdown */
void handle_shutdown(int sig) {
    (void)sig;
    if (g_client) {
        g_client->running = 0;
    }
}

/* Check if message ID is duplicate */
int is_duplicate(ClientState *client, const uint8_t *msg_id) {
    for (int i = 0; i < DEDUP_WINDOW; i++) {
        if (memcmp(client->dedup_set[i], msg_id, MSG_ID_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Add message ID to dedup ring buffer */
void add_to_dedup(ClientState *client, const uint8_t *msg_id) {
    memcpy(client->dedup_set[client->dedup_idx], msg_id, MSG_ID_LEN);
    client->dedup_idx = (client->dedup_idx + 1) % DEDUP_WINDOW;
}

/* Initialize client state and connect to server */
int client_init(ClientState *client, const char *hostname, int port, const char *username) {
    memset(client, 0, sizeof(ClientState));
    strncpy(client->username, username, MAX_USERNAME_LEN - 1);
    client->running = 1;
    pthread_mutex_init(&client->ratchet_lock, NULL);

    /* Resolve hostname */
    char ip_str[INET_ADDRSTRLEN];
    if (dns_resolve(hostname, ip_str, sizeof(ip_str)) != 0) {
        fprintf(stderr, "DNS resolution failed for %s\n", hostname);
        return -1;
    }

    /* Create TCP socket */
    client->tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client->tcp_socket < 0) {
        perror("socket");
        return -1;
    }

    /* Setup server address */
    memset(&client->server_addr, 0, sizeof(client->server_addr));
    client->server_addr.sin_family = AF_INET;
    client->server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_str, &client->server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(client->tcp_socket);
        return -1;
    }

    /* Connect to server */
    if (connect(client->tcp_socket, (struct sockaddr *)&client->server_addr, 
                sizeof(client->server_addr)) < 0) {
        perror("connect");
        close(client->tcp_socket);
        return -1;
    }

    client_log_format("[+] Connected to %s:%d", ip_str, port);

    /* Setup TLS */
    client->ssl_ctx = tls_create_client_ctx("certs/ca.crt");
    if (!client->ssl_ctx) {
        fprintf(stderr, "Failed to create TLS context\n");
        close(client->tcp_socket);
        return -1;
    }

    client->ssl = tls_wrap_client_socket(client->ssl_ctx, client->tcp_socket, hostname);
    if (!client->ssl) {
        fprintf(stderr, "TLS handshake failed\n");
        tls_free_ctx(client->ssl_ctx);
        close(client->tcp_socket);
        return -1;
    }

    client_log_line("[+] TLS 1.3 handshake complete");

    /* Generate RSA keypair for authentication */
    client->rsa_keypair = rsa_generate_keypair();
    if (!client->rsa_keypair) {
        fprintf(stderr, "Failed to generate RSA keypair\n");
        tls_close(client->ssl);
        tls_free_ctx(client->ssl_ctx);
        return -1;
    }

    /* Create UDP socket for multi-path */
    client->udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (client->udp_socket < 0) {
        perror("udp socket");
        /* Non-fatal, continue without UDP */
        client->udp_socket = -1;
    }

    /* Initialize dedup set */
    memset(client->dedup_set, 0, sizeof(client->dedup_set));
    client->dedup_idx = 0;

    /* Default DH ratchet frequency (updated by MSG_ENGINE_STATE) */
    client->dh_ratchet_freq = 10;

    return 0;
}

/* Perform DH key exchange with server */
int perform_dh_exchange(ClientState *client) {
    /* Generate X25519 keypair */
    EVP_PKEY *dh_keypair = dh_generate_keypair();
    if (!dh_keypair) {
        fprintf(stderr, "Failed to generate DH keypair\n");
        return -1;
    }

    /* Serialize our public key */
    uint8_t our_pubkey[DH_PUBKEY_LEN];
    size_t pubkey_len = DH_PUBKEY_LEN;
    if (dh_serialize_pubkey(dh_keypair, our_pubkey, DH_PUBKEY_LEN, &pubkey_len) != 0) {
        fprintf(stderr, "Failed to serialize DH public key\n");
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    /* Send MSG_DH_INIT */
    MsgHeader hdr = {0};
    hdr.version = MSG_VERSION;
    hdr.msg_type = MSG_DH_INIT;
    hdr.priority = PRIORITY_NORMAL;
    RAND_bytes(hdr.msg_id, MSG_ID_LEN);
    hdr.payload_len = htonl(DH_PUBKEY_LEN);

    if (tls_send(client->ssl, &hdr, sizeof(hdr)) != sizeof(hdr) ||
        tls_send(client->ssl, our_pubkey, DH_PUBKEY_LEN) != DH_PUBKEY_LEN) {
        fprintf(stderr, "Failed to send DH init\n");
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    /* Receive MSG_DH_RESP */
    MsgHeader resp_hdr;
    if (tls_recv(client->ssl, &resp_hdr, sizeof(resp_hdr)) != sizeof(resp_hdr)) {
        fprintf(stderr, "Failed to receive DH response header\n");
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    if (resp_hdr.msg_type != MSG_DH_RESP) {
        fprintf(stderr, "Unexpected message type in DH exchange: %d\n", resp_hdr.msg_type);
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    uint32_t payload_len = ntohl(resp_hdr.payload_len);
    if (payload_len != DH_PUBKEY_LEN) {
        fprintf(stderr, "Invalid DH response payload length: %u\n", payload_len);
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    uint8_t peer_pubkey[DH_PUBKEY_LEN];
    if (tls_recv(client->ssl, peer_pubkey, DH_PUBKEY_LEN) != DH_PUBKEY_LEN) {
        fprintf(stderr, "Failed to receive peer DH public key\n");
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    client_log_line("[+] DH exchange complete");

    /* Derive shared secret */
    uint8_t shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);
    EVP_PKEY *peer_key = dh_deserialize_pubkey(peer_pubkey, DH_PUBKEY_LEN);
    if (!peer_key) {
        fprintf(stderr, "Failed to deserialize peer DH key\n");
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    if (dh_compute_shared_secret(dh_keypair, peer_key, shared_secret, &shared_secret_len) != 0) {
        fprintf(stderr, "Failed to compute shared secret\n");
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    /* Initialize ratchet state (client is initiator) */
    if (ratchet_init(&client->ratchet, shared_secret, sizeof(shared_secret), 1) != 0) {
        fprintf(stderr, "Failed to initialize ratchet\n");
        OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(dh_keypair);
        return -1;
    }

    client_log_line("[+] Ratchet initialized");

    /* Cleanup */
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(dh_keypair);

    return 0;
}

/* Authenticate with server using RSA signature */
int authenticate_with_server(ClientState *client) {
    /* Prepare authentication message: username */
    uint8_t auth_data[MAX_USERNAME_LEN];
    memset(auth_data, 0, sizeof(auth_data));
    strncpy((char *)auth_data, client->username, MAX_USERNAME_LEN - 1);

    /* Sign with RSA private key */
    uint8_t signature[512];
    size_t sig_len = sizeof(signature);
    if (rsa_sign(client->rsa_keypair, auth_data, strlen((char *)auth_data), 
                 signature, &sig_len) != 0) {
        fprintf(stderr, "Failed to sign authentication data\n");
        return -1;
    }

    /* Export RSA public key */
    char pubkey_pem[2048];
    if (rsa_pubkey_to_pem(client->rsa_keypair, pubkey_pem, sizeof(pubkey_pem)) != 0) {
        fprintf(stderr, "Failed to export RSA public key\n");
        return -1;
    }

    /* Build auth payload: username + signature + pubkey_pem */
    size_t payload_len = MAX_USERNAME_LEN + sig_len + strlen(pubkey_pem) + 1;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        perror("malloc");
        return -1;
    }

    memcpy(payload, auth_data, MAX_USERNAME_LEN);
    memcpy(payload + MAX_USERNAME_LEN, signature, sig_len);
    strcpy((char *)(payload + MAX_USERNAME_LEN + sig_len), pubkey_pem);

    /* Send MSG_AUTH_REQ */
    MsgHeader hdr = {0};
    hdr.version = MSG_VERSION;
    hdr.msg_type = MSG_AUTH_REQ;
    hdr.priority = PRIORITY_NORMAL;
    RAND_bytes(hdr.msg_id, MSG_ID_LEN);
    hdr.payload_len = htonl(payload_len);

    if (tls_send(client->ssl, &hdr, sizeof(hdr)) != sizeof(hdr) ||
        tls_send(client->ssl, payload, payload_len) != (int)payload_len) {
        fprintf(stderr, "Failed to send auth request\n");
        free(payload);
        return -1;
    }

    free(payload);

    /* Receive auth response */
    MsgHeader resp_hdr;
    if (tls_recv(client->ssl, &resp_hdr, sizeof(resp_hdr)) != sizeof(resp_hdr)) {
        fprintf(stderr, "Failed to receive auth response\n");
        return -1;
    }

    if (resp_hdr.msg_type == MSG_AUTH_OK) {
        client_log_line("[+] Authentication successful");
        return 0;
    } else if (resp_hdr.msg_type == MSG_AUTH_FAIL) {
        fprintf(stderr, "Authentication failed\n");
        return -1;
    } else {
        fprintf(stderr, "Unexpected auth response: %d\n", resp_hdr.msg_type);
        return -1;
    }
}

/* Send MSG_RATCHET_DH if send_counter has hit the DH ratchet frequency threshold.
   Called after every successful message send. */
static void trigger_dh_ratchet_if_needed(ClientState *client) {
    pthread_mutex_lock(&client->ratchet_lock);
    uint32_t send_count = client->ratchet.send_counter;
    pthread_mutex_unlock(&client->ratchet_lock);

    if (send_count == 0 || (send_count % (uint32_t)client->dh_ratchet_freq) != 0) {
        return;
    }

    EVP_PKEY *new_keypair = dh_generate_keypair();
    if (!new_keypair) {
        return;
    }

    uint8_t new_pubkey[DH_PUBKEY_LEN];
    size_t pubkey_len = DH_PUBKEY_LEN;
    if (dh_get_public_key(new_keypair, new_pubkey, &pubkey_len) != 0) {
        EVP_PKEY_free(new_keypair);
        return;
    }

    pthread_mutex_lock(&client->ratchet_lock);
    if (client->ratchet.dh_keypair) {
        EVP_PKEY_free(client->ratchet.dh_keypair);
    }
    client->ratchet.dh_keypair = new_keypair;
    pthread_mutex_unlock(&client->ratchet_lock);

    MsgHeader hdr = {0};
    hdr.version = MSG_VERSION;
    hdr.msg_type = MSG_RATCHET_DH;
    hdr.priority = PRIORITY_NORMAL;
    RAND_bytes(hdr.msg_id, MSG_ID_LEN);
    hdr.payload_len = htonl(DH_PUBKEY_LEN);

    tls_send(client->ssl, &hdr, sizeof(hdr));
    tls_send(client->ssl, new_pubkey, DH_PUBKEY_LEN);

    client_log_line("[+] DH ratchet key refreshed");
}

/* Receive thread: reads from TLS, decrypts via ratchet, displays */
void *recv_thread_func(void *arg) {
    ClientState *client = (ClientState *)arg;
    uint8_t ciphertext_buf[MSG_PADDED_SIZE + AES_IV_LEN + 64];
    uint8_t plaintext_buf[MSG_PADDED_SIZE + 64];

    while (client->running) {
        MsgHeader hdr;
        int ret = tls_recv(client->ssl, &hdr, sizeof(hdr));
        
        if (ret <= 0) {
            if (client->running) {
                fprintf(stderr, "[!] Connection closed by server\n");
                client->running = 0;
            }
            break;
        }

        if (ret != sizeof(hdr)) {
            fprintf(stderr, "[!] Incomplete header received\n");
            continue;
        }

        /* Check for duplicate message ID */
        if (is_duplicate(client, hdr.msg_id)) {
            /* Skip duplicate (from UDP backup path) */
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len > 0) {
                uint8_t *discard = malloc(payload_len);
                if (discard) {
                    tls_recv(client->ssl, discard, payload_len);
                    free(discard);
                }
            }
            continue;
        }

        add_to_dedup(client, hdr.msg_id);

        /* Handle message by type */
        if (hdr.msg_type == MSG_CHAT) {
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len > sizeof(ciphertext_buf)) {
                fprintf(stderr, "[!] Payload too large: %u\n", payload_len);
                continue;
            }

            if (tls_recv(client->ssl, ciphertext_buf, payload_len) != (int)payload_len) {
                fprintf(stderr, "[!] Failed to receive chat payload\n");
                continue;
            }

            /* Extract IV and ciphertext */
            uint8_t *iv = ciphertext_buf;
            uint8_t *ciphertext = ciphertext_buf + AES_IV_LEN;
            int ciphertext_len = payload_len - AES_IV_LEN;

            /* Derive message key from ratchet */
            uint8_t msg_key[RATCHET_KEY_LEN];
            pthread_mutex_lock(&client->ratchet_lock);
            if (ratchet_recv_step(&client->ratchet, msg_key) != 0) {
                pthread_mutex_unlock(&client->ratchet_lock);
                fprintf(stderr, "[!] Ratchet recv step failed\n");
                OPENSSL_cleanse(msg_key, sizeof(msg_key));
                continue;
            }
            pthread_mutex_unlock(&client->ratchet_lock);

            /* Decrypt */
            int plaintext_len = aes_decrypt(msg_key, iv, ciphertext, ciphertext_len, plaintext_buf);
            OPENSSL_cleanse(msg_key, sizeof(msg_key));

            if (plaintext_len < 0) {
                fprintf(stderr, "[!] Decryption failed\n");
                continue;
            }

            /* Unpad */
            uint8_t unpadded[MSG_PADDED_SIZE];
            int unpadded_len = msg_unpad(plaintext_buf, plaintext_len, unpadded);
            if (unpadded_len < 0) {
                fprintf(stderr, "[!] Unpadding failed\n");
                continue;
            }

            /* Display message with priority marker */
            unpadded[unpadded_len] = '\0';
            const char *prio = "NORMAL";
            if (hdr.priority == PRIORITY_URGENT) {
                prio = "URGENT";
            } else if (hdr.priority == PRIORITY_CRITICAL) {
                prio = "CRITICAL";
            }
            client_log_format("[MSG][%s] %s", prio, (char *)unpadded);

            if (!g_log_callback) {
                printf("> ");
                fflush(stdout);
            }

        } else if (hdr.msg_type == MSG_ERROR) {
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len > 0 && payload_len < 2048) {
                uint8_t *msg = malloc(payload_len + 1);
                if (msg && tls_recv(client->ssl, msg, payload_len) == (int)payload_len) {
                    msg[payload_len] = '\0';
                    client_log_format("[SERVER] %s", (char *)msg);
                }
                free(msg);
            } else {
                client_log_line("[SERVER] Error");
            }
        } else if (hdr.msg_type == MSG_OFFLINE_STORED) {
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len > 0 && payload_len < 2048) {
                uint8_t *msg = malloc(payload_len + 1);
                if (msg && tls_recv(client->ssl, msg, payload_len) == (int)payload_len) {
                    msg[payload_len] = '\0';
                    client_log_format("[QUEUE] %s", (char *)msg);
                }
                free(msg);
            } else {
                client_log_line("[QUEUE] Message stored for offline recipient");
            }
        } else if (hdr.msg_type == MSG_USER_LIST_RESP) {
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len > 0 && payload_len < 4096) {
                uint8_t *msg = malloc(payload_len + 1);
                if (msg && tls_recv(client->ssl, msg, payload_len) == (int)payload_len) {
                    msg[payload_len] = '\0';
                    client_log_format("[USERS] %s", (char *)msg);
                }
                free(msg);
            } else {
                client_log_line("[USERS]");
            }
        } else if (hdr.msg_type == MSG_RATCHET_DH) {
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len != DH_PUBKEY_LEN) {
                uint8_t *discard = malloc(payload_len);
                if (discard) { tls_recv(client->ssl, discard, payload_len); free(discard); }
                continue;
            }
            uint8_t peer_pubkey_bytes[DH_PUBKEY_LEN];
            if (tls_recv(client->ssl, peer_pubkey_bytes, DH_PUBKEY_LEN) != DH_PUBKEY_LEN) {
                continue;
            }
            EVP_PKEY *peer_new_pubkey = dh_pubkey_from_bytes(peer_pubkey_bytes, DH_PUBKEY_LEN);
            if (!peer_new_pubkey) {
                continue;
            }
            pthread_mutex_lock(&client->ratchet_lock);
            ratchet_dh_step(&client->ratchet, peer_new_pubkey);
            pthread_mutex_unlock(&client->ratchet_lock);
            EVP_PKEY_free(peer_new_pubkey);
            client_log_line("[+] DH ratchet step: forward secrecy renewed");

        } else if (hdr.msg_type == MSG_ENGINE_STATE) {
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len == 1) {
                uint8_t mode_byte = 0;
                if (tls_recv(client->ssl, &mode_byte, 1) == 1) {
                    /* Adjust DH ratchet frequency based on engine mode */
                    client->dh_ratchet_freq = (mode_byte == MODE_HIGH_RISK) ? 1 : 10;
                    const char *mode_str = (mode_byte == 0) ? "NORMAL"
                                        : (mode_byte == 1) ? "UNSTABLE"
                                        : "HIGH_RISK";
                    client_log_format("[Engine] Mode -> %s (DH ratchet every %d msgs)",
                                      mode_str, client->dh_ratchet_freq);
                }
            } else {
                uint8_t *discard = malloc(payload_len);
                if (discard) { tls_recv(client->ssl, discard, payload_len); free(discard); }
            }
        } else {
            /* Skip unknown message types */
            uint32_t payload_len = ntohl(hdr.payload_len);
            if (payload_len > 0) {
                uint8_t *discard = malloc(payload_len);
                if (discard) {
                    tls_recv(client->ssl, discard, payload_len);
                    free(discard);
                }
            }
        }
    }

    return NULL;
}

/* Send thread: drains priority queue, encrypts, sends */
void *send_thread_func(void *arg) {
    ClientState *client = (ClientState *)arg;
    char input_buf[MAX_MSG_LEN];

    if (!g_log_callback) {
        printf("\n> ");
        fflush(stdout);
    }

    while (client->running && fgets(input_buf, sizeof(input_buf), stdin)) {
        /* Remove trailing newline */
        size_t len = strlen(input_buf);
        if (len > 0 && input_buf[len-1] == '\n') {
            input_buf[len-1] = '\0';
            len--;
        }

        if (len == 0) {
            if (!g_log_callback) {
                printf("> ");
                fflush(stdout);
            }
            continue;
        }

        /* Check for quit command */
        if (strcmp(input_buf, "/quit") == 0) {
            client->running = 0;
            break;
        }

        /* Pad message */
        uint8_t padded[MSG_PADDED_SIZE];
        if (msg_pad((uint8_t *)input_buf, len, padded) != 0) {
            fprintf(stderr, "[!] Padding failed\n");
            if (!g_log_callback) {
                printf("> ");
                fflush(stdout);
            }
            continue;
        }

        /* Derive message key from ratchet */
        uint8_t msg_key[RATCHET_KEY_LEN];
        pthread_mutex_lock(&client->ratchet_lock);
        if (ratchet_send_step(&client->ratchet, msg_key) != 0) {
            pthread_mutex_unlock(&client->ratchet_lock);
            fprintf(stderr, "[!] Ratchet send step failed\n");
            OPENSSL_cleanse(msg_key, sizeof(msg_key));
            if (!g_log_callback) {
                printf("> ");
                fflush(stdout);
            }
            continue;
        }
        pthread_mutex_unlock(&client->ratchet_lock);

        /* Generate fresh IV */
        uint8_t iv[AES_IV_LEN];
        if (aes_generate_iv(iv) != 0) {
            fprintf(stderr, "[!] IV generation failed\n");
            OPENSSL_cleanse(msg_key, sizeof(msg_key));
            if (!g_log_callback) {
                printf("> ");
                fflush(stdout);
            }
            continue;
        }

        /* Encrypt */
        uint8_t ciphertext[MSG_PADDED_SIZE + 64];
        int ciphertext_len = aes_encrypt(msg_key, iv, padded, MSG_PADDED_SIZE, ciphertext);
        OPENSSL_cleanse(msg_key, sizeof(msg_key));

        if (ciphertext_len < 0) {
            fprintf(stderr, "[!] Encryption failed\n");
            printf("> ");
            fflush(stdout);
            continue;
        }

        /* Build payload: IV + ciphertext */
        size_t payload_len = AES_IV_LEN + ciphertext_len;
        uint8_t *payload = malloc(payload_len);
        if (!payload) {
            perror("malloc");
            printf("> ");
            fflush(stdout);
            continue;
        }

        memcpy(payload, iv, AES_IV_LEN);
        memcpy(payload + AES_IV_LEN, ciphertext, ciphertext_len);

        /* Send MSG_CHAT */
        MsgHeader hdr = {0};
        hdr.version = MSG_VERSION;
        hdr.msg_type = MSG_CHAT;
        hdr.priority = PRIORITY_NORMAL;
        RAND_bytes(hdr.msg_id, MSG_ID_LEN);
        hdr.payload_len = htonl(payload_len);

        int send_ok = 0;
        if (tls_send(client->ssl, &hdr, sizeof(hdr)) == sizeof(hdr) &&
            tls_send(client->ssl, payload, payload_len) == (int)payload_len) {
            send_ok = 1;
        }

        free(payload);

        if (!send_ok) {
            fprintf(stderr, "[!] Send failed\n");
            client->running = 0;
            break;
        }

        trigger_dh_ratchet_if_needed(client);

        if (!g_log_callback) {
            printf("> ");
            fflush(stdout);
        }
    }

    return NULL;
}

/* UDP thread stub (presence signals) */
void *udp_thread_func(void *arg) {
    ClientState *client = (ClientState *)arg;
    
    /* TODO: Implement UDP presence signals and backup message copies */
    (void)client;
    
    return NULL;
}

/* Start client threads */
int client_start_threads(ClientState *client) {
    if (pthread_create(&client->recv_thread, NULL, recv_thread_func, client) != 0) {
        perror("pthread_create recv_thread");
        return -1;
    }

    if (pthread_create(&client->send_thread, NULL, send_thread_func, client) != 0) {
        perror("pthread_create send_thread");
        pthread_cancel(client->recv_thread);
        return -1;
    }

    if (pthread_create(&client->udp_thread, NULL, udp_thread_func, client) != 0) {
        perror("pthread_create udp_thread");
        /* Non-fatal, continue without UDP thread */
    }

    return 0;
}

/* Wait for client threads */
void client_join_threads(ClientState *client) {
    pthread_join(client->recv_thread, NULL);
    pthread_join(client->send_thread, NULL);
    pthread_join(client->udp_thread, NULL);
}

/* Cleanup client resources */
void client_cleanup(ClientState *client) {
    if (client->ssl) {
        tls_close(client->ssl);
        client->ssl = NULL;
    }
    
    if (client->ssl_ctx) {
        tls_free_ctx(client->ssl_ctx);
        client->ssl_ctx = NULL;
    }
    
    if (client->tcp_socket >= 0) {
        close(client->tcp_socket);
        client->tcp_socket = -1;
    }
    
    if (client->udp_socket >= 0) {
        close(client->udp_socket);
        client->udp_socket = -1;
    }
    
    if (client->rsa_keypair) {
        EVP_PKEY_free(client->rsa_keypair);
        client->rsa_keypair = NULL;
    }

    save_ratchet_state(client);
    ratchet_destroy(&client->ratchet);
    pthread_mutex_destroy(&client->ratchet_lock);
}

/*
 * Ratchet persistence format written to ~/.aschat/<username>.ratchet:
 *   salt[16] | iv[16] | AES-256-CBC(key, iv, ratchet_serialized)
 * key = PBKDF2-HMAC-SHA256(password=username, salt, iterations=10000, dklen=32)
 */

#ifndef PLATFORM_WINDOWS

static int aschat_get_state_path(const ClientState *client, char *path_out, size_t path_len) {
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.aschat", home);
    /* mkdir is idempotent; ignore EEXIST */
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    snprintf(path_out, path_len, "%s/.aschat/%s.ratchet", home, client->username);
    return 0;
}

int save_ratchet_state(ClientState *client) {
    if (!client) return -1;

    uint8_t serial[256];
    pthread_mutex_lock(&client->ratchet_lock);
    int serial_len = ratchet_serialize(&client->ratchet, serial, sizeof(serial));
    pthread_mutex_unlock(&client->ratchet_lock);
    if (serial_len < 0) return -1;

    uint8_t salt[16], iv[AES_IV_LEN];
    RAND_bytes(salt, sizeof(salt));
    RAND_bytes(iv, sizeof(iv));

    uint8_t enc_key[32];
    if (PKCS5_PBKDF2_HMAC(client->username, (int)strlen(client->username),
                           salt, sizeof(salt), 10000,
                           EVP_sha256(), 32, enc_key) != 1) {
        OPENSSL_cleanse(serial, sizeof(serial));
        return -1;
    }

    uint8_t ciphertext[512];
    int ct_len = aes_encrypt(enc_key, iv, serial, serial_len, ciphertext);
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    OPENSSL_cleanse(serial, sizeof(serial));
    if (ct_len < 0) return -1;

    char path[512];
    if (aschat_get_state_path(client, path, sizeof(path)) != 0) return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;

    ssize_t written = write(fd, salt, sizeof(salt));
    written += write(fd, iv, sizeof(iv));
    written += write(fd, ciphertext, (size_t)ct_len);
    close(fd);

    return (written == (ssize_t)(sizeof(salt) + sizeof(iv) + (size_t)ct_len)) ? 0 : -1;
}

int load_ratchet_state(ClientState *client) {
    if (!client) return -1;

    char path[512];
    if (aschat_get_state_path(client, path, sizeof(path)) != 0) return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    uint8_t salt[16], iv[AES_IV_LEN];
    if (read(fd, salt, sizeof(salt)) != (ssize_t)sizeof(salt) ||
        read(fd, iv, sizeof(iv)) != (ssize_t)sizeof(iv)) {
        close(fd);
        return -1;
    }

    uint8_t ciphertext[512];
    ssize_t ct_len = read(fd, ciphertext, sizeof(ciphertext));
    close(fd);
    if (ct_len <= 0) return -1;

    uint8_t enc_key[32];
    if (PKCS5_PBKDF2_HMAC(client->username, (int)strlen(client->username),
                           salt, sizeof(salt), 10000,
                           EVP_sha256(), 32, enc_key) != 1) {
        return -1;
    }

    uint8_t plaintext[512];
    int pt_len = aes_decrypt(enc_key, iv, ciphertext, (int)ct_len, plaintext);
    OPENSSL_cleanse(enc_key, sizeof(enc_key));
    if (pt_len < 0) return -1;

    pthread_mutex_lock(&client->ratchet_lock);
    int ret = ratchet_deserialize(&client->ratchet, plaintext, (size_t)pt_len);
    pthread_mutex_unlock(&client->ratchet_lock);
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    return ret;
}

#else /* PLATFORM_WINDOWS */

int save_ratchet_state(ClientState *client) {
    (void)client;
    return 0; /* Not implemented for Windows */
}

int load_ratchet_state(ClientState *client) {
    (void)client;
    return -1;
}

#endif /* PLATFORM_WINDOWS */

/* Main client entry point */
int client_send_chat_message_ex(ClientState *client, const char *input_buf, uint8_t priority) {
    size_t len = strlen(input_buf);

    if (len == 0) {
        return 0;
    }

    uint8_t padded[MSG_PADDED_SIZE];
    if (msg_pad((uint8_t *)input_buf, len, padded) != 0) {
        client_log_line("[!] Padding failed");
        return -1;
    }

    uint8_t msg_key[RATCHET_KEY_LEN];
    pthread_mutex_lock(&client->ratchet_lock);
    if (ratchet_send_step(&client->ratchet, msg_key) != 0) {
        pthread_mutex_unlock(&client->ratchet_lock);
        client_log_line("[!] Ratchet send step failed");
        OPENSSL_cleanse(msg_key, sizeof(msg_key));
        return -1;
    }
    pthread_mutex_unlock(&client->ratchet_lock);

    uint8_t iv[AES_IV_LEN];
    if (aes_generate_iv(iv) != 0) {
        client_log_line("[!] IV generation failed");
        OPENSSL_cleanse(msg_key, sizeof(msg_key));
        return -1;
    }

    uint8_t ciphertext[MSG_PADDED_SIZE + 64];
    int ciphertext_len = aes_encrypt(msg_key, iv, padded, MSG_PADDED_SIZE, ciphertext);
    OPENSSL_cleanse(msg_key, sizeof(msg_key));

    if (ciphertext_len < 0) {
        client_log_line("[!] Encryption failed");
        return -1;
    }

    size_t payload_len = AES_IV_LEN + (size_t)ciphertext_len;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        perror("malloc");
        return -1;
    }

    memcpy(payload, iv, AES_IV_LEN);
    memcpy(payload + AES_IV_LEN, ciphertext, (size_t)ciphertext_len);

    MsgHeader hdr = {0};
    hdr.version = MSG_VERSION;
    hdr.msg_type = MSG_CHAT;
    hdr.priority = priority;
    RAND_bytes(hdr.msg_id, MSG_ID_LEN);
    hdr.payload_len = htonl((uint32_t)payload_len);

    int send_ok = 0;
    if (tls_send(client->ssl, &hdr, sizeof(hdr)) == (int)sizeof(hdr) &&
        tls_send(client->ssl, payload, (int)payload_len) == (int)payload_len) {
        send_ok = 1;
    }

    free(payload);

    if (!send_ok) {
        client_log_line("[!] Send failed");
        client->running = 0;
        return -1;
    }

    trigger_dh_ratchet_if_needed(client);

    return 0;
}

int client_send_chat_message(ClientState *client, const char *input_buf) {
    return client_send_chat_message_ex(client, input_buf, PRIORITY_NORMAL);
}

int client_request_user_list(ClientState *client) {
    MsgHeader hdr = {0};
    hdr.version = MSG_VERSION;
    hdr.msg_type = MSG_USER_LIST_REQ;
    hdr.priority = PRIORITY_NORMAL;
    RAND_bytes(hdr.msg_id, MSG_ID_LEN);
    hdr.payload_len = htonl(0);

    if (tls_send(client->ssl, &hdr, sizeof(hdr)) != (int)sizeof(hdr)) {
        client_log_line("[!] Failed to request online user list");
        return -1;
    }

    return 0;
}

#ifndef CLIENT_NO_MAIN
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <hostname> <port> <username>\n", argv[0]);
        return 1;
    }

    const char *hostname = argv[1];
    int port = atoi(argv[2]);
    const char *username = argv[3];

    ClientState client;
    g_client = &client;

    /* Setup signal handlers */
    signal(SIGINT, handle_shutdown);
    signal(SIGTERM, handle_shutdown);

    /* Initialize OpenSSL */
    if (tls_init() != SUCCESS) {
        fprintf(stderr, "Failed to initialize OpenSSL\n");
        return 1;
    }

    /* Initialize client and connect */
    if (client_init(&client, hostname, port, username) != 0) {
        fprintf(stderr, "Client initialization failed\n");
        return 1;
    }

    /* Perform DH exchange */
    if (perform_dh_exchange(&client) != 0) {
        fprintf(stderr, "DH exchange failed\n");
        client_cleanup(&client);
        return 1;
    }

    /* Authenticate with server */
    if (authenticate_with_server(&client) != 0) {
        fprintf(stderr, "Authentication failed\n");
        client_cleanup(&client);
        return 1;
    }

    printf("\n=== Connected as %s ===\n", username);
    printf("Type messages to send, /quit to exit\n\n");

    /* Start threads */
    if (client_start_threads(&client) != 0) {
        fprintf(stderr, "Failed to start threads\n");
        client_cleanup(&client);
        return 1;
    }

    /* Wait for threads */
    client_join_threads(&client);

    /* Cleanup */
    printf("\nDisconnecting...\n");
    client_cleanup(&client);

    return 0;
}
#endif
