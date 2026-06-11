#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include "server.h"
#include "socket_utils.h"
#include "message.h"
#include "ratchet.h"
#include "crypto.h"
#include "tls_layer.h"
#include "offline_queue.h"
#include "intrusion.h"
#include "common.h"
#include "crypto_log.h"

/* Shared server globals */
EngineState g_engine_state;
Metrics     g_metrics;

/* Client table */
static ClientEntry  client_table[MAX_CLIENTS];
static int          client_count = 0;
static pthread_mutex_t ct_lock = PTHREAD_MUTEX_INITIALIZER;

void client_table_init(void) {
    pthread_mutex_lock(&ct_lock);
    memset(client_table, 0, sizeof(client_table));
    client_count = 0;
    pthread_mutex_unlock(&ct_lock);
}

int client_table_add(ClientEntry *entry) {
    pthread_mutex_lock(&ct_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!client_table[i].active) {
            memcpy(&client_table[i], entry, sizeof(ClientEntry));
            client_table[i].active = 1;
            client_count++;
            pthread_mutex_unlock(&ct_lock);
            return i;
        }
    }
    pthread_mutex_unlock(&ct_lock);
    return -1;
}

void client_table_remove(const char *username) {
    pthread_mutex_lock(&ct_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_table[i].active &&
            strcmp(client_table[i].username, username) == 0) {
            ratchet_destroy(&client_table[i].ratchet);
            client_table[i].active = 0;
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&ct_lock);
}

/* Push current user list to every connected client */
static void broadcast_user_list(void) {
    char list_buf[MAX_CLIENTS * (MAX_USERNAME_LEN + 1)];
    client_table_list(list_buf, sizeof(list_buf));
    uint32_t len = (uint32_t)strlen(list_buf);

    uint8_t mid[MSG_ID_LEN];
    pthread_mutex_lock(&ct_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!client_table[i].active) continue;
        RAND_bytes(mid, MSG_ID_LEN);
        send_message(client_table[i].ssl, MSG_USER_LIST_RESP,
                     PRIORITY_NORMAL, 0, mid, list_buf, len);
    }
    pthread_mutex_unlock(&ct_lock);
}

ClientEntry *client_table_find(const char *username) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (client_table[i].active &&
            strcmp(client_table[i].username, username) == 0)
            return &client_table[i];
    return NULL;
}

int client_table_list(char *buf, size_t buf_len) {
    pthread_mutex_lock(&ct_lock);
    int wrote = 0;
    buf[0] = '\0';
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!client_table[i].active) continue;
        int n = snprintf(buf + wrote, buf_len - (size_t)wrote,
                         "%s%s", wrote > 0 ? "," : "", client_table[i].username);
        if (n <= 0) break;
        wrote += n;
    }
    pthread_mutex_unlock(&ct_lock);
    return wrote;
}

/* Drain callback: re-encrypts stored plaintext with dest's ratchet,
   sends as a proper MSG_CHAT with full MsgHeader. */
typedef struct { SSL *ssl; RatchetState *ratchet; } DrainCtx;

static int drain_send_fn(const void *plaintext, size_t len, void *ctx) {
    DrainCtx *dc = (DrainCtx *)ctx;

    uint8_t padded[MSG_PADDED_SIZE];
    if (msg_pad((const uint8_t *)plaintext, len, padded) < 0) return -1;

    uint8_t msg_key[RATCHET_KEY_LEN];
    ratchet_send_step(dc->ratchet, msg_key);

    uint8_t iv[AES_IV_LEN];
    aes_generate_iv(iv);

    uint8_t ct[MSG_PADDED_SIZE + 32];
    int ct_len = aes_encrypt(msg_key, iv, padded, MSG_PADDED_SIZE, ct);
    OPENSSL_cleanse(msg_key, sizeof(msg_key));
    if (ct_len < 0) return -1;

    uint8_t wire[AES_IV_LEN + MSG_PADDED_SIZE + 32];
    memcpy(wire, iv, AES_IV_LEN);
    memcpy(wire + AES_IV_LEN, ct, (size_t)ct_len);

    uint8_t mid[MSG_ID_LEN];
    RAND_bytes(mid, MSG_ID_LEN);
    return send_message(dc->ssl, MSG_CHAT, PRIORITY_NORMAL,
                        MSG_FLAG_IS_OFFLINE_REPLAY, mid,
                        wire, (uint32_t)(AES_IV_LEN + ct_len));
}

/* Validate username characters */
static int valid_username(const char *u) {
    for (const char *p = u; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return 0;
    }
    return (u[0] != '\0');
}

void *handle_client(void *arg) {
    HandlerArg *ha = (HandlerArg *)arg;
    SSL  *ssl    = ha->ssl;
    char  ip[48];
    memcpy(ip, ha->ip_str, sizeof(ip));
    free(ha);

    /* Check if IP is blocked */
    if (ids_is_blocked(ip)) {
        ids_log_event("BLOCKED_CONNECT", ip);
        tls_close(ssl);
        return NULL;
    }

    MsgHeader hdr;
    uint8_t   payload[MSG_PADDED_SIZE + 256];

    /* ── DH key exchange ─────────────────────────────────── */
    /* 1. Receive client DH public key */
    if (recv_message(ssl, &hdr, payload, sizeof(payload)) < 0) goto done;
    if (hdr.msg_type != MSG_DH_INIT) goto done;

    size_t peer_pub_len = hdr.payload_len;
    EVP_PKEY *peer_pubkey = ratchet_pubkey_from_bytes(payload, peer_pub_len);
    if (!peer_pubkey) goto done;

    /* Log client's X25519 public key */
    {
        uint8_t peer_raw[32];
        size_t  peer_raw_len = sizeof(peer_raw);
        if (EVP_PKEY_get_raw_public_key(peer_pubkey, peer_raw, &peer_raw_len) == 1)
            crypto_log_hex(CL_YELLOW, "[DH-EXCHANGE]", "Client X25519 pubkey: ", peer_raw, peer_raw_len, 8);
    }

    /* 2. Generate our DH keypair */
    EVP_PKEY *our_keypair = dh_generate_keypair();
    if (!our_keypair) { EVP_PKEY_free(peer_pubkey); goto done; }

    /* 3. Send our public key */
    uint8_t our_pub[32];
    size_t  our_pub_len = sizeof(our_pub);
    if (EVP_PKEY_get_raw_public_key(our_keypair, our_pub, &our_pub_len) != 1) {
        EVP_PKEY_free(our_keypair); EVP_PKEY_free(peer_pubkey); goto done;
    }
    crypto_log_hex(CL_YELLOW, "[DH-EXCHANGE]", "Server X25519 pubkey: ", our_pub, our_pub_len, 8);

    uint8_t msg_id[MSG_ID_LEN];
    RAND_bytes(msg_id, MSG_ID_LEN);
    if (send_message(ssl, MSG_DH_RESP, PRIORITY_NORMAL, 0, msg_id,
                     our_pub, (uint32_t)our_pub_len) < 0) {
        EVP_PKEY_free(our_keypair); EVP_PKEY_free(peer_pubkey); goto done;
    }

    /* 4. Compute shared secret */
    uint8_t shared[64];
    size_t  shared_len = sizeof(shared);
    if (dh_compute_shared_secret(our_keypair, peer_pubkey, shared, &shared_len) < 0) {
        EVP_PKEY_free(our_keypair); EVP_PKEY_free(peer_pubkey); goto done;
    }
    crypto_log_hex(CL_YELLOW, "[DH-EXCHANGE]", "Shared secret (X25519): ", shared, shared_len, 8);
    EVP_PKEY_free(our_keypair);
    EVP_PKEY_free(peer_pubkey);

    /* ── Ratchet init ─────────────────────────────────────── */
    RatchetState ratchet;
    if (ratchet_init(&ratchet, shared, shared_len, 0 /* responder */) < 0) goto done;
    OPENSSL_cleanse(shared, sizeof(shared));

    /* ── Auth ─────────────────────────────────────────────── */
    if (recv_message(ssl, &hdr, payload, sizeof(payload)) < 0) goto done;
    if (hdr.msg_type != MSG_AUTH_REQ) goto done;

    /* payload: username(MAX_USERNAME_LEN) + pubkey_pem(2048) + sig(512) + sig_len(4) */
    char username[MAX_USERNAME_LEN + 1] = {0};
    memcpy(username, payload, MAX_USERNAME_LEN);
    username[MAX_USERNAME_LEN] = '\0';

    if (!valid_username(username)) {
        send_message(ssl, MSG_AUTH_FAIL, PRIORITY_NORMAL, 0, msg_id, NULL, 0);
        ids_record_auth_fail(ip, &g_metrics);
        goto done;
    }

    /* Registration: extract pubkey and store on first login */
    char    *pem_start = (char *)payload + MAX_USERNAME_LEN;
    uint32_t sig_len_val;
    memcpy(&sig_len_val, payload + MAX_USERNAME_LEN + 2048, 4);
    sig_len_val = ntohl(sig_len_val);
    uint8_t *sig = payload + MAX_USERNAME_LEN + 2048 + 4;

    /* Store pubkey (idempotent) */
    auth_register_pubkey(username, pem_start);

    /* Challenge = username bytes */
    if (auth_verify(username, sig, sig_len_val,
                    (uint8_t *)username, strlen(username)) < 0) {
        crypto_log(CL_RED, "[AUTH]", "Login REJECTED for '%s' from %s", username, ip);
        send_message(ssl, MSG_AUTH_FAIL, PRIORITY_NORMAL, 0, msg_id, NULL, 0);
        ids_record_auth_fail(ip, &g_metrics);
        goto done;
    }
    crypto_log(CL_GREEN, "[AUTH]", "Login ACCEPTED for '%s' from %s", username, ip);

    /* Reject duplicate username */
    if (client_table_find(username)) {
        const char *err = "Username already in use";
        send_message(ssl, MSG_ERROR, PRIORITY_NORMAL, 0, msg_id,
                     (uint8_t *)err, (uint32_t)strlen(err));
        goto done;
    }

    /* Auth OK */
    RAND_bytes(msg_id, MSG_ID_LEN);
    send_message(ssl, MSG_AUTH_OK, PRIORITY_NORMAL, 0, msg_id, NULL, 0);

    /* Register in client table */
    ClientEntry entry = {0};
    entry.ssl    = ssl;
    entry.active = 1;
    strncpy(entry.username, username, MAX_USERNAME_LEN - 1);
    strncpy(entry.ip_str, ip, sizeof(entry.ip_str) - 1);
    memcpy(&entry.ratchet, &ratchet, sizeof(ratchet));

    int slot = client_table_add(&entry);
    if (slot < 0) goto done;
    broadcast_user_list();

    /* Drain offline queue — re-encrypt each stored plaintext for this client */
    {
        ClientEntry *ce2 = client_table_find(username);
        if (ce2) {
            crypto_log(CL_CYAN, "[QUEUE]", "Draining offline queue for '%s'", username);
            DrainCtx dc = { ssl, &ce2->ratchet };
            queue_drain(username, drain_send_fn, &dc);
        }
    }

    /* ── Main message loop ───────────────────────────────── */
    while (1) {
        memset(&hdr, 0, sizeof(hdr));
        if (recv_message(ssl, &hdr, payload, sizeof(payload)) < 0) break;

        /* Validate payload size */
        if (hdr.payload_len > MSG_PADDED_SIZE + 64) break;

        switch (hdr.msg_type) {
        case MSG_CHAT: {
            /* payload: IV(16) + AES-256-CBC ciphertext */
            if (hdr.payload_len < AES_IV_LEN) break;

            uint8_t *iv_in      = payload;
            uint8_t *ciphertext = payload + AES_IV_LEN;
            size_t   ct_len     = hdr.payload_len - AES_IV_LEN;

            /* Decrypt using sender's ratchet */
            ClientEntry *ce = client_table_find(username);
            if (!ce) break;

            crypto_log(CL_MAGENTA, "[RATCHET]",
                       "recv_step #%u for '%s': advancing recv_chain_key",
                       ce->ratchet.recv_counter, username);

            uint8_t msg_key_in[RATCHET_KEY_LEN];
            ratchet_recv_step(&ce->ratchet, msg_key_in);

            crypto_log_hex(CL_YELLOW, "[AES]", "  msg_key (AES-256 key): ", msg_key_in, RATCHET_KEY_LEN, 8);
            crypto_log_hex(CL_CYAN,   "[AES]", "  IV (random 128-bit):   ", iv_in, AES_IV_LEN, AES_IV_LEN);
            crypto_log_hex(CL_RED,    "[AES]", "  Ciphertext[0..16]:     ", ciphertext, ct_len, 16);

            uint8_t padded_in[MSG_PADDED_SIZE + 16];
            int pad_len = aes_decrypt(msg_key_in, iv_in, ciphertext,
                                      (int)ct_len, padded_in);
            OPENSSL_cleanse(msg_key_in, sizeof(msg_key_in));
            if (pad_len < 0) break;

            /* Unpad → "recipient\nmessage" */
            uint8_t plain[MSG_PADDED_SIZE + 1];
            int plain_len = msg_unpad(padded_in, (size_t)pad_len, plain);
            if (plain_len < 0) break;
            plain[plain_len] = '\0';

            crypto_log(CL_GREEN, "[AES]", "  AES-256-CBC decrypted: \"%.80s\"", (char *)plain);

            /* Split on '\n': before = recipient, after = message text */
            char recipient[MAX_USERNAME_LEN + 1] = {0};
            const char *msg_text = (char *)plain;
            char *nl = memchr(plain, '\n', (size_t)plain_len);
            if (nl) {
                size_t rlen = (size_t)(nl - (char *)plain);
                if (rlen >= MAX_USERNAME_LEN) rlen = MAX_USERNAME_LEN - 1;
                memcpy(recipient, plain, rlen);
                recipient[rlen] = '\0';
                msg_text = nl + 1;
            }

            /* Re-encrypt for destination: payload = "sender\nmessage" */
            char fwd_plain[MAX_MSG_LEN];
            int  fwd_len = snprintf(fwd_plain, sizeof(fwd_plain),
                                    "%s\n%s", username, msg_text);
            if (fwd_len <= 0) break;

            /* Helper: re-encrypt and send to a single destination entry */
            #define SEND_TO_DEST(dest_entry) do { \
                crypto_log(CL_MAGENTA, "[RATCHET]", \
                           "send_step #%u for '%s': advancing send_chain_key", \
                           (dest_entry)->ratchet.send_counter, (dest_entry)->username); \
                uint8_t msg_key_out[RATCHET_KEY_LEN]; \
                ratchet_send_step(&(dest_entry)->ratchet, msg_key_out); \
                uint8_t padded_out[MSG_PADDED_SIZE]; \
                if (msg_pad((uint8_t *)fwd_plain, (size_t)fwd_len, padded_out) < 0) { \
                    OPENSSL_cleanse(msg_key_out, sizeof(msg_key_out)); break; \
                } \
                uint8_t iv_out[AES_IV_LEN]; \
                aes_generate_iv(iv_out); \
                uint8_t ct_out[MSG_PADDED_SIZE + 32]; \
                int ct_out_len = aes_encrypt(msg_key_out, iv_out, \
                                             padded_out, MSG_PADDED_SIZE, ct_out); \
                crypto_log_hex(CL_YELLOW, "[AES]", "  msg_key (AES-256 key):  ", msg_key_out, RATCHET_KEY_LEN, 8); \
                crypto_log_hex(CL_CYAN,   "[AES]", "  IV (fresh 128-bit):     ", iv_out, AES_IV_LEN, AES_IV_LEN); \
                OPENSSL_cleanse(msg_key_out, sizeof(msg_key_out)); \
                if (ct_out_len < 0) break; \
                crypto_log_hex(CL_RED, "[AES]", "  Re-encrypted[0..16]:   ", ct_out, (size_t)ct_out_len, 16); \
                uint8_t wire[AES_IV_LEN + MSG_PADDED_SIZE + 32]; \
                memcpy(wire, iv_out, AES_IV_LEN); \
                memcpy(wire + AES_IV_LEN, ct_out, (size_t)ct_out_len); \
                RAND_bytes(msg_id, MSG_ID_LEN); \
                send_message((dest_entry)->ssl, MSG_CHAT, hdr.priority, \
                             hdr.flags, msg_id, wire, \
                             (uint32_t)(AES_IV_LEN + ct_out_len)); \
            } while (0)

            if (recipient[0] != '\0') {
                ClientEntry *dest = client_table_find(recipient);
                if (dest && dest->active) {
                    SEND_TO_DEST(dest);
                } else {
                    /* Offline: store plaintext "sender\nmessage" for later re-encryption */
                    crypto_log(CL_YELLOW, "[QUEUE]",
                               "Stored offline msg for '%s' (held encrypted at rest)", recipient);
                    queue_store(recipient, fwd_plain, (size_t)fwd_len, hdr.msg_id);
                    RAND_bytes(msg_id, MSG_ID_LEN);
                    send_message(ssl, MSG_OFFLINE_STORED, PRIORITY_NORMAL, 0,
                                 msg_id, (uint8_t *)recipient,
                                 (uint32_t)strlen(recipient));
                }
            } else {
                /* Broadcast to all other connected clients */
                pthread_mutex_lock(&ct_lock);
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (!client_table[i].active) continue;
                    if (strcmp(client_table[i].username, username) == 0) continue;
                    SEND_TO_DEST(&client_table[i]);
                }
                pthread_mutex_unlock(&ct_lock);
            }
            #undef SEND_TO_DEST
            break;
        }

        case MSG_USER_LIST_REQ: {
            char list_buf[MAX_CLIENTS * (MAX_USERNAME_LEN + 1)];
            client_table_list(list_buf, sizeof(list_buf));
            RAND_bytes(msg_id, MSG_ID_LEN);
            send_message(ssl, MSG_USER_LIST_RESP, PRIORITY_NORMAL, 0,
                         msg_id, list_buf, (uint32_t)strlen(list_buf));
            break;
        }

        case MSG_RATCHET_DH: {
            ClientEntry *ce_dh = client_table_find(username);
            if (ce_dh) {
                crypto_log(CL_CYAN, "[RATCHET]",
                           "DH ratchet triggered by '%s' (send_counter=%u) — rotating keys",
                           username, ce_dh->ratchet.send_counter);
                crypto_log_hex(CL_YELLOW, "[RATCHET]", "  old root_key: ",
                               ce_dh->ratchet.root_key, RATCHET_KEY_LEN, 8);
            }
            EVP_PKEY *peer_new = ratchet_pubkey_from_bytes(payload, hdr.payload_len);
            if (peer_new && ce_dh) {
                ratchet_dh_step(&ce_dh->ratchet, peer_new);
                crypto_log_hex(CL_GREEN, "[RATCHET]", "  new root_key: ",
                               ce_dh->ratchet.root_key, RATCHET_KEY_LEN, 8);
            }
            break;
        }

        case MSG_JOIN_ROOM:
            payload[hdr.payload_len] = '\0';
            room_join((char *)payload, username);
            break;

        case MSG_LEAVE_ROOM:
            payload[hdr.payload_len] = '\0';
            room_leave((char *)payload, username);
            break;

        default:
            break;
        }

        ids_expire_blocks();
    }

    client_table_remove(username);
    broadcast_user_list();
    /* ratchet was memcpy'd into client_table — EVP_PKEY* ownership transferred.
       Zero local struct without freeing keys to avoid double-free. */
    memset(&ratchet, 0, sizeof(ratchet));

done:
    tls_close(ssl);
    return NULL;
}
