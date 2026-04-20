# AGENTS.md — Adaptive Secure Communication System for Unreliable and Adversarial Networks

> **Language:** C (C11 standard)
> **OS Target:** Linux (Ubuntu 20.04+)
> **Crypto Library:** OpenSSL 3.x
> **Build System:** GCC + Makefile
> **Transport:** TCP (primary) + UDP (multi-path backup)
> **New vs Old:** Double Ratchet replaces static AES session key; Adaptive Engine, Multi-Path Delivery, Offline Queue, Priority Messaging, Directed Client Messaging, and a GTK Operator UI are new modules

---

## Table of Contents

1. [Project Goal](#project-goal)
2. [Repository Structure](#repository-structure)
3. [Architecture Overview](#architecture-overview)
4. [Component Specifications](#component-specifications)
   - [Server](#1-server)
   - [Client](#2-client)
   - [Double Ratchet](#3-double-ratchet)
   - [Crypto Layer (RSA + AES)](#4-crypto-layer-rsa--aes)
   - [TLS Layer](#5-tls-layer)
   - [Adaptive Engine](#6-adaptive-engine)
   - [Multi-Path Transport](#7-multi-path-transport)
   - [Offline Message Queue](#8-offline-message-queue)
   - [Priority Messaging](#9-priority-messaging)
   - [Intrusion Detection](#10-intrusion-detection)
   - [DNS Resolver](#11-dns-resolver)
5. [Message Format (Wire Protocol)](#message-format-wire-protocol)
6. [Full Connection & Message Flow](#full-connection--message-flow)
7. [Adaptive Engine State Machine](#adaptive-engine-state-machine)
8. [Build Instructions](#build-instructions)
9. [Phase-by-Phase Implementation Plan](#phase-by-phase-implementation-plan)
10. [Coding Conventions](#coding-conventions)
11. [Testing Strategy](#testing-strategy)
12. [Error Handling Rules](#error-handling-rules)
13. [Security Rules](#security-rules)
14. [What NOT to Do](#what-not-to-do)

---

## Project Goal

Build an **adaptive, secure, multi-client communication system** in C that:
- Encrypts every individual message with a unique key using the **Double Ratchet Algorithm**
- Delivers messages over **TCP and UDP simultaneously** for resilience in degraded networks
- Stores encrypted messages for **offline recipients** and delivers on reconnect
- Dynamically changes security and transport behavior via an **Adaptive Engine** responding to network quality and threat level
- Protects metadata via **fixed-size padding** and randomized transmission delays
- Authenticates clients via RSA digital signatures over a TLS 1.3 transport
- Detects and responds to lightweight intrusion attempts (replay attacks, auth brute-force)

---

## Repository Structure

```
adaptive-secure-chat/
│
├── AGENTS.md                        ← This file
├── Makefile
├── README.md
│
├── include/
│   ├── common.h                     ← Constants, enums, error codes
│   ├── server.h
│   ├── client.h
│   ├── ratchet.h                    ← Double Ratchet state + API
│   ├── crypto.h                     ← RSA + AES
│   ├── tls_layer.h
│   ├── adaptive_engine.h            ← Engine state machine
│   ├── multipath.h                  ← Multi-path send/recv
│   ├── offline_queue.h              ← Offline message persistence
│   ├── priority_queue.h             ← Priority send queue
│   ├── intrusion.h                  ← IDS counters + actions
│   ├── message.h                    ← Wire protocol structs
│   ├── socket_utils.h
│   ├── dns_resolver.h
│   └── udp_notify.h
│
├── src/
│   ├── server/
│   │   ├── server.c                 ← Main server: socket, bind, listen, fork loop
│   │   ├── client_handler.c         ← Per-client child: handshake, route, queue
│   │   ├── room_manager.c           ← Group chat room tracking
│   │   └── auth_manager.c           ← RSA login verification
│   │
│   ├── client/
│   │   ├── client.c                 ← Main client: connect, threads, UI
│   │   ├── gtk_client.c             ← GTK3 GUI client (directed send, online users list)
│   │   ├── input_handler.c          ← Stdin → priority queue
│   │   └── display.c                ← Render decrypted messages
│   │
│   ├── crypto/
│   │   ├── ratchet.c                ← Double Ratchet: DH + symmetric ratchet
│   │   ├── rsa_utils.c              ← RSA keypair, sign, verify
│   │   ├── aes_utils.c              ← AES-256-CBC encrypt/decrypt
│   │   └── crypto_common.c          ← HKDF, HMAC-SHA256, random bytes
│   │
│   ├── tls/
│   │   ├── tls_server.c
│   │   └── tls_client.c
│   │
│   ├── engine/
│   │   ├── adaptive_engine.c        ← State machine: Normal/Unstable/HighRisk
│   │   └── metrics_collector.c      ← Packet loss, latency, auth failure counters
│   │
│   ├── transport/
│   │   ├── multipath.c              ← Dual TCP+UDP send, dedup receive
│   │   ├── offline_queue.c          ← Persist + drain ciphertext queue
│   │   └── priority_queue.c         ← CRITICAL/URGENT/NORMAL send queue
│   │
│   ├── security/
│   │   └── intrusion.c              ← Per-IP counters, block list, replay detection
│   │
│   └── net/
│       ├── socket_utils.c
│       ├── dns_resolver.c
│       └── udp_notify.c
│
├── certs/
│   ├── server.crt
│   ├── server.key
│   └── ca.crt
│
├── data/
│   └── offline_queue/               ← Encrypted message files (per username)
│
├── tests/
│   ├── test_ratchet.c               ← Ratchet key evolution + forward secrecy
│   ├── test_crypto.c                ← AES round-trip, RSA sign/verify
│   ├── test_multipath.c             ← Dedup, priority delivery
│   ├── test_adaptive.c              ← Mode transitions
│   └── test_tls.c
│
└── docs/
    ├── architecture.md
    └── ratchet_spec.md
```

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              SERVER PROCESS                              │
│                                                                          │
│  main() → socket/bind/listen → accept() loop → pthread per client       │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  CLIENT THREAD (client_handler)                                    │  │
│  │  TLS handshake → DH exchange → RSA auth → Ratchet init            │  │
│  │  Route directed encrypted messages (or offline queue)              │  │
│  │  Feed metrics to Adaptive Engine                                   │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Adaptive Engine (shared state via mmap / POSIX shm)                    │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────────────┐ │
│  │ NORMAL MODE │ →  │  UNSTABLE MODE   │ →  │    HIGH-RISK MODE       │ │
│  │ fast, lean  │    │ retry, chunk     │    │ pad, delay, rotate keys │ │
│  └─────────────┘    └──────────────────┘    └─────────────────────────┘ │
│                                                                          │
│  UDP thread → recvfrom() → presence + backup message copies             │
│  Offline Queue → persist ciphertext → drain on reconnect                │
└──────────────────────────────────────────────────────────────────────────┘

        TCP+TLS ▲                              TCP+TLS ▲
        UDP     ▲                              UDP     ▲
                │                                      │
┌───────────────┴──────────┐           ┌───────────────┴──────────┐
│        CLIENT A          │           │        CLIENT B           │
│  DNS resolve             │           │  DNS resolve              │
│  TLS connect             │           │  TLS connect              │
│  DH → ratchet init       │           │  DH → ratchet init        │
│  RSA login               │           │  RSA login                │
│  Encrypt via ratchet key │  ──────►  │  Decrypt via ratchet key  │
│  Send TCP + UDP          │           │  Accept first, discard dup│
│  Adaptive mode aware     │           │  Adaptive mode aware      │
└──────────────────────────┘           └──────────────────────────┘
```

---

## Component Specifications

### 1. Server

**File:** `src/server/server.c`

Current implementation uses a thread-per-connection architecture with `pthread_create`. Key additions:

- Maintains **shared memory segment** (POSIX `shm_open`) for Adaptive Engine state, readable by all child processes
- Maintains an **in-memory connected-client table**: `username → SSL* + ratchet state` for directed routing
- On `accept()`, starts a detached thread that calls `handle_client(connfd, ...)`
- Supports directed delivery (`@recipient message`), broadcast (`@all message`), and `MSG_USER_LIST_REQ/RESP`
- Sends `MSG_OFFLINE_STORED` acknowledgement when recipient is offline and queueing succeeds

**Constants (`include/common.h`):**
```c
#define SERVER_PORT           8080
#define UDP_PORT              8081
#define MAX_CLIENTS           50
#define MAX_USERNAME_LEN      32
#define MAX_MSG_LEN           4096
#define MSG_PADDED_SIZE       4096    /* All messages padded to this size */
#define MAX_ROOM_NAME_LEN     64
#define AES_KEY_LEN           32
#define AES_IV_LEN            16
#define RSA_KEY_BITS          2048
#define RATCHET_KEY_LEN       32
#define MSG_ID_LEN            16      /* Random 128-bit message ID */
#define DEDUP_WINDOW          1024    /* Recent message IDs to remember */
#define OFFLINE_QUEUE_MAX     500     /* Max queued messages per user */

/* Adaptive Engine thresholds */
#define LOSS_THRESHOLD_UNSTABLE    0.05f   /* 5% packet loss → Unstable */
#define LOSS_THRESHOLD_HIGH_RISK   0.20f   /* 20% → High-Risk */
#define AUTH_FAIL_THRESHOLD        5       /* 5 failures → High-Risk */
#define REPLAY_THRESHOLD           3       /* 3 replays → High-Risk */

/* Priority levels */
#define PRIORITY_NORMAL    0
#define PRIORITY_URGENT    1
#define PRIORITY_CRITICAL  2
```

---

### 2. Client

**File:** `src/client/client.c`

Usage: `./bin/client <hostname> <port> <username>`

GTK usage: `./bin/client_gtk`

Spawns three pthreads after connection:
- **recv_thread** — reads from TLS socket, deduplicates by message ID, decrypts via ratchet, passes to display
- **send_thread** — drains priority queue, encrypts via ratchet, sends via multipath
- **udp_thread** — sends/receives UDP presence signals and backup message copies

Persists ratchet state to `~/.aschat/<username>.ratchet` (AES-encrypted with a passphrase-derived key) after every message to survive crashes.

Recent client-facing additions:
- `client_send_chat_message_ex(..., priority)` for explicit NORMAL/URGENT/CRITICAL sends
- `client_request_user_list(...)` to fetch online users from server
- Optional GUI log callback (`client_set_log_callback`) for GTK integration
- Receive path now surfaces `[MSG][PRIORITY] ...`, `[QUEUE] ...`, `[SERVER] ...`, and `[USERS] ...` messages

GTK client capabilities (`src/client/gtk_client.c`):
- Connect form (host/port/username) and directed `To` field
- Online users side panel with click-to-fill recipient
- Manual and timed refresh of user list
- Broadcast toggle (`@all` routing)
- Priority selector and quick action presets (`Emergency Broadcast`, `Status Check`, `Team Sync`)

---

### 3. Double Ratchet

**File:** `src/crypto/ratchet.c`
**Header:** `include/ratchet.h`

This is the core cryptographic innovation. Implements a simplified Double Ratchet following the Signal specification structure.

**State struct:**
```c
typedef struct {
    uint8_t  root_key[RATCHET_KEY_LEN];       /* Updated on DH ratchet step */
    uint8_t  send_chain_key[RATCHET_KEY_LEN]; /* Advances with each sent msg */
    uint8_t  recv_chain_key[RATCHET_KEY_LEN]; /* Advances with each received msg */
    EVP_PKEY *dh_keypair;                      /* Our current ephemeral DH key */
    EVP_PKEY *peer_dh_pubkey;                  /* Peer's last known DH public key */
    uint32_t  send_counter;
    uint32_t  recv_counter;
    uint32_t  prev_send_counter;               /* For out-of-order handling */
} RatchetState;
```

**Functions to implement:**

```c
/* Initialize ratchet from DH shared secret (post-DH-handshake).
   Derives initial root_key, send_chain_key, recv_chain_key via HKDF.
   Returns 0 on success. */
int ratchet_init(RatchetState *state,
                 const uint8_t *shared_secret, size_t secret_len,
                 int is_initiator);

/* Derive the next message key for sending.
   Advances send_chain_key using HMAC-SHA256.
   Writes 32-byte message key to msg_key_out.
   Returns 0 on success. */
int ratchet_send_step(RatchetState *state, uint8_t *msg_key_out);

/* Derive the next message key for receiving.
   Advances recv_chain_key.
   Returns 0 on success. */
int ratchet_recv_step(RatchetState *state, uint8_t *msg_key_out);

/* Perform a DH ratchet step (called when a new DH public key is received
   from peer). Generates new DH keypair, derives new root key and chain keys.
   Returns 0 on success. */
int ratchet_dh_step(RatchetState *state, EVP_PKEY *peer_new_pubkey);

/* Serialize ratchet state to buffer for persistence.
   Returns bytes written or -1. */
int ratchet_serialize(const RatchetState *state, uint8_t *buf, size_t buf_len);

/* Deserialize ratchet state from buffer. Returns 0 or -1. */
int ratchet_deserialize(RatchetState *state, const uint8_t *buf, size_t buf_len);

/* Securely zero and free ratchet state. */
void ratchet_destroy(RatchetState *state);
```

**Key derivation inside ratchet (implement in `crypto_common.c`):**
```c
/* KDF_CK: advance chain key. Uses HMAC-SHA256.
   chain_key_out = HMAC-SHA256(chain_key, 0x02)
   msg_key_out   = HMAC-SHA256(chain_key, 0x01)
   Both outputs are 32 bytes. */
void kdf_ck(const uint8_t *chain_key,
            uint8_t *chain_key_out,
            uint8_t *msg_key_out);

/* KDF_RK: derive new root key and chain key from DH output.
   Uses HKDF-SHA256 with root_key as salt.
   rk_out and ck_out are each 32 bytes. */
void kdf_rk(const uint8_t *root_key,
            const uint8_t *dh_output, size_t dh_len,
            uint8_t *rk_out, uint8_t *ck_out);
```

---

### 4. Crypto Layer (RSA + AES)

**Files:** `src/crypto/rsa_utils.c`, `src/crypto/aes_utils.c`

RSA is used only for authentication (login signature), not for encrypting messages. AES-256-CBC is used for all message encryption, keyed with the per-message key derived from the ratchet.

**RSA functions (same as baseline):**
```c
EVP_PKEY *rsa_generate_keypair(void);
int rsa_pubkey_to_pem(EVP_PKEY *key, char *buf, size_t buf_len);
EVP_PKEY *rsa_pubkey_from_pem(const char *pem_buf, size_t pem_len);
int rsa_sign(EVP_PKEY *privkey, const unsigned char *data, size_t data_len,
             unsigned char *sig_buf, size_t *sig_len);
int rsa_verify(EVP_PKEY *pubkey, const unsigned char *data, size_t data_len,
               const unsigned char *sig, size_t sig_len);
```

**AES functions — note: key comes from ratchet, not from DH directly:**
```c
int aes_encrypt(const unsigned char *key,   /* 32 bytes from ratchet_send_step */
                const unsigned char *iv,    /* fresh random 16 bytes per message */
                const unsigned char *plaintext, int plaintext_len,
                unsigned char *ciphertext_buf);

int aes_decrypt(const unsigned char *key,   /* 32 bytes from ratchet_recv_step */
                const unsigned char *iv,
                const unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext_buf);

int aes_generate_iv(unsigned char *iv_buf);
```

**Padding (implement in `aes_utils.c`):**
```c
/* Pad plaintext to MSG_PADDED_SIZE using PKCS#7-style padding.
   Output buffer must be MSG_PADDED_SIZE bytes.
   Returns 0 or -1. */
int msg_pad(const uint8_t *plaintext, size_t plaintext_len,
            uint8_t *padded_out);

/* Strip padding after decryption. Returns original length or -1. */
int msg_unpad(const uint8_t *padded, size_t padded_len,
              uint8_t *plaintext_out);
```

---

### 5. TLS Layer

**Files:** `src/tls/tls_server.c`, `src/tls/tls_client.c`

Identical to baseline. TLS 1.3 minimum enforced. All ratchet handshake and message traffic travels inside the TLS tunnel.

```c
SSL_CTX *tls_create_server_ctx(const char *cert_file, const char *key_file);
SSL *tls_wrap_server_socket(SSL_CTX *ctx, int connfd);
SSL_CTX *tls_create_client_ctx(const char *ca_cert_file);
SSL *tls_wrap_client_socket(SSL_CTX *ctx, int sockfd, const char *hostname);
int tls_send(SSL *ssl, const void *buf, int len);
int tls_recv(SSL *ssl, void *buf, int len);
void tls_close(SSL *ssl);
```

---

### 6. Adaptive Engine

**Files:** `src/engine/adaptive_engine.c`, `src/engine/metrics_collector.c`
**Header:** `include/adaptive_engine.h`

The Adaptive Engine is a state machine running as a background thread in each child process. It reads metrics from `MetricsCollector`, evaluates threshold conditions, and updates a shared `EngineState` that all other modules query.

**State enum:**
```c
typedef enum {
    MODE_NORMAL    = 0,
    MODE_UNSTABLE  = 1,
    MODE_HIGH_RISK = 2,
} AdaptiveMode;
```

**Engine state struct:**
```c
typedef struct {
    AdaptiveMode mode;

    /* Transport config (read by multipath.c) */
    int     max_retries;       /* Normal: 3 | Unstable: 7 | HighRisk: 10 */
    int     retry_delay_ms;    /* Normal: 100 | Unstable: 200 | HighRisk: random(100,500) */
    int     chunk_size;        /* Normal: MAX_MSG_LEN | Unstable: 512 | HighRisk: 256 */
    int     use_udp_backup;    /* Normal: 1 | Unstable: 1 | HighRisk: 1 */

    /* Privacy config (read by multipath.c and aes_utils.c) */
    int     force_padding;     /* Normal: 0 | Unstable: 0 | HighRisk: 1 */
    int     random_delay;      /* Normal: 0 | Unstable: 0 | HighRisk: 1 */

    /* Crypto config (read by ratchet.c) */
    int     dh_ratchet_freq;   /* Normal: every 10 msgs | HighRisk: every msg */
} EngineState;
```

**Metrics struct:**
```c
typedef struct {
    float    packet_loss_rate;    /* Rolling average over last 100 sends */
    uint32_t rtt_ms;              /* Smoothed round-trip time */
    uint32_t auth_fail_count;     /* Failures since last reset */
    uint32_t replay_count;        /* Replay detections since last reset */
    uint32_t consecutive_timeouts;
} Metrics;
```

**Functions to implement:**

```c
/* Initialize engine. Spawns background evaluation thread.
   state_out written to shared memory segment for all children.
   Returns 0 or -1. */
int engine_init(EngineState *state_out);

/* Called by background thread every ENGINE_EVAL_INTERVAL_MS.
   Reads current metrics, evaluates transitions, updates state. */
void engine_evaluate(EngineState *state, const Metrics *metrics);

/* Apply mode-specific configuration to state. */
void engine_apply_mode(EngineState *state, AdaptiveMode new_mode);

/* Query current mode. Thread-safe (atomic read). */
AdaptiveMode engine_get_mode(const EngineState *state);

/* Update a specific metric. Thread-safe. */
void metrics_record_send(Metrics *m, int success);
void metrics_record_auth_fail(Metrics *m);
void metrics_record_replay(Metrics *m);
void metrics_record_rtt(Metrics *m, uint32_t rtt_ms);
```

**Transition logic (implement inside `engine_evaluate`):**
```
if (metrics.auth_fail_count >= AUTH_FAIL_THRESHOLD ||
    metrics.replay_count >= REPLAY_THRESHOLD ||
    metrics.packet_loss_rate >= LOSS_THRESHOLD_HIGH_RISK)
    → transition to MODE_HIGH_RISK

else if (metrics.packet_loss_rate >= LOSS_THRESHOLD_UNSTABLE ||
         metrics.consecutive_timeouts >= 3)
    → transition to MODE_UNSTABLE

else
    → transition to MODE_NORMAL

On any upward transition (Normal→HighRisk), log with timestamp.
On downward transition, require 30 seconds of stable metrics before reverting.
```

---

### 7. Multi-Path Transport

**File:** `src/transport/multipath.c`
**Header:** `include/multipath.h`

Every outgoing message is sent over both TCP (via TLS) and UDP simultaneously. The receiver deduplicates by message ID.

**Message ID:** 16 random bytes generated per message with `RAND_bytes()`.

**Deduplication set:** A ring buffer of the last `DEDUP_WINDOW` message IDs. On receive, check if ID is present; if yes, discard silently; if no, add to set and process.

**Functions to implement:**

```c
/* Send msg over both TCP (ssl) and UDP (udp_fd) simultaneously.
   Applies retry logic and delays based on current engine state.
   Returns 0 if at least one path succeeded, -1 if both failed. */
int multipath_send(SSL *ssl, int udp_fd,
                   const struct sockaddr_in *udp_dest,
                   const void *payload, size_t payload_len,
                   uint8_t priority,
                   const EngineState *engine);

/* Blocking receive. Accepts from either TCP or UDP.
   Deduplicates by msg ID. Writes to payload_out (caller allocates).
   Returns payload length or -1. */
int multipath_recv(SSL *ssl, int udp_fd,
                   void *payload_out, size_t buf_len,
                   uint8_t *msg_id_out);

/* Add message ID to dedup set. Thread-safe. */
void dedup_add(uint8_t id[MSG_ID_LEN]);

/* Check if message ID seen before. Returns 1 if duplicate, 0 if new. */
int dedup_check(const uint8_t id[MSG_ID_LEN]);
```

**Retry logic inside `multipath_send`:**
```
for (attempt = 0; attempt < engine->max_retries; attempt++) {
    send via TCP
    send via UDP
    if (engine->random_delay) sleep(random(100, 500) ms)
    else sleep(engine->retry_delay_ms)
    if ack received: break
}
```

---

### 8. Offline Message Queue

**File:** `src/transport/offline_queue.c`
**Header:** `include/offline_queue.h`

When a message arrives for a recipient who is not connected, the server stores the ciphertext on disk in `data/offline_queue/<username>/`. Filenames are formatted as `<timestamp_ms>_<msg_id_hex>` to preserve ordering.

The server **never decrypts** queued messages. It stores only the raw encrypted payload as received.

**Functions to implement:**

```c
/* Persist an encrypted message payload for offline user.
   Creates file in data/offline_queue/<username>/.
   Returns 0 or -1. */
int queue_store(const char *username,
                const void *ciphertext, size_t len,
                const uint8_t msg_id[MSG_ID_LEN]);

/* Count pending messages for user. */
int queue_count(const char *username);

/* Drain all queued messages to the now-connected user.
   Calls send_fn(payload, len, ctx) for each message in order.
   Deletes each file after successful delivery.
   Returns number of messages delivered, or -1 on error. */
int queue_drain(const char *username,
                int (*send_fn)(const void *payload, size_t len, void *ctx),
                void *ctx);

/* Delete all queued messages for user (on explicit request). */
int queue_clear(const char *username);
```

**Security constraint:** `data/offline_queue/` must have permissions `0700`. Each per-user directory `0700`. Individual message files `0600`.

---

### 9. Priority Messaging

**File:** `src/transport/priority_queue.c`
**Header:** `include/priority_queue.h`

A thread-safe priority queue on the client side. Messages are inserted with a priority level and drained by the send thread in priority order.

```c
typedef struct {
    uint8_t  priority;                     /* PRIORITY_NORMAL/URGENT/CRITICAL */
    uint8_t  msg_id[MSG_ID_LEN];
    uint8_t  payload[MSG_PADDED_SIZE + 64];
    size_t   payload_len;
    uint64_t enqueue_time_ms;
} QueuedMessage;

/* Thread-safe enqueue. CRITICAL messages bypass internal ordering
   and go to the front. Returns 0 or -1 if queue full. */
int pq_enqueue(QueuedMessage *msg);

/* Blocking dequeue. Returns highest-priority message.
   Caller must not free — message is from internal pool. */
QueuedMessage *pq_dequeue(void);

/* Current queue depth. */
int pq_size(void);
```

**Behavior by priority:**
- `PRIORITY_CRITICAL` — enqueued to front; send thread wakes immediately via condition variable; uses maximum retry count regardless of engine mode
- `PRIORITY_URGENT` — enqueued ahead of NORMAL; standard retry with URGENT flag in header
- `PRIORITY_NORMAL` — standard FIFO ordering behind URGENT/CRITICAL

---

### 10. Intrusion Detection

**File:** `src/security/intrusion.c`
**Header:** `include/intrusion.h`

Lightweight per-source-IP counters. Feeds directly into the Adaptive Engine's metrics.

```c
/* Record a failed authentication attempt from ip_str.
   If count exceeds AUTH_FAIL_THRESHOLD, adds to block list.
   Calls metrics_record_auth_fail() to update engine metrics. */
void ids_record_auth_fail(const char *ip_str, Metrics *metrics);

/* Record a detected replay attack (duplicate msg ID from unexpected source).
   Calls metrics_record_replay(). */
void ids_record_replay(const char *ip_str, Metrics *metrics);

/* Check if ip_str is currently blocked.
   Returns 1 if blocked, 0 if allowed. */
int ids_is_blocked(const char *ip_str);

/* Unblock after BLOCK_DURATION_SEC seconds.
   Called periodically by server main loop. */
void ids_expire_blocks(void);

/* Log security event to stderr with timestamp, type, and source IP. */
void ids_log_event(const char *event_type, const char *ip_str);
```

**Constants:**
```c
#define BLOCK_DURATION_SEC    300   /* 5-minute block */
#define MAX_BLOCKED_IPS       256
```

---

### 11. DNS Resolver

**File:** `src/net/dns_resolver.c`

Unchanged from baseline.

```c
int dns_resolve(const char *hostname, char *ip_out, size_t ip_out_len);
int dns_reverse_lookup(const char *ip_str, char *hostname_out, size_t len);
void dns_print_error(int gai_error_code);
```

---

## Message Format (Wire Protocol)

**Header (20 bytes, all multi-byte fields in network byte order):**
```c
typedef struct {
    uint8_t  version;              /* Always 0x02 */
    uint8_t  msg_type;             /* See MsgType enum */
    uint8_t  priority;             /* PRIORITY_NORMAL / URGENT / CRITICAL */
    uint8_t  flags;                /* Bit 0: has_dh_pubkey, Bit 1: is_offline_replay */
    uint8_t  msg_id[MSG_ID_LEN];  /* 16-byte random message ID for dedup */
    uint32_t payload_len;          /* Length of payload (always MSG_PADDED_SIZE for CHAT) */
    uint32_t checksum;             /* CRC32 of payload */
} __attribute__((packed)) MsgHeader;
/* Total: 1+1+1+1+16+4+4 = 28 bytes */
```

**Message types:**
```c
typedef enum {
    MSG_DH_INIT        = 0x01,
    MSG_DH_RESP        = 0x02,
    MSG_AUTH_REQ       = 0x03,
    MSG_AUTH_OK        = 0x04,
    MSG_AUTH_FAIL      = 0x05,
    MSG_CHAT           = 0x06,  /* Payload: IV(16) + padded_ciphertext(MSG_PADDED_SIZE) */
    MSG_JOIN_ROOM      = 0x07,
    MSG_LEAVE_ROOM     = 0x08,
    MSG_FILE_START     = 0x09,
    MSG_FILE_CHUNK     = 0x0A,
    MSG_FILE_END       = 0x0B,
    MSG_RATCHET_DH     = 0x0C,  /* NEW: carry new DH public key for ratchet step */
    MSG_OFFLINE_STORED = 0x0D,  /* NEW: server confirms message queued for offline user */
    MSG_PRIORITY       = 0x0E,  /* NEW: urgent/critical message signal */
    MSG_ENGINE_STATE   = 0x0F,  /* NEW: server broadcasts current adaptive mode to clients */
   MSG_USER_LIST_REQ  = 0x10,  /* NEW: client requests online users */
   MSG_USER_LIST_RESP = 0x11,  /* NEW: server responds with comma-separated users */
    MSG_ERROR          = 0xFF,
} MsgType;
```

**Encrypted chat payload:**
```
[ IV (16 bytes) ][ AES-256-CBC ciphertext of padded message (MSG_PADDED_SIZE bytes) ]
```
Total payload for every `MSG_CHAT` message: `16 + MSG_PADDED_SIZE = 4112 bytes` (constant, regardless of actual message length — this is intentional for traffic analysis resistance).

---

## Full Connection & Message Flow

```
CLIENT                                          SERVER CHILD
  |                                                  |
  |=== TCP connect → TLS handshake ================> |
  |                                                  |
  |--- MSG_DH_INIT (DH public key) ----------------> |
  |<-- MSG_DH_RESP (DH public key) ----------------- |
  |    Both: kdf_rk(shared_secret) → root_key        |
  |    Both: ratchet_init()                           |
  |                                                  |
  |--- MSG_AUTH_REQ (username + RSA signature) -----> |
  |<-- MSG_AUTH_OK ---------------------------------- |
  |    IDS: reset fail counter for this IP            |
  |                                                  |
  |    [Offline queue drained here if any pending]   |
  |                                                  |
  |    ======= CHAT SESSION ACTIVE ===============   |
  |                                                  |
   | User types "Hello" (directed in client as        |
   | `@recipient Hello`)                               |
  | ratchet_send_step() → msg_key                    |
  | aes_generate_iv() → iv                           |
  | msg_pad("Hello") → padded (4096 bytes)           |
  | aes_encrypt(msg_key, iv, padded) → ciphertext    |
  | Assemble MsgHeader (MSG_CHAT, new msg_id)         |
  |                                                  |
  |--- MSG_CHAT via TCP (TLS) -------------------→   |
  |--- MSG_CHAT via UDP (backup copy) ----------→    |
  |                                                  |
   |    Server decrypts payload, parses recipient      |
   |    Server routes directed message to recipient    |
  |    (If recipient offline → queue_store())        |
  |                                                  |
  |    Recipient:                                    |
  |    dedup_check(msg_id) → not seen                |
  |    dedup_add(msg_id)                             |
  |    ratchet_recv_step() → msg_key                 |
  |    aes_decrypt(msg_key, iv, ciphertext)          |
  |    msg_unpad() → "Hello"                         |
  |    Display to user                               |
  |                                                  |
  | Every N messages (per engine config):            |
  |--- MSG_RATCHET_DH (new DH pubkey) -----------→   |
  |    ratchet_dh_step() on both sides               |
  |    New root_key, new chain_keys                  |
```

---

## Adaptive Engine State Machine

```
                    ┌──────────────────┐
                    │   MODE_NORMAL    │
                    │  retries=3       │
                    │  padding=off     │
                    │  delay=100ms     │
                    │  dh_freq=10msgs  │
                    └────────┬─────────┘
                             │
              loss > 5% OR   │   loss < 5% AND
              timeouts >= 3  │   stable for 30s
                             ▼
                    ┌──────────────────┐
                    │  MODE_UNSTABLE   │
                    │  retries=7       │
                    │  chunk_size=512  │
                    │  padding=off     │
                    │  delay=200ms     │
                    └────────┬─────────┘
                             │
           auth_fails >= 5   │   stable for 30s
           OR replays >= 3   │   AND no threats
           OR loss >= 20%    │
                             ▼
                    ┌──────────────────┐
                    │  MODE_HIGH_RISK  │
                    │  retries=10      │
                    │  padding=FORCED  │
                    │  delay=random    │
                    │  dh_freq=1msg    │
                    │  block offender  │
                    └──────────────────┘
```

---

## Build Instructions

### Prerequisites
```bash
sudo apt-get install -y gcc make libssl-dev
```

For GTK client builds:
```bash
sudo apt-get install -y libgtk-3-dev pkg-config
```

### Makefile
```makefile
CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g -I./include \
          $(shell pkg-config --cflags openssl)
LDFLAGS = $(shell pkg-config --libs openssl) -lpthread -lrt

SRC_COMMON = src/crypto/ratchet.c src/crypto/rsa_utils.c \
             src/crypto/aes_utils.c src/crypto/crypto_common.c \
             src/tls/tls_server.c src/tls/tls_client.c \
             src/engine/adaptive_engine.c src/engine/metrics_collector.c \
             src/transport/multipath.c src/transport/offline_queue.c \
             src/transport/priority_queue.c \
             src/security/intrusion.c \
             src/net/socket_utils.c src/net/dns_resolver.c \
             src/net/udp_notify.c

all: server client certs

server: src/server/server.c src/server/client_handler.c \
        src/server/room_manager.c src/server/auth_manager.c $(SRC_COMMON)
	$(CC) $(CFLAGS) -o bin/server $^ $(LDFLAGS)

client: src/client/client.c src/client/input_handler.c \
        src/client/display.c $(SRC_COMMON)
	$(CC) $(CFLAGS) -o bin/client $^ $(LDFLAGS)

certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key \
	  -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
	cp certs/server.crt certs/ca.crt

tests:
	$(CC) $(CFLAGS) -o bin/test_ratchet tests/test_ratchet.c \
	  src/crypto/ratchet.c src/crypto/crypto_common.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o bin/test_adaptive tests/test_adaptive.c \
	  src/engine/adaptive_engine.c src/engine/metrics_collector.c $(LDFLAGS)
	$(CC) $(CFLAGS) -o bin/test_multipath tests/test_multipath.c \
	  src/transport/multipath.c $(LDFLAGS)

clean:
	rm -f bin/* certs/*

.PHONY: all clean tests certs
```

### Running
```bash
mkdir -p bin data/offline_queue
make all
make gtk-client
./bin/server                          # Terminal 1
./bin/client localhost 8080 alice     # Terminal 2
./bin/client localhost 8080 bob       # Terminal 3
./bin/client_gtk                       # Optional GTK client
```

### Directed Messaging Notes

- Messages are routed to a specific recipient using `@username message`.
- Broadcast to all online users uses `@all message`.
- Server rejects self-targeting and returns `MSG_ERROR` guidance.
- If target user is offline, payload is queued and sender receives `MSG_OFFLINE_STORED`.

---

## Phase-by-Phase Implementation Plan

### Phase 1 — TCP Server + DNS + Wire Protocol (Week 1)
- [ ] `socket_utils.c`: socket, bind, listen, accept, send_all, recv_all
- [ ] `server.c`: fork loop, SIGCHLD handler
- [ ] `dns_resolver.c`: getaddrinfo wrapper
- [ ] `message.h`: MsgHeader struct, MsgType enum
- [ ] `socket_utils.c`: send_message, recv_message, CRC32
- [ ] Checkpoint: plaintext echo server with structured headers

### Phase 2 — TLS + RSA Auth (Week 1–2)
- [ ] `rsa_utils.c`: keypair gen, sign, verify
- [ ] `tls_server.c` / `tls_client.c`: TLS 1.3, cert load, SSL_accept/connect
- [ ] `auth_manager.c`: verify RSA-signed login token
- [ ] Checkpoint: authenticated TLS connection established

### Phase 3 — Double Ratchet (Week 2–3)
- [ ] `crypto_common.c`: HKDF, HMAC-SHA256, kdf_ck, kdf_rk
- [ ] `ratchet.c`: ratchet_init, ratchet_send_step, ratchet_recv_step, ratchet_dh_step
- [ ] `ratchet.c`: ratchet_serialize / ratchet_deserialize (state persistence)
- [ ] Integrate ratchet into client send/recv threads
- [ ] Add MSG_RATCHET_DH message type handling
- [ ] Checkpoint: two clients exchange messages, each with unique derived key. Print key hex in debug mode and verify they match on both sides.

### Phase 4 — AES Encryption + Padding (Week 3)
- [ ] `aes_utils.c`: AES-256-CBC encrypt/decrypt, fresh IV per message
- [ ] `aes_utils.c`: msg_pad, msg_unpad to MSG_PADDED_SIZE
- [ ] Wire all encryption into send/recv path
- [ ] Checkpoint: tcpdump shows constant 4112-byte payloads regardless of message length

### Phase 5 — Multi-Path Delivery + Offline Queue (Week 4)
- [ ] `multipath.c`: dual TCP+UDP send, dedup ring buffer
- [ ] `offline_queue.c`: queue_store, queue_drain, queue_count
- [ ] `priority_queue.c`: thread-safe priority queue, CRITICAL bypass
- [ ] Integrate offline queue into client_handler: check routing table; if offline, queue_store
- [ ] Integrate queue_drain on client reconnect
- [ ] Checkpoint: send message to offline client; reconnect; message delivered

### Phase 6 — Adaptive Engine + Intrusion Detection (Week 5)
- [ ] `metrics_collector.c`: rolling packet loss, RTT, auth fail, replay counters
- [ ] `adaptive_engine.c`: state machine, engine_evaluate, engine_apply_mode
- [ ] `intrusion.c`: per-IP fail counters, block list, expiry
- [ ] Wire metrics_record_* calls into send/recv and auth paths
- [ ] Wire engine state queries into multipath_send (retry count, delay, padding)
- [ ] Add MSG_ENGINE_STATE broadcast to clients on mode change
- [ ] Checkpoint: simulate 25% packet loss → server enters UNSTABLE; simulate 6 auth fails → HIGH_RISK; verify padding forced on in HIGH_RISK

### Phase 7 — Testing + Demo (Week 6)
- [ ] `test_ratchet.c`: encrypt 100 messages, verify unique key each time; verify forward secrecy (delete key, confirm old messages unrecoverable)
- [ ] `test_adaptive.c`: inject synthetic metrics, verify mode transitions
- [ ] `test_multipath.c`: block TCP path, verify UDP delivery succeeds
- [ ] Stress test: 20 concurrent clients, 1000 messages, no message loss
- [ ] Valgrind: `valgrind --leak-check=full ./bin/server` for 60s
- [ ] Write README and demo script

---

## Coding Conventions

```c
/* Module-prefixed function names */
int ratchet_send_step(...)
void engine_evaluate(...)
int multipath_send(...)

/* Structs: PascalCase typedef */
typedef struct { ... } RatchetState;
typedef struct { ... } EngineState;

/* Constants: ALL_CAPS */
#define MSG_PADDED_SIZE 4096

/* Always zero sensitive key material after use */
OPENSSL_cleanse(msg_key, sizeof(msg_key));
OPENSSL_cleanse(chain_key, sizeof(chain_key));
```

---

## Testing Strategy

| Test | Method | Pass Condition |
|------|--------|----------------|
| Ratchet key uniqueness | Derive 100 msg keys, check all distinct | No two keys match |
| Forward secrecy | Delete ratchet state after 50 msgs; try decrypt msg 1–50 | All fail |
| Break-in recovery | Expose chain_key at msg 50; verify msg 60+ unreadable from key 50 | Decrypt fails after DH ratchet step |
| Constant payload size | tcpdump during chat | All MSG_CHAT packets same size |
| Offline delivery | Send to offline user; reconnect; check delivery | All messages received in order |
| Adaptive transition | Inject synthetic 25% loss via iptables | Mode transitions to UNSTABLE within 5s |
| High-Risk padding | Trigger HIGH_RISK via 6 auth fails | force_padding=1 confirmed in EngineState |
| Multi-path dedup | Send same msg_id twice | Only processed once |
| Memory leaks | valgrind on server + client | 0 bytes definitely lost |

---

## Error Handling Rules

1. Check every return value — `socket()`, `fork()`, `SSL_*`, `EVP_*`, file I/O
2. Use `perror()` for POSIX errors; `ERR_print_errors_fp(stderr)` for OpenSSL
3. Child processes must call `exit()` on fatal error, never `return` to parent loop
4. On IDS block: close connection cleanly before blocking — send `MSG_AUTH_FAIL` first
5. On ratchet deserialization failure: do not attempt to use partial state — reinitiate handshake

---

## Security Rules

1. **Zero all key material after use** — use `OPENSSL_cleanse()`, not `memset()` (compiler cannot optimize it away)
2. **Never log plaintext message content** — log only `[MSG from <user> id=<hex> len=<n>]`
3. **Fresh IV per AES call** — call `aes_generate_iv()` every single encryption
4. **TLS 1.3 minimum** — `SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)`
5. **Validate all incoming payload_len** — reject and close if `payload_len > MSG_PADDED_SIZE + 64`
6. **Sanitize usernames** — allow only `[a-zA-Z0-9_-]`, max `MAX_USERNAME_LEN`
7. **Offline queue permissions** — `data/offline_queue/` and subdirs must be `0700`
8. **Ratchet state file permissions** — `~/.aschat/*.ratchet` must be `0600`
9. **Replay window** — reject msg_id seen within last `DEDUP_WINDOW` messages from any source

---

## What NOT to Do

| ❌ Don't | ✅ Do Instead |
|---------|--------------|
| Reuse AES session key across messages | Derive fresh key from ratchet_send_step() per message |
| Store plaintext in offline queue | Store only the AES ciphertext payload |
| Skip DH ratchet steps to save CPU | Perform DH ratchet at least every dh_ratchet_freq messages |
| Use memset() to zero keys | Use OPENSSL_cleanse() |
| Hardcode Adaptive thresholds in multiple files | Define all thresholds only in common.h |
| Skip dedup check on UDP receives | Always run dedup_check() before processing any received message |
| Transition HIGH_RISK → NORMAL immediately | Require 30s of clean metrics before downgrade |
| Use deprecated RSA_generate_key() | Use EVP_PKEY_CTX + EVP_PKEY_keygen() |
| Block in engine_evaluate() | Engine runs in its own thread; never blocks send/recv path |
| Persist ratchet state in plaintext | Encrypt ratchet checkpoint file with passphrase-derived AES key |