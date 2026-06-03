# Adaptive Secure Communication System

An adaptive, end-to-end encrypted (E2EE), multi-client communication system targeting degraded, adversarial network environments. Developed in **C11**, using **OpenSSL 3.x**, and compiling on both **Linux (Ubuntu 20.04+)** and **Windows (MinGW/WSL)**.

---

## 📖 Architecture & Cryptographic Design

This system provides complete privacy, network resilience, and intrusion defense through several decoupled, high-performance C modules.

```
                  ┌──────────────────────────────────────────────┐
                  │                SERVER PROCESS                │
                  │  Coordinates routing, offline queueing, and  │
                  │       progressive IP security blocks.        │
                  └──────────────────────┬───────────────────────┘
                                         │  TLS 1.3
                                         │  UDP Backup
                  ┌──────────────────────┴───────────────────────┐
                  │                CLIENT CORE                   │
                  │  Handles X3DH bootstrap, Double Ratchet,     │
                  │  and network deduplication.                  │
                  └──────────────────────┬───────────────────────┘
                                         │  Modular API
                     ┌───────────────────┴───────────────────┐
                     ▼                                       ▼
         ┌───────────────────────┐               ┌───────────────────────┐
         │      CLI CLIENT       │               │      GTK CLIENT       │
         │  Interactive Terminal │               │   Graphical User UI   │
         │     (client.c)        │               │    (gtk_client.c)     │
         └───────────────────────┘               └───────────────────────┘
```

### 1. End-to-End Encryption (E2EE) Layer
*   **X3DH Session Bootstrap:** Alice and Bob securely negotiate encryption keys on-the-fly via 4 Diffie-Hellman handshakes (Identity, Ephemeral, Signed PreKey, and One-Time PreKeys).
*   **Double Ratchet Key Evolution:** Keys rotate on every message via symmetric KDF chains. When new DR keys are sent, the DH ratchet steps forward to provide forward secrecy and break-in recovery.
*   **Symmetric Initial State:** The Double Ratchet starts with keys derived directly from the X3DH shared secret. The receiver initializes the peer DR key on the first received message instead of executing an immediate DH step. This guarantees out-of-the-box key alignment and decryption compatibility.
*   **AES-256-GCM:** Protects confidentiality and validates payload integrity.

### 2. Transport Resilience & Multi-Path Delivery
*   **TCP (via TLS 1.3) + UDP Backup:** Messages are sent simultaneously over secure TLS 1.3 TCP channels and raw UDP.
*   **Deduplication:** The receiver uses random 128-bit message IDs and a sliding ring-buffer window (`DEDUP_WINDOW = 1024`) to discard duplicates.
*   **Priority Messaging:** Outgoing queues order messages by priority (`PRIORITY_NORMAL`, `URGENT`, and `CRITICAL`), ensuring urgent and critical messages bypass network congestion.

### 3. Adaptive Security & Intrusion Detection (IDS)
*   **Adaptive State Machine:** The engine monitors network packet loss, RTT, auth failures, and replay attacks, dynamically transitioning between `NORMAL`, `UNSTABLE`, and `HIGH-RISK` modes.
*   **Traffic Analysis Resistance:** In `HIGH-RISK` mode, the client automatically applies fixed-size padding (`4096 bytes`) to all messages and introduces randomized transmission delays to prevent timing analysis attacks.
*   **Progressive IP Blocking:** Scores IP behavior (brute force, replay attempts, timestamp anomalies) and drops malicious connection requests.

---

## 📂 Repository Layout

| Directory / File | Description |
| :--- | :--- |
| **`include/`** | Header definitions (`ratchet.h`, `crypto.h`, `message.h`, `client.h`, `server.h`, etc.) |
| **`src/crypto/`** | Double Ratchet state, X3DH prekey utilities, AES-GCM, and HKDF/HMAC implementations |
| **`src/tls/`** | TLS 1.3 server and client connection handlers |
| **`src/engine/`** | Adaptive engine state machine and real-time network metrics collectors |
| **`src/transport/`** | Multi-path send/recv delivery, offline ciphertext persistence, and priority queues |
| **`src/security/`** | Intrusion Detection System (IDS) scoring, rate limits, and block tracking |
| **`src/net/`** | Cross-platform socket utilities, DNS resolvers, and UDP notification threads |
| **`src/server/`** | Multi-threaded routing, rooms management, and authentication managers |
| **`src/client/`** | Client threads, CLI controller, and GTK graphical user interface |
| **`certs/`** | Generated server certificates and keys |
| **`data/offline_queue/`** | Persistent directory for storing offline E2EE ciphertexts |

---

## 🛠️ Build & Verification Instructions

### 1. Prerequisites (WSL or Linux Ubuntu)
Install the required toolchain and development libraries:
```bash
sudo apt-get update
sudo apt-get install -y gcc make libssl-dev pkg-config libgtk-3-dev
```

### 2. Build Targets
Build the entire workspace or specific components using the Makefile:
*   **Clean and build everything:**
    ```bash
    make clean && make all && make tests
    ```
*   **Build the GTK Graphical UI Client:**
    ```bash
    make gtk-client
    ```
*   **Build Phase-1 (TCP-only, no crypto dependencies):**
    ```bash
    make phase1
    ```

### 3. Run Unit Tests
Run the entire automated test suite (7 components, 100% pass):
```bash
make test
```

Or run any of the unit test binaries individually:
```bash
./bin/test_ratchet          # Double Ratchet state, evolution, and recovery
./bin/test_crypto           # AES-GCM, Ed25519 signatures, X3DH Bootstrap
./bin/test_adaptive         # Adaptive engine mode state transitions
./bin/test_multipath        # Deduplication, padding, and priority sorting
./bin/test_tls              # TLS 1.3 context creation and connection loops
./bin/test_ids              # Intrusion detection scoring and IP blocking
./bin/test_network_monitor  # Network quality metrics, health scores, and trends
```

---

## 🔌 API & Custom Frontend Integration Guide

The client core has been designed with a strict **Separation of Concerns** to make implementing custom frontends (e.g. React/Electron, mobile apps, or alternative UI toolkits) extremely simple without touching the cryptography or network codebase.

### 1. Client Core Entry Points
Your frontend wrapper can initialize and manage the connection lifecycle through the following functions in [client.h](file:///c:/6th%20semester%20EL's/Network%20programming%20and%20security%20lab%20EL/Implementation/secure-chat/include/client.h):

```c
/* 1. Initialize client state, resolve DNS, and connect socket */
int client_init(ClientState *client, const char *hostname, int port, const char *username);

/* 2. Execute TLS handshake and authenticate with server via Ed25519 signature */
int authenticate_with_server(ClientState *client);

/* 3. Spawn background recv, send, and UDP notify threads */
int client_start_threads(ClientState *client);

/* 4. Enqueue an outgoing message with a priority level */
int client_send_chat_message_ex(ClientState *client, const char *input_buf, uint8_t priority);

/* 5. Shut down socket and join background threads cleanly on exit */
void client_join_threads(ClientState *client);

/* 6. Clean up contexts and free allocated key structures */
void client_cleanup(ClientState *client);
```

### 2. Log & Event Callback API
Instead of writing output directly to the terminal, you can route all decrypted chat messages, server notices, and status updates directly to your frontend using the registration API:

```c
/* Register callback function to receive formatted log lines */
void client_set_log_callback(void (*callback)(const char *log_line));
```

#### Example Usage in C / GTK Wrapper:
```c
/* Callback function in your frontend code */
void my_frontend_logger(const char *log_line) {
    // Render the log line on your graphical window, console, or chat bubble
    gtk_text_buffer_insert_at_cursor(chat_buffer, log_line, -1);
}

int main() {
    ClientState client;
    client_set_log_callback(my_frontend_logger);
    
    // Run client threads...
}
```

### 3. Reference Implementation
See [gtk_client.c](file:///c:/6th%20semester%20EL's/Network%20programming%20and%20security%20lab%20EL/Implementation/secure-chat/src/client/gtk_client.c) to inspect a fully-functional GTK3 implementation that displays online users, manages chat buffers, supports priority selections, and registers logger callbacks.

---

## 🛠️ Summary of Key Fixes & Improvements

During the recent consolidation phase, we resolved critical compilation, security, and runtime bugs to guarantee stable execution:
1.  **OpenSSL 3.0 Deprecations:** Replaced deprecated `EVP_PKEY_cmp` calls with `EVP_PKEY_eq` in [client.c](file:///c:/6th%20semester%20EL's/Network%20programming%20and%20security%20lab%20EL/Implementation/secure-chat/src/client/client.c).
2.  **E2EE Sender Buffer Overflow:** Expanded the `sender` buffer inside `E2EEChatPayload` in [message.h](file:///c:/6th%20semester%20EL's/Network%20programming%20and%20security%20lab%20EL/Implementation/secure-chat/include/message.h) to `MAX_USERNAME_LEN * 2 + 2` to prevent memory corruption when packing both sender and recipient names.
3.  **Double Ratchet Key Alignment:** Resolved initial state mismatch by ensuring the responder initializes `peer_dh_pubkey` on the first received message instead of executing an immediate DH step.
4.  **Graceful Disconnect/Exit:** Updated `client_join_threads` in [client.c](file:///c:/6th%20semester%20EL's/Network%20programming%20and%20security%20lab%20EL/Implementation/secure-chat/src/client/client.c) to shutdown the socket channel. This unblocks the background receiver thread from `tls_recv` immediately when `/quit` is entered, resolving client terminal hanging issues.
5.  **Winsock Initialization:** Added platform socket startup and cleanup functions to client's `main` to support native Windows socket initialization.
6.  **Drift Synchronization:** Configured client auth request timestamp using current milliseconds and network byte order to satisfy the server's strict 5-minute anti-replay clock validation.
7.  **Warning Clearance:** Cast print sizes, removed unused variables (`metrics` in test cases), and replaced legacy `usleep` with POSIX-standard `nanosleep` across components.
