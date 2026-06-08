# Architecture

## Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              SERVER PROCESS                              │
│                                                                          │
│  main() → socket/bind/listen → accept() loop → pthread per client       │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  CLIENT THREAD (client_handler)                                    │  │
│  │  TLS handshake → DH exchange → RSA auth → unique username check    │  │
│  │  Ratchet init → broadcast_user_list() → drain offline queue        │  │
│  │  Route directed encrypted messages (or offline queue)              │  │
│  │  On disconnect: remove from table → broadcast_user_list()          │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Adaptive Engine (background thread)                                     │
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
│  GTK login dialog        │           │  GTK login dialog         │
│  DNS resolve             │           │  DNS resolve              │
│  TLS connect             │           │  TLS connect              │
│  DH → ratchet init       │           │  DH → ratchet init        │
│  RSA login               │           │  RSA login                │
│  Encrypt via ratchet key │  ──────►  │  Decrypt via ratchet key  │
│  Send TCP + UDP          │           │  Accept first, discard dup│
│  Adaptive mode aware     │           │  Adaptive mode aware      │
└──────────────────────────┘           └──────────────────────────┘
```

## Module Map

| Module | Files | Role |
|--------|-------|------|
| Server | `src/server/server.c`, `client_handler.c`, `room_manager.c`, `auth_manager.c` | TCP accept loop, per-client threads, routing, auth, user-list broadcast |
| GTK Client | `src/client/gtk_client.c` | GTK3 GUI: login dialog, chat window, To dropdown, priority, online users panel |
| CLI Client | `src/client/client.c`, `input_handler.c`, `display.c` | Terminal client: connect, send/recv threads, @-syntax input |
| Crypto | `src/crypto/ratchet.c`, `aes_utils.c`, `rsa_utils.c`, `crypto_common.c` | Double Ratchet, AES-256-CBC, RSA-2048, HKDF |
| TLS | `src/tls/tls_server.c`, `tls_client.c` | TLS 1.3 wrap/unwrap |
| Engine | `src/engine/adaptive_engine.c`, `metrics_collector.c` | State machine, rolling loss/RTT metrics |
| Transport | `src/transport/multipath.c`, `offline_queue.c`, `priority_queue.c` | Dual TCP+UDP, offline storage, priority send |
| Security | `src/security/intrusion.c` | Per-IP blocking, replay detection |
| Net | `src/net/socket_utils.c`, `dns_resolver.c`, `udp_notify.c`, `message_utils.c` | Sockets, DNS, UDP, CRC32 |

## Connection Flow

```
CLIENT                                          SERVER CHILD
  |=== TCP connect → TLS handshake ================> |
  |--- MSG_DH_INIT (X25519 public key) ------------> |
  |<-- MSG_DH_RESP (X25519 public key) ------------- |
  |    Both compute shared secret → ratchet_init()   |
  |--- MSG_AUTH_REQ (username + RSA signature) -----> |
  |    Server checks for duplicate username           |
  |<-- MSG_AUTH_OK  (or MSG_ERROR if duplicate) ----- |
  |    Server: client_table_add() →                   |
  |<-- MSG_USER_LIST_RESP (broadcast to ALL clients)  |
  |    Server drains offline queue for this user      |
  |--- MSG_CHAT (IV + AES-256-CBC ciphertext) ------> |
  |    Server routes to recipient or offline queue    |
  |<-- MSG_OFFLINE_STORED (if recipient offline) ---- |
  | Every N messages:                                |
  |--- MSG_RATCHET_DH (new DH pubkey) ------------->  |
  |                                                   |
  | On disconnect:                                    |
  |    Server: client_table_remove() →               |
  |<-- MSG_USER_LIST_RESP (broadcast to ALL clients)  |
```

## Wire Protocol

**Header (28 bytes):**
```
version(1) | msg_type(1) | priority(1) | flags(1) | msg_id(16) | payload_len(4) | checksum(4)
```

**flags field:**
- `MSG_FLAG_IS_OFFLINE_REPLAY (0x02)` — set on replayed offline messages so receiver can show `[queued]` badge

**Encrypted chat payload (constant 4112 bytes):**
```
IV(16) | AES-256-CBC(padded_message)(4096)
```

All `MSG_CHAT` payloads are always exactly 4112 bytes regardless of message length — traffic analysis resistance.

## GTK Client Architecture

```
main()
  └─ show_login_window()          — GTK login dialog
       └─ on_connect_clicked()
            ├─ client_connect()   — synchronous auth (blocks until MSG_AUTH_OK or error)
            ├─ build_chat_window()
            │    ├─ GtkTextView   — rich text with tags (ts, self, other, urgent, critical, queued, sys)
            │    ├─ GtkMenuButton + GtkPopover  — multi-select To dropdown
            │    ├─ GtkListBox    — online users panel
            │    └─ GtkRadioButton group — Normal / Urgent / Critical priority
            └─ Callbacks registered:
                 ├─ message_callback → on_message_cb → gdk_threads_add_idle → chat_append()
                 ├─ system_callback  → on_system_cb  → gdk_threads_add_idle → chat_system()
                 └─ users_callback   → on_users_cb   → gdk_threads_add_idle → update_users_idle()
```

Cross-thread safety: all GTK mutations go through `gdk_threads_add_idle` — recv/send threads never touch GTK widgets directly.

## Adaptive Engine State Machine

```
                ┌──────────────────┐
                │   MODE_NORMAL    │  retries=3, delay=100ms, dh_freq=10
                └────────┬─────────┘
                         │ loss>5% OR timeouts≥3
                         ▼
                ┌──────────────────┐
                │  MODE_UNSTABLE   │  retries=7, delay=200ms, chunk=512
                └────────┬─────────┘
                         │ auth_fails≥5 OR replays≥3 OR loss≥20%
                         ▼
                ┌──────────────────┐
                │  MODE_HIGH_RISK  │  retries=10, padding=forced, delay=random, dh_freq=1
                └──────────────────┘

Downgrade requires 30s of stable metrics (hysteresis).
```

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Forward secrecy | Double Ratchet — each message has unique derived key |
| Auth | RSA-2048 signatures over TLS 1.3 |
| Traffic analysis resistance | All payloads padded to constant 4096 bytes |
| Replay protection | 1024-entry dedup ring buffer per connection |
| Brute-force protection | IDS per-IP block after 5 auth failures (5 min) |
| Key erasure | `OPENSSL_cleanse()` on all key material after use |
| Username uniqueness | Server rejects duplicate usernames with `MSG_ERROR` |

## Crypto Verbose Logging

Both server (`client_handler.c`) and client (`client.c`) always print the E2EE layer to stderr, showing the ciphertext on the wire and the decrypted plaintext. This is intentional for demonstration purposes — it proves encryption is active at the application layer, independent of TLS.

The ciphertext values differ between sender and server because the server re-encrypts with a fresh ratchet key for each recipient.
