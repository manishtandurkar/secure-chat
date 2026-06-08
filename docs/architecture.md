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
│  │  TLS handshake → DH exchange → RSA auth → Ratchet init            │  │
│  │  Route directed encrypted messages (or offline queue)              │  │
│  │  Feed metrics to Adaptive Engine                                   │  │
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
| Server | `src/server/server.c`, `client_handler.c`, `room_manager.c`, `auth_manager.c` | TCP accept loop, per-client threads, routing, auth |
| Client | `src/client/client.c`, `input_handler.c`, `display.c` | Connect, send/recv threads, UI |
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
  |<-- MSG_AUTH_OK ---------------------------------- |
  |    [Offline queue drained]                        |
  |--- MSG_CHAT (IV + AES-256-CBC ciphertext) ------> |
  |    Server routes to recipient or offline queue    |
  |<-- MSG_OFFLINE_STORED (if recipient offline) ---- |
  | Every N messages:                                |
  |--- MSG_RATCHET_DH (new DH pubkey) ------------->  |
```

## Wire Protocol

**Header (28 bytes):**
```
version(1) | msg_type(1) | priority(1) | flags(1) | msg_id(16) | payload_len(4) | checksum(4)
```

**Encrypted chat payload (constant 4112 bytes):**
```
IV(16) | AES-256-CBC(padded_message)(4096)
```

All `MSG_CHAT` payloads are always exactly 4112 bytes regardless of message length — traffic analysis resistance.

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
