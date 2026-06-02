# Architecture

## Overview

Adaptive Secure Communication System — a multi-client secure chat server written in C11 targeting Linux/WSL. Every message uses a unique per-message key derived via the Double Ratchet Algorithm. An Adaptive Engine monitors network and threat metrics and adjusts transport, retry, and cryptographic behavior at runtime.

## System Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              SERVER PROCESS                              │
│                                                                          │
│  main() → socket/bind/listen → accept() loop → pthread per client       │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  CLIENT THREAD (client_handler.c)                                  │  │
│  │  TLS handshake → DH exchange → RSA auth → Ratchet init            │  │
│  │  Route directed/broadcast messages (or offline queue)             │  │
│  │  Handle MSG_RATCHET_DH: perform DH step, reply with new pubkey    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Adaptive Engine (polling in accept loop)                                │
│  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────────────┐ │
│  │ MODE_NORMAL │ →  │  MODE_UNSTABLE   │ →  │    MODE_HIGH_RISK       │ │
│  │ retries=3   │    │  retries=7       │    │  retries=10, padding,   │ │
│  │ dh_freq=10  │    │  chunk=512       │    │  rand delay, dh_freq=1  │ │
│  └─────────────┘    └──────────────────┘    └─────────────────────────┘ │
│  Mode change → broadcast MSG_ENGINE_STATE to all connected clients       │
│                                                                          │
│  IDS (intrusion.c): per-IP auth-fail counters, replay detection,         │
│  5-minute block. Feeds directly into Adaptive Engine metrics.            │
│                                                                          │
│  Offline Queue (offline_queue.c): ciphertext persisted to               │
│  data/offline_queue/<username>/ when recipient is offline.               │
│  Drained on reconnect.                                                   │
└──────────────────────────────────────────────────────────────────────────┘

        TCP+TLS ▲                              TCP+TLS ▲
        UDP     ▲  (backup, dedup by msg_id)   UDP     ▲
                │                                      │
┌───────────────┴──────────┐           ┌───────────────┴──────────┐
│        CLIENT A          │           │        CLIENT B           │
│  dns_resolver.c          │           │  dns_resolver.c           │
│  TLS connect             │           │  TLS connect              │
│  DH → ratchet_init()     │           │  DH → ratchet_init()      │
│  RSA login               │           │  RSA login                │
│  send_thread: encrypt    │  ──────►  │  recv_thread: decrypt     │
│    ratchet_send_step()   │           │    ratchet_recv_step()    │
│    aes_encrypt(msg_key)  │           │    aes_decrypt(msg_key)   │
│  Every N msgs:           │           │  On MSG_RATCHET_DH:       │
│    send MSG_RATCHET_DH   │  ◄──────  │    ratchet_dh_step()      │
│    ratchet_dh_step()     │           │                           │
│  On MSG_ENGINE_STATE:    │           │  On MSG_ENGINE_STATE:     │
│    update dh_ratchet_freq│           │    update dh_ratchet_freq │
│  Persist ratchet state   │           │  Persist ratchet state    │
│  to ~/.aschat/user.ratchet│          │  to ~/.aschat/user.ratchet│
└──────────────────────────┘           └──────────────────────────┘
```

## Component Summary

| Component | File(s) | Responsibility |
|-----------|---------|----------------|
| Server main | `src/server/server.c` | Accept loop, engine eval, mode broadcast |
| Client handler | `src/server/client_handler.c` | Per-client thread: handshake, routing, DH ratchet |
| Auth manager | `src/server/auth_manager.c` | RSA signature verification |
| Room manager | `src/server/room_manager.c` | Group membership tracking |
| TLS layer | `src/tls/` | TLS 1.3 wrap/unwrap over TCP |
| Double Ratchet | `src/crypto/ratchet.c` | Key derivation, DH ratchet step, state persistence |
| RSA | `src/crypto/rsa_utils.c` | Auth keypair gen, sign, verify |
| AES | `src/crypto/aes_utils.c` | AES-256-CBC encrypt/decrypt, padding |
| DH exchange | `src/crypto/dh_exchange.c` | X25519 keypair, shared secret |
| Crypto common | `src/crypto/crypto_common.c` | HKDF, HMAC-SHA256, kdf_ck, kdf_rk |
| Adaptive engine | `src/engine/adaptive_engine.c` | State machine, mode transitions (30s stability gate) |
| Metrics collector | `src/engine/metrics_collector.c` | Rolling packet loss, RTT, auth-fail, replay counters |
| Multi-path | `src/transport/multipath.c` | Dual TCP+UDP send, msg_id deduplication ring buffer |
| Offline queue | `src/transport/offline_queue.c` | Ciphertext persistence, drain on reconnect |
| Priority queue | `src/transport/priority_queue.c` | CRITICAL/URGENT/NORMAL send ordering |
| IDS | `src/security/intrusion.c` | Per-IP block list, replay detection, engine feed |
| Socket utils | `src/net/socket_utils.c` | send_all, recv_all, CRC32 |
| DNS resolver | `src/net/dns_resolver.c` | getaddrinfo wrapper |
| UDP notify | `src/net/udp_notify.c` | UDP presence signals |
| Client | `src/client/client.c` | Threads, ratchet persistence, DH trigger, engine handling |
| GTK client | `src/client/gtk_client.c` | GUI: directed send, online users panel, priority presets |

## Connection and Message Flow

```
CLIENT                                          SERVER THREAD
  │                                                  │
  │═══ TCP connect → TLS 1.3 handshake ════════════► │
  │                                                  │
  │─── MSG_DH_INIT (X25519 pubkey) ───────────────► │
  │◄── MSG_DH_RESP (X25519 pubkey) ─────────────── │
  │    Both: kdf_rk(shared_secret) → root_key        │
  │    Both: ratchet_init()                           │
  │                                                  │
  │─── MSG_AUTH_REQ (username + RSA sig) ──────────► │
  │◄── MSG_AUTH_OK ──────────────────────────────── │
  │    [Offline queue drained if pending]             │
  │                                                  │
  │    ═══════ CHAT SESSION ACTIVE ═══════           │
  │                                                  │
  │    User types "@bob hello"                        │
  │    ratchet_send_step() → msg_key                  │
  │    aes_encrypt(msg_key, fresh_iv, padded)         │
  │─── MSG_CHAT (IV + ciphertext) ─────────────────► │
  │─── MSG_CHAT via UDP (backup copy) ─────────────► │
  │                                                  │
  │    Server decrypts, parses @bob, routes to bob   │
  │    If bob offline: queue_store() on disk          │
  │◄── MSG_OFFLINE_STORED ─────────────────────────  │
  │                                                  │
  │    Every N msgs (N = engine.dh_ratchet_freq):    │
  │─── MSG_RATCHET_DH (new X25519 pubkey) ─────────► │
  │    Server: ratchet_dh_step(), new chains          │
  │◄── MSG_RATCHET_DH (server's new pubkey) ───────  │
  │    Client: ratchet_dh_step(), forward secrecy    │
  │                                                  │
  │    On engine mode change (server → all clients): │
  │◄── MSG_ENGINE_STATE (mode byte) ───────────────  │
  │    Client: update dh_ratchet_freq                 │
```

## Adaptive Engine State Machine

```
              ┌──────────────────┐
              │   MODE_NORMAL    │ retries=3, dh_freq=10, no padding
              └────────┬─────────┘
                       │
       loss>5% OR      │  loss<5% AND stable 30s
       timeouts≥3      │
                       ▼
              ┌──────────────────┐
              │  MODE_UNSTABLE   │ retries=7, chunk=512
              └────────┬─────────┘
                       │
     auth_fails≥5      │  stable 30s AND no threats
     OR replays≥3      │
     OR loss≥20%       │
                       ▼
              ┌──────────────────┐
              │  MODE_HIGH_RISK  │ retries=10, force_padding, rand delay, dh_freq=1
              └──────────────────┘
```

Upward transitions are immediate. Downward transitions require 30 consecutive seconds of clean metrics. Mode changes are broadcast to all clients via `MSG_ENGINE_STATE`.

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Confidentiality | AES-256-CBC, per-message key from Double Ratchet |
| Forward secrecy | DH ratchet step every N messages; old keys are not stored |
| Break-in recovery | DH ratchet rotates root/chain keys; compromise of one session key doesn't expose future messages |
| Traffic analysis resistance | Fixed 4096-byte padded payload; random delays in HIGH_RISK mode |
| Authentication | RSA-2048 signature over username at login |
| Transport security | TLS 1.3 minimum enforced |
| Replay protection | 1024-message deduplication ring buffer by msg_id |
| Intrusion detection | Per-IP auth-fail counter; 5-minute block after 5 failures |
| State persistence | Ratchet state encrypted with PBKDF2-derived key (10k iterations) at `~/.aschat/<user>.ratchet` |

## Build Targets

```
make all          Build server + client + certs
make tests        Build all test binaries (including test_tls)
make test         Build and run test suite
make gtk-client   Build GTK GUI client
make phase1       Build Phase 1 TCP-only binaries
make debug        Build with -DDEBUG -O0
make release      Build with -O2 -DNDEBUG
make clean        Remove build artifacts
make clean-all    Remove artifacts and certificates
```
