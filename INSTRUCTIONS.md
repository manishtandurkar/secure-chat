# Instructions — Adaptive Secure Chat

## Prerequisites

**Linux (Ubuntu 20.04+) required.** If on Windows, use WSL (Ubuntu).

```bash
sudo apt-get install -y gcc make libssl-dev pkg-config
# Optional GTK client:
sudo apt-get install -y libgtk-3-dev
```

---

## Build

```bash
# One-time setup
mkdir -p bin data/offline_queue data/keys

# Build server and client
make all

# Generate TLS certificates (self-signed, valid 365 days)
make certs
```

---

## Run

Open three terminals (or WSL panes):

**Terminal 1 — Server:**
```bash
./bin/server
```

**Terminal 2 — Alice:**
```bash
./bin/client localhost 8080 alice
```

**Terminal 3 — Bob:**
```bash
./bin/client localhost 8080 bob
```

---

## Message Syntax

| Input | Effect |
|-------|--------|
| `@bob Hello!` | Send directed message to bob |
| `@all Broadcast` | Send to all connected users |
| `!urgent @bob Emergency` | Urgent priority send to bob |
| `!critical @all SOS` | Critical priority broadcast |
| `/users` | List online users |

> Priority messages bypass queue ordering and wake the send thread immediately.

---

## GTK GUI Client (optional)

```bash
make gtk-client
./bin/client_gtk localhost 8080 alice
```

Features:
- Online users panel (click to fill recipient)
- Broadcast toggle
- Priority selector
- Connect form

---

## Tests

```bash
make tests
```

Runs: `test_crypto`, `test_ratchet`, `test_adaptive`, `test_multipath`, `test_tls`, `test_ids`.

---

## Clean

```bash
make clean       # Remove binaries
make distclean   # Also remove certs and queued messages
```

---

## Architecture Summary

```
Client A  ──TCP+TLS──▶  Server  ──TCP+TLS──▶  Client B
          ──UDP────────▶        ──UDP──────────▶

Encryption:  Double Ratchet (unique key per message)
Auth:        RSA-2048 signatures over TLS 1.3
Transport:   Dual TCP+UDP with deduplication
Queuing:     Encrypted offline storage per user
Security:    IDS per-IP blocking + Adaptive Engine
```

- **Double Ratchet** — every message uses a fresh derived key; past keys are never reusable
- **Adaptive Engine** — monitors packet loss and auth failures; escalates to HIGH_RISK mode (forced padding, random delays, per-message DH ratchet)
- **Offline Queue** — messages for disconnected users are stored encrypted on disk, delivered on reconnect
- **Priority Queue** — CRITICAL > URGENT > NORMAL; CRITICAL bypasses ordering and wakes send thread immediately

---

## Security Notes

- All TLS connections require TLS 1.3 minimum
- Message payloads are always padded to 4096 bytes (traffic analysis resistance)
- Key material is zeroed with `OPENSSL_cleanse()` after use
- Offline queue files: `0600`, directories: `0700`
- Ratchet state files: `~/.aschat/<username>.ratchet` with `0600`
- Usernames restricted to `[a-zA-Z0-9_-]`

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Connection refused` | Start `./bin/server` first |
| `TLS error` | Run `make certs` to regenerate certificates |
| `Auth failed` | Each client generates a fresh RSA keypair on first connect |
| Build error: `openssl/ssl.h not found` | `sudo apt-get install libssl-dev` |
| Build error: `clock_gettime` | Ensure `gcc` and `make` use `-D_POSIX_C_SOURCE=200809L` (already in Makefile) |
