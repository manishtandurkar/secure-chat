# Instructions — Adaptive Secure Chat

## Prerequisites

**Linux (Ubuntu 20.04+) required.** If on Windows, use WSL (Ubuntu).

```bash
sudo apt-get install -y gcc make libssl-dev pkg-config libgtk-3-dev
```

---

## Build

```bash
# One-time setup
mkdir -p bin data/offline_queue data/keys

# Build everything
make all          # server + CLI client
make gtk-client   # GTK GUI client

# Generate TLS certificates (self-signed, valid 365 days)
make certs
```

---

## Run — GTK GUI Client (Recommended)

Open three terminals (or WSL panes):

**Terminal 1 — Server:**
```bash
./bin/server
```

**Terminal 2 — First user:**
```bash
./bin/client_gtk
```

**Terminal 3 — Second user:**
```bash
./bin/client_gtk
```

In each login dialog, enter `localhost`, port `8080`, and a unique username, then click **Connect**.

---

## GTK GUI Features

| Feature | Description |
|---------|-------------|
| Login dialog | Enter host/port/username; duplicate usernames are rejected with an error |
| To dropdown | Checkbox list of online users; tick one or more; use **Everyone (All)** to broadcast |
| Offline user entry | Type any username directly in the field next to the dropdown (works for offline users too) |
| Priority | Radio buttons: Normal / Urgent / Critical; resets to Normal after each send |
| Online Users panel | Live list on the right — updates instantly when anyone connects or disconnects |
| Chat formatting | Timestamps (gray), sender name (green=self, blue=others), orange/red for priority messages |
| Offline queue feedback | Sender sees `── Message queued for offline user: bob ──`; receiver sees `[queued]` badge |
| Sent message echo | Your own messages appear in your chat view immediately after sending |

---

## Run — CLI Client

```bash
./bin/client localhost 8080 alice
```

### Message Syntax

| Input | Effect |
|-------|--------|
| `@bob Hello!` | Directed message to bob |
| `@all Broadcast` | Send to all connected users |
| `!urgent @bob Emergency` | Urgent priority send to bob |
| `!critical @all SOS` | Critical priority broadcast |
| `/users` | List online users |

> Priority messages bypass queue ordering and wake the send thread immediately.

---

## Offline Queue Demo

1. Start server and connect as alice
2. In alice's **To** field, type `bob` (who is not connected)
3. Send a message — alice sees `── Message queued for offline user: bob ──`
4. Connect as bob — queued message is delivered immediately with a `[queued]` badge

---

## Crypto Verbose Logging

Enabled by default. Both server and clients print E2EE layer details to stderr:

```
[CLIENT-SEND] E2EE encrypt:
[CLIENT-SEND]   Plaintext:  "bob\nhello"
[CLIENT-SEND]   Ciphertext: a3f8c2d1e047b9...[528 bytes total]

[SERVER] MSG_CHAT from 'alice' — E2EE layer:
[SERVER]   Ciphertext (gibberish): a3f8c2d1e047b9...[528 bytes total]
[SERVER]   Decrypted plaintext: "bob\nhello"

[CLIENT-RECV]   Ciphertext: 5d8e2a1f349c88...
[CLIENT-RECV]   Decrypted:  "alice\nhello"
```

Note: the ciphertext on the send side and on the server side use **different keys** (Double Ratchet re-encrypts for each recipient).

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
- Usernames restricted to `[a-zA-Z0-9_-]`, must be unique per session

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Connection refused` | Start `./bin/server` first |
| `TLS error` | Run `make certs` to regenerate certificates |
| `Username already in use` | Choose a different username — duplicates are rejected |
| `Auth failed` | Each client generates a fresh RSA keypair on first connect |
| Build error: `openssl/ssl.h not found` | `sudo apt-get install libssl-dev` |
| Build error: `gtk/gtk.h not found` | `sudo apt-get install libgtk-3-dev` |
| Online Users panel empty | Wait a moment — server pushes list on connect; click Refresh if needed |
