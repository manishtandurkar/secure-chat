# Adaptive Secure Chat

End-to-end encrypted multi-client chat with Double Ratchet, TLS 1.3, multi-path delivery, offline queueing, priority messaging, and adaptive security based on network conditions.

## Quick Start

```bash
# Prerequisites
sudo apt-get install -y gcc make libssl-dev pkg-config libgtk-3-dev

# Build
make all
make gtk-client
make certs

# Run
./bin/server           # Terminal 1
./bin/client_gtk       # Terminal 2 — GTK GUI (recommended)
./bin/client_gtk       # Terminal 3 — second user
```

Enter hostname, port, and a unique username in the login dialog, then click **Connect**.

## GTK GUI Client

- **Login dialog** — enter host, port (default 8080), and username; duplicate usernames are rejected
- **To dropdown** — multi-select checkboxes for online users; **Everyone (All)** for broadcast; or type any username directly (including offline users) in the text field beside the dropdown
- **Priority radio buttons** — Normal / Urgent / Critical; resets to Normal after each send
- **Online Users panel** — live list, updates instantly on any connect/disconnect
- **Rich chat formatting** — timestamps, colored sender names, orange/red priority lines, gray italic system notices
- **Offline queue feedback** — sender sees a gray italic notice when a message is queued; receiver sees a `[queued]` badge on replayed messages

## CLI Client

```bash
./bin/client localhost 8080 alice
```

| Input | Effect |
|-------|--------|
| `@bob Hello!` | Directed message to bob |
| `@all Broadcast` | Send to all connected users |
| `!urgent @bob msg` | Urgent priority to bob |
| `!critical @all msg` | Critical priority broadcast |
| `/users` | List online users |

## Crypto Verbose Logging

Both server and clients print plaintext and ciphertext to stderr automatically — useful for demonstrations:

```
[CLIENT-SEND] E2EE encrypt:
[CLIENT-SEND]   Plaintext:  "bob\nhello"
[CLIENT-SEND]   Ciphertext: a3f8c2d1e047b9...[528 bytes total]

[SERVER] MSG_CHAT from 'alice' — E2EE layer:
[SERVER]   Ciphertext (gibberish): a3f8c2d1e047b9...[528 bytes total]
[SERVER]   Decrypted plaintext: "bob\nhello"
```

## Tests

```bash
make tests
```

## Architecture

See `docs/architecture.md` for full specification.
