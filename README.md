# Adaptive Secure Chat

End-to-end encrypted multi-client chat with Double Ratchet, TLS 1.3, multi-path delivery, offline queueing, priority messaging, and adaptive security based on network conditions.

## Quick Start

```bash
# Prerequisites
sudo apt-get install -y gcc make libssl-dev

# Build
make all
make certs

# Run
./bin/server                          # Terminal 1
./bin/client localhost 8080 alice     # Terminal 2
./bin/client localhost 8080 bob       # Terminal 3
```

## Message Syntax

```
@bob Hello Bob!           # Directed message
@all Announcement         # Broadcast
!urgent @bob Emergency    # Priority send
/users                    # List online users
```

## Tests

```bash
make tests
```

## Architecture

See `AGENTS.md` for full specification.
