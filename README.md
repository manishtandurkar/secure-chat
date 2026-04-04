# Adaptive Secure Communication System

Language: C11

Crypto: OpenSSL 3.x

Build: GCC + Makefile

Primary target: Linux (Ubuntu 20.04+). Windows users should run through WSL for best compatibility.

## What This Project Provides

- TLS 1.3 transport setup
- RSA authentication helpers
- Diffie-Hellman key exchange helpers
- Double Ratchet primitives
- AES encryption and fixed-size message padding
- Adaptive engine mode logic
- Multi-path transport utilities (TCP/UDP support code)
- Offline queue and priority queue modules
- Unit tests for core modules

## Repository Layout

- `bin/` compiled binaries
- `certs/` generated TLS cert/key files
- `include/` headers
- `src/` implementation
- `tests/` unit tests
- `data/offline_queue/` persisted offline ciphertext files

## Prerequisites

### Linux or WSL Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y gcc make libssl-dev pkg-config
```

### Verify Toolchain

```bash
gcc --version
make --version
pkg-config --modversion openssl
```


## Build Instructions

From project root:

```bash
make clean
make all
```


What `make all` does:

1. Creates `bin/` (if missing)
2. Builds `bin/server`
3. Builds `bin/client`
4. Generates TLS materials in `certs/`

Build tests:

```bash
make tests
```

Build only one target:

```bash
make server
make client
```

Build phase-1 TCP-only binaries:

```bash
make phase1
```

## Running The Application

Open three terminals.

Terminal 1 (server):

```bash
./bin/server
```

Terminal 2 (client A):

```bash
./bin/client localhost 8080 alice
```

Terminal 3 (client B):

```bash
./bin/client localhost 8080 bob
```

Client usage notes:

- Type a message and press Enter to send.
- Use `/quit` to disconnect cleanly.

## Detailed Test Workflow

## 1) Fast Build Validation

```bash
make clean
make all
```

Checks:

- `bin/server` exists
- `bin/client` exists
- `certs/server.crt`, `certs/server.key`, `certs/ca.crt` exist

## 2) Run Unit Tests

Build and run all unit tests:

```bash
make test
```

This runs:

- `./bin/test_ratchet`
- `./bin/test_crypto`
- `./bin/test_adaptive`
- `./bin/test_multipath`

Run one test directly:

```bash
./bin/test_crypto
```

Pass condition: process exits with code `0`.

## 3) Manual End-to-End Smoke Test

1. Start server in terminal A:

```bash
./bin/server
```

2. Start client in terminal B:

```bash
./bin/client localhost 8080 testuser
```

3. Send a few messages from client.

Expected:

- Client establishes connection and authenticates.
- Messages are processed without crash.
- Server remains running and logs message handling.

## 4) Two-Client Concurrency Check

1. Server in terminal A.
2. Start two clients with different usernames.
3. Send messages from both clients quickly.

Expected:

- Both clients remain connected.
- Server does not crash or hang.
- Message processing continues for both sessions.

## 5) Scripted Feature Check (WSL/Linux)

A helper script exists:

```bash
chmod +x test_all_features.sh
./test_all_features.sh
```


Notes:

- Script assumes Linux paths and commands.
- Run it from WSL or Linux, not native cmd.exe.

## 6) Inspect Exit Codes In CI/Automation

Example:

```bash
make tests && ./bin/test_ratchet && ./bin/test_crypto && ./bin/test_adaptive && ./bin/test_multipath
```

Use non-zero exit code as failure signal.

## Troubleshooting

Connection refused:

- Ensure server is running before client.
- Confirm server port (`8080`) is not occupied.

TLS/certificate failures:

```bash
make certs
```

Then retry server and client.

Build fails due to OpenSSL headers/libs:

```bash
sudo apt-get install -y libssl-dev pkg-config
pkg-config --cflags --libs openssl
```

Windows native shell issues:

- Prefer WSL Ubuntu for runtime and tests.
- If using Git Bash/MSYS2, ensure OpenSSL dev libraries are available and compatible.

## Useful Make Targets

```bash
make help
```

Common targets:

- `make all`
- `make tests`
- `make test`
- `make clean`
- `make certs`
- `make debug`
- `make release`

## Recommended Verification Order

1. `make clean && make all`
2. `make test`
3. Manual server/client smoke run
4. Optional: `./test_all_features.sh`

This sequence gives fast confidence in build health, crypto logic, adaptive logic, and runtime startup behavior.
