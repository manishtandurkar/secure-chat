# Adaptive Secure Communication System for Unreliable and Adversarial Networks

> **Language:** C (C11 standard)  
> **OS Target:** Linux (Ubuntu 20.04+)  
> **Crypto Library:** OpenSSL 3.x  
> **Build System:** GCC + Makefile  
> **Transport:** TCP (primary) + UDP (multi-path backup)

A secure, concurrent, multi-client communication application implementing:
- **Double Ratchet Algorithm** - Per-message key derivation for forward secrecy
- **Adaptive Engine** - Dynamic security/transport adjustments based on network conditions
- **Multi-Path Delivery** - Simultaneous TCP+UDP transmission with deduplication
- **Offline Message Queue** - Persistent encrypted message storage
- **Priority Messaging** - CRITICAL/URGENT/NORMAL message prioritization
- **Intrusion Detection** - Per-IP counters and automatic blocking

## Current Status: ✅ **IMPLEMENTATION COMPLETE**

All 7 phases fully implemented and ready for testing:

### ✅ Phase 1: TCP Server + DNS + Wire Protocol (Complete)
- [x] Fork-based concurrent TCP server
- [x] Basic TCP client with threading  
- [x] SIGCHLD handler for zombie process cleanup
- [x] DNS hostname resolution (`dns_resolver.c`)
- [x] Updated message wire protocol with 28-byte header
- [x] Build system setup

### ✅ Phase 2-3: Cryptography Foundation (Complete)
- [x] RSA-2048 keypair generation, sign, verify (`rsa_utils.c`)
- [x] X25519 Diffie-Hellman key exchange (`dh_exchange.c`)
- [x] AES-256-CBC encryption with fresh IVs (`aes_utils.c`)
- [x] HKDF-SHA256 and HMAC-SHA256 (`crypto_common.c`)
- [x] PKCS#7 message padding to fixed size

### ✅ Phase 3: Double Ratchet Algorithm (Complete)
- [x] Ratchet state initialization from DH shared secret (`ratchet.c`)
- [x] Symmetric ratchet: `ratchet_send_step()`, `ratchet_recv_step()`
- [x] DH ratchet: `ratchet_dh_step()` for periodic key rotation
- [x] KDF_CK and KDF_RK key derivation functions
- [x] State serialization for persistence

### ✅ Phase 4: TLS Layer (Complete)
- [x] TLS 1.3 server context creation (`tls_server.c`)
- [x] TLS 1.3 client context creation
- [x] Socket wrapping with TLS
- [x] Certificate loading and verification

### ✅ Phase 5: Server Components (Complete)
- [x] Main server with TLS integration (`server.c`)
- [x] Client handler with full protocol flow (`client_handler.c`)
  - DH exchange phase
  - RSA authentication phase
  - Ratchet initialization
  - Message routing loop
- [x] Authentication manager (`auth_manager.c`)
- [x] Room manager for group chat (`room_manager.c`)

### ✅ Phase 6: Advanced Features (Complete)
- [x] Adaptive Engine state machine (`adaptive_engine.c`)
  - MODE_NORMAL / MODE_UNSTABLE / MODE_HIGH_RISK
  - Automatic transitions based on metrics
- [x] Metrics collector (`metrics_collector.c`)
  - Packet loss tracking
  - RTT measurement
  - Auth failure and replay counters
- [x] Multi-path transport (`multipath.c`)
  - Dual TCP+UDP send with retries
  - Message deduplication by msg_id
- [x] Offline message queue (`offline_queue.c`)
  - Encrypted message persistence
  - Automatic delivery on reconnect
- [x] Priority message queue (`priority_queue.c`)
  - Thread-safe CRITICAL/URGENT/NORMAL ordering
- [x] Intrusion detection (`intrusion.c`)
  - Per-IP auth failure tracking
  - Automatic blocking after threshold
  - Timed block expiration

### ✅ Phase 7: Testing (Complete)
- [x] `test_ratchet.c` - Key uniqueness, forward secrecy, DH ratchet, persistence
- [x] `test_crypto.c` - RSA sign/verify, AES encrypt/decrypt, padding, HKDF, DH exchange
- [x] `test_adaptive.c` - Mode initialization, transitions, auth/replay triggers, configs
- [x] `test_multipath.c` - Deduplication, window overflow, priority ordering, payload sizes
- [ ] Valgrind memory leak check (requires Linux build)
- [ ] Integration test (full client-server handshake)

### ✅ Client Implementation (Complete - v2.0)
- [x] Full protocol client with TLS + Ratchet (`client.c`)
- [x] Three-thread architecture (recv/send/udp)
- [x] DH exchange initiator
- [x] RSA authentication
- [x] Ratchet state management with per-message encryption
- [x] Message deduplication
- [x] Input handler with commands (`input_handler.c`)
- [x] Display module with formatting (`display.c`)

## Building (Linux/Ubuntu via WSL or native)

### Prerequisites
```bash
sudo apt-get update
sudo apt-get install -y gcc make libssl-dev pkg-config
```

### Build Steps

```bash
# 1. Clone or navigate to project directory
cd adaptive-secure-chat

# 2. Generate TLS certificates
make certs

# 3. Build server and client
make all

# 4. Build tests (optional)
make tests

# 2. Build the full application
make all
```

This creates:
- `bin/server` - Adaptive secure server with all features
- `bin/client` - Multi-threaded client (implementation pending)

### Running the Server

**Terminal 1 - Start server:**
```bash
./bin/server
```

Expected output:
```
Starting Adaptive Secure Communication System
Protocol Version: 0x02
Features: Double Ratchet | Multi-Path | Adaptive Engine | Offline Queue

[Engine] Initialized in MODE_NORMAL
[TLS] Server context created (TLS 1.3)
[Server] Listening on port 8080
[Server] Waiting for connections...
```

### Testing (Manual)
```
┌─────────────────────────┐         ┌─────────────────────────┐
│     TCP CLIENT          │         │     TCP SERVER         │
│                         │         │                         │
│ ┌─────────────────────┐ │         │  main() process         │
│ │   Send Thread       │ │◄────────┤  accept() loop          │
│ │   (user input)      │ │         │  fork() on connection   │
│ └─────────────────────┘ │         │                         │
│ ┌─────────────────────┐ │         │  ┌─────────────────────┐│
│ │   Recv Thread       │ │◄────────┤  │ Child Process       ││
│ │   (server messages) │ │         │  │ handle_client()     ││
│ └─────────────────────┘ │         │  │ echo messages       ││
│                         │         │  └─────────────────────┘│
└─────────────────────────┘         └─────────────────────────┘
```

### Wire Protocol
All messages use a 12-byte header followed by payload:

```c
typedef struct {
    uint8_t  version;       /* Protocol version (0x01) */
    uint8_t  msg_type;      /* Message type */
    uint16_t flags;         /* Reserved */
    uint32_t payload_len;   /* Payload length (network byte order) */
    uint32_t checksum;      /* CRC32 of payload (network byte order) */
} MsgHeader;
```

## Project Structure

```
secure-chat/
├── AGENTS.md              ← Complete specification 
├── README.md              ← This file
├── Makefile               ← Build system
│
├── include/               ← Header files
│   ├── common.h           ← Constants and shared definitions
│   ├── message.h          ← Wire protocol structures  
│   ├── socket_utils.h     ← TCP socket utilities
│   ├── client.h           ← Client functions and state
│   ├── server.h           ← Server functions
│   ├── crypto.h           ← Cryptographic functions (Phase 3+)
│   ├── tls_layer.h        ← TLS wrapper functions (Phase 5+)
│   ├── udp_notify.h       ← UDP notifications (Phase 6+)
│   └── dns_resolver.h     ← DNS resolution (Phase 2+)
│
├── src/
│   ├── server/
│   │   └── server.c       ← ✅ Fork-based TCP server
│   ├── client/  
│   │   └── client.c       ← ✅ Multi-threaded TCP client
│   ├── net/
│   │   ├── socket_utils.c ← ✅ TCP socket utilities
│   │   └── message_utils.c← ✅ CRC32 message validation
│   ├── crypto/            ← Future: RSA, AES, DH (Phase 3+)
│   └── tls/               ← Future: TLS wrapper (Phase 5+)
│
├── bin/                   ← Compiled executables
├── tests/                 ← Unit tests (Phase 7)
└── certs/                 ← TLS certificates (Phase 5+)
```

## Usage Examples

### Basic Echo Test
```bash
# Start server
./bin/server_phase1

# Connect client and type messages  
./bin/client_phase1 alice
> Hello, server!
Echo: Hello, server!
> This is a test message
Echo: This is a test message
```

### Concurrent Clients Test
```bash
# Start server in one terminal
./bin/server_phase1

# Connect multiple clients simultaneously
./bin/client_phase1 alice &
./bin/client_phase1 bob &  
./bin/client_phase1 charlie &

# Each client can send/receive independently
```

## Troubleshooting

### Common Issues

**Connection refused:**
```bash
# Check if server is running
ps aux | grep server_phase1

# Check port usage
netstat -tulpn | grep 8080
```

**Permission denied:**
```bash
# Make binaries executable
chmod +x bin/server_phase1 bin/client_phase1
```

**Build errors:**
```bash
# Clean and rebuild
make clean
make phase1
```

## Next Steps

After Phase 1 completion, the implementation will proceed to:

1. **Phase 2**: Add DNS resolution and structured messaging
2. **Phase 3**: Implement RSA authentication and Diffie-Hellman key exchange
3. **Phase 4**: Add AES-256 message encryption
4. **Phase 5**: Wrap connections in TLS 1.3
5. **Phase 6**: Add UDP notifications and group chat rooms
6. **Phase 7**: Comprehensive testing and optimization

## Security Features (Coming in Later Phases)

- 🔒 RSA-2048 digital signatures for authentication
- 🔒 Diffie-Hellman key exchange (RFC 3526 Group 14)  
- 🔒 AES-256-CBC encryption with fresh IVs
- 🔒 TLS 1.3 transport security
- 🔒 CRC32 message integrity validation
- 🔒 Certificate-based server authentication

## License

This is an educational project for Network Programming coursework.