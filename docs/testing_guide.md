# Verification & Testing Guide: Secure Chat System

This document outlines the step-by-step procedures to test and verify the entire **Adaptive Secure Communication System** under WSL (Ubuntu-24.04).

---

## 🛠️ Phase 0: Setup and Compilation

First, clean the environment and compile all binaries (server, client, and unit tests) and generate new TLS certificates. Run this in your main WSL terminal:

```bash
make clean-all && make all && make tests
```

---

## 🧪 Phase 1: Automated Unit Test Suite

Run the automated verification suite to validate the lower-level cryptographic and transport state machines:

```bash
make test
```

This tests 7 major components:
*   **Double Ratchet** (`./bin/test_ratchet`): Verifies forward secrecy, break-in recovery (DH ratchet steps), and session serialization.
*   **Crypto Layer** (`./bin/test_crypto`): Verifies AES-GCM encryption/decryption and X3DH bootstrap derivation.
*   **Adaptive Engine** (`./bin/test_adaptive`): Verifies dynamic transition logic between `NORMAL`, `UNSTABLE`, and `HIGH-RISK` modes.
*   **Multi-Path Transport** (`./bin/test_multipath`): Verifies sliding ring-buffer packet deduplication, constant padding, and priority sorting.
*   **TLS 1.3** (`./bin/test_tls`): Verifies secure connection handshakes.
*   **IDS Layer** (`./bin/test_ids`): Verifies progressive IP threat blocking and malformed packet detection.
*   **Network Health Monitor** (`./bin/test_network_monitor`): Verifies real-time latency and packet loss tracking.

---

## 💬 Phase 2: Live Interactive Chat (E2EE Double Ratchet)

Open **three separate WSL terminals** and run the following:

### 1. In Terminal 1 (Server):
Start the server:
```bash
./bin/server
```

### 2. In Terminal 2 (Bob):
Start Bob's client once to register his prekeys in the server's memory, then quit:
```bash
./bin/client localhost 8080 Bob
```
*Type `/quit` once Bob authenticates successfully.*

### 3. In Terminal 3 (Alice):
Start Alice's client:
```bash
./bin/client localhost 8080 Alice
```

### 4. Send E2EE Messages:
In **Alice's terminal (Terminal 3)**, send Bob a message:
```text
@Bob Hello Bob! This is Alice.
```
*   **Verification:** You should see `[+] Derived X3DH E2EE Shared Secret with Bob` print in Alice's console. This proves Alice successfully requested Bob's PreKey bundle, ran X3DH key agreement, and initialized her Double Ratchet.

---

## 💾 Phase 3: Offline Message Queueing

Now test the server-blind offline persistence layer:

1.  **Keep Bob Offline:** Ensure Bob's client is not running.
2.  **Send Offline Message:** In Alice's terminal, type:
    ```text
    @Bob Are you there? I am sending this to your offline queue.
    ```
    *   **Verification:** Alice's terminal will print:
        ```text
        [QUEUE] Recipient offline. Message queued E2EE.
        ```
    *   **Disk Check:** In Bob's terminal, run:
        ```bash
        ls -l data/offline_queue/Bob/
        ```
        You will see a file containing the encrypted message payload. The server cannot decrypt this file because it does not possess the session keys.
3.  **Reconnect Bob:** In Bob's terminal, launch Bob's client:
    ```bash
    ./bin/client localhost 8080 Bob
    ```
    *   **Verification:** Bob should immediately receive and decrypt the offline message:
        ```text
        [MSG][NORMAL] Alice: Are you there? I am sending this to your offline queue.
        ```
    *   **Cleanup Check:** Running `ls -l data/offline_queue/Bob/` again will show the directory is empty, proving the server successfully drained and cleaned up the queued files.

---

## ⚡ Phase 4: Concurrent Stress Testing

To verify thread safety and lock stability under heavy load, run the concurrent stress test script:

```bash
./stress_test.sh
```

*   **What this does:** Spawns a receiver client and 20 sender processes sending 50 E2EE messages each simultaneously.
*   **Pass condition:** All sender processes exit cleanly (code 0) and the server remains alive and stable.

---

## 🛡️ Phase 5: Intrusion Detection & IP Blocking

1.  Start the server (`./bin/server`).
2.  Attempt to connect a client but fail the authentication challenge **5 times** in a row.
3.  On the 5th failure, the server's IDS registry ([intrusion.c](file:///c:/6th%20semester%20EL's/Network%20programming%20and%20security%20lab%20EL/Implementation/secure-chat/src/security/intrusion.c)) will apply an Offense Level 1 block (300 seconds).
4.  Subsequent TCP connections from that client IP will be immediately rejected on `accept()` without entering the TLS handshake.
