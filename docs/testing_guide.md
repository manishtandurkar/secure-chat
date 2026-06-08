# Testing Guide

## Unit Tests

Run all:
```bash
make tests
```

| Test binary | What it tests |
|-------------|---------------|
| `bin/test_crypto` | AES-256-CBC round-trip, RSA sign/verify, msg_pad/unpad |
| `bin/test_ratchet` | 100 unique message keys, send==recv match, serialize/deserialize |
| `bin/test_adaptive` | All mode transitions (NORMAL→UNSTABLE→HIGH_RISK), config values |
| `bin/test_multipath` | Dedup ring buffer add/check/evict past window |
| `bin/test_tls` | TLS CTX creation |
| `bin/test_ids` | IP blocking after threshold, replay counter |

## Integration Test — GTK GUI (Recommended)

```bash
# Terminal 1
./bin/server

# Terminal 2
./bin/client_gtk   # connect as alice

# Terminal 3
./bin/client_gtk   # connect as bob
```

1. In alice's window: select **bob** from the To dropdown → type `Hello Bob` → Send
2. Bob's window shows: `[HH:MM:SS] alice:  Hello Bob`
3. Alice's window shows the sent message echoed in green: `[HH:MM:SS] You → bob:  Hello Bob`
4. Server stderr shows:
   ```
   [SERVER] MSG_CHAT from 'alice' — E2EE layer:
   [SERVER]   Ciphertext (gibberish): a3f8c2...
   [SERVER]   Decrypted plaintext: "bob\nHello Bob"
   ```

## Integration Test — CLI Client

```bash
# Terminal 1
./bin/server

# Terminal 2
./bin/client localhost 8080 alice

# Terminal 3
./bin/client localhost 8080 bob
```

In alice's terminal:
```
@bob Hello Bob
!urgent @bob This is urgent
```

Expected: Bob receives both messages; `[URGENT]` prefix on the second.

## Unique Username Test

1. Connect as `alice` in one GTK window
2. Open another GTK window and try to connect as `alice` again
3. Expected: login dialog shows **"Username already in use"** — second connection is rejected

## Online Users Panel Test

1. Start server, connect alice → alice's Online Users panel is empty (no other users)
2. Connect bob → alice's panel immediately shows **bob**, bob's panel immediately shows **alice**
3. Close bob's window → alice's panel immediately clears
4. No manual refresh required — server pushes user list on every join/leave

## Offline Queue Test — GUI

```bash
./bin/server &
./bin/client_gtk   # connect as alice
```

1. In alice's To field, type `bob` directly (he is not connected)
2. Send a message
3. Alice's chat shows: `── Message queued for offline user: bob ──` (gray italic)
4. Open a second GTK window, connect as bob
5. Bob's chat immediately shows alice's message with `[queued]` badge:
   ```
   [HH:MM:SS] [queued] alice:  <message>
   ```

## Priority Messaging Test

1. Connect two GTK clients (alice and bob)
2. Alice selects **Critical**, types a message, sends to bob
3. Bob sees entire line in red bold
4. Alice sees entire line in red bold in her own window
5. Priority radio resets to **Normal** after send

## Encryption Proof (Demo)

Both server and clients print crypto details to stderr by default:

```bash
# Run server — watch for [SERVER] lines
./bin/server

# Run client — watch for [CLIENT-SEND] and [CLIENT-RECV] lines
./bin/client_gtk
```

Key observations:
- `[CLIENT-SEND] Plaintext` matches what was typed
- `[CLIENT-SEND] Ciphertext` is hex gibberish — nothing readable
- `[SERVER] Ciphertext` hex is **different** from the client's ciphertext (re-encrypted with recipient's ratchet key)
- `[CLIENT-RECV] Decrypted` matches original plaintext

## Adaptive Engine Test

Simulate packet loss with `tc` (Linux traffic control):

```bash
# Add 25% packet loss on loopback (requires root)
sudo tc qdisc add dev lo root netem loss 25%

# Start server and clients — engine should enter UNSTABLE then HIGH_RISK
./bin/server &
./bin/client_gtk

# Remove rule
sudo tc qdisc del dev lo root
```

Trigger HIGH_RISK via auth failures:
```bash
# Connect 5+ times with wrong signatures to trigger IDS block
# Watch server stderr for: [ENGINE] mode 0 → 2
```

## Memory Leak Check

```bash
sudo apt-get install -y valgrind

# Run server under valgrind for 60 seconds
valgrind --leak-check=full --show-leak-kinds=all ./bin/server &
sleep 60
kill %1
# Check output for "definitely lost" — should be 0 bytes
```

## Expected Test Criteria

| Test | Pass condition |
|------|----------------|
| Ratchet key uniqueness | 100 derived keys, all distinct, Alice send == Bob recv |
| AES round-trip | Decrypt(Encrypt(plaintext)) == plaintext |
| Padding round-trip | msg_unpad(msg_pad(msg)) == msg, exact length match |
| Mode transitions | NORMAL→UNSTABLE at 7% loss, NORMAL→HIGH_RISK at 21% or 5 auth fails |
| Dedup | Same msg_id processed only once |
| IDS block | IP blocked after 5 auth failures |
| Offline delivery | Message queued when recipient offline, delivered on reconnect with [queued] badge |
| Unique username | Second connect with same username rejected with error message |
| User list sync | All clients update Online Users panel simultaneously on any join/leave |
