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

## Integration Test — Two Clients

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

## Offline Queue Test

```bash
# Start server and alice
./bin/server &
./bin/client localhost 8080 alice

# In a separate terminal, send a message to offline bob
# (bob is not connected yet)
# In alice's terminal:
@bob This message will be queued

# Alice should see: [QUEUE] Message queued for offline user: bob

# Now connect bob — queued message should be delivered immediately
./bin/client localhost 8080 bob
```

## Adaptive Engine Test

Simulate packet loss with `tc` (Linux traffic control):

```bash
# Add 25% packet loss on loopback (requires root)
sudo tc qdisc add dev lo root netem loss 25%

# Start server and clients — engine should enter UNSTABLE then HIGH_RISK
./bin/server &
./bin/client localhost 8080 alice

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
| Offline delivery | Message queued when recipient offline, delivered on reconnect |
