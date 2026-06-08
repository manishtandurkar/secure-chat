# Double Ratchet Specification

## Overview

This implementation follows the Signal Double Ratchet Algorithm structure. Every sent message uses a unique derived key — compromise of one key does not expose past or future messages.

## State

```c
typedef struct {
    uint8_t   root_key[32];        // Updated on DH ratchet step
    uint8_t   send_chain_key[32];  // Advances with each sent message
    uint8_t   recv_chain_key[32];  // Advances with each received message
    EVP_PKEY *dh_keypair;          // Our current ephemeral X25519 keypair
    EVP_PKEY *peer_dh_pubkey;      // Peer's last known DH public key
    uint32_t  send_counter;
    uint32_t  recv_counter;
    uint32_t  prev_send_counter;
} RatchetState;
```

## Initialization

After DH key exchange (X25519), both sides call `ratchet_init(shared_secret, is_initiator)`:

```
root_key      = HKDF(salt=0, ikm=shared_secret, info="ratchet_root_init")
send_chain_key = HKDF(salt=0, ikm=shared_secret, info="ratchet_send_init")  [initiator]
recv_chain_key = HKDF(salt=0, ikm=shared_secret, info="ratchet_recv_init")  [initiator]
```

Responder swaps send/recv assignments so both sides derive matching keys.

## Symmetric Ratchet (KDF_CK)

Each message advances its chain key:

```
msg_key       = HMAC-SHA256(chain_key, 0x01)   // 32 bytes, used for AES-256-CBC
new_chain_key = HMAC-SHA256(chain_key, 0x02)   // replaces chain_key
```

- `ratchet_send_step()` — advances `send_chain_key`, returns `msg_key`
- `ratchet_recv_step()` — advances `recv_chain_key`, returns `msg_key`

## DH Ratchet (KDF_RK)

Triggered every `dh_ratchet_freq` messages (10 in NORMAL, 1 in HIGH_RISK):

```
new_root_key     = HKDF(salt=root_key, ikm=DH(our_privkey, peer_pubkey), info="ratchet_rk")
new_chain_key    = HKDF(salt=root_key, ikm=DH(our_privkey, peer_pubkey), info="ratchet_ck")
```

After stepping, a new ephemeral X25519 keypair is generated. The new public key is sent as `MSG_RATCHET_DH`.

## Message Encryption

```
msg_key  = ratchet_send_step()
iv       = RAND_bytes(16)
padded   = msg_pad(plaintext, 4096)          // 4-byte length prefix + zero fill
cipher   = AES-256-CBC(key=msg_key, iv=iv, plaintext=padded)
payload  = iv(16) || cipher(4096+padding)
```

Total `MSG_CHAT` payload: **4112 bytes** (constant).

## Message Decryption

```
msg_key    = ratchet_recv_step()
iv         = payload[0:16]
ciphertext = payload[16:]
padded     = AES-256-CBC-decrypt(key=msg_key, iv=iv, cipher=ciphertext)
plaintext  = msg_unpad(padded)               // reads 4-byte length prefix
```

## Key Material Lifetime

| Key | Lifetime |
|-----|----------|
| `msg_key` | Single message — zeroed with `OPENSSL_cleanse()` immediately after use |
| `send_chain_key` / `recv_chain_key` | Until next symmetric ratchet step |
| `root_key` | Until next DH ratchet step |
| `dh_keypair` | Until next DH ratchet step |

## State Persistence

`ratchet_serialize()` writes `root_key + send_chain_key + recv_chain_key + counters` to a buffer. The buffer is encrypted with a passphrase-derived AES key before writing to `~/.aschat/<username>.ratchet` (mode `0600`).

**Important:** The DH private key is NOT serialized. On deserialization, a fresh keypair is generated and a `MSG_RATCHET_DH` is sent immediately to re-synchronize.

## Security Properties

| Property | How achieved |
|----------|-------------|
| Forward secrecy | Old chain keys discarded after each step |
| Break-in recovery | DH ratchet rotates root after each exchange |
| Key uniqueness | HMAC-SHA256 with distinct constants (0x01 / 0x02) |
| No key reuse | Fresh IV per AES call via `RAND_bytes` |
