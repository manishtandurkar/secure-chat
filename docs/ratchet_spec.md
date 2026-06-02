# Double Ratchet Specification

## Overview

This implementation follows the structure of the Signal Double Ratchet Algorithm (Trevor Perrin, Moxie Marlinspike, 2016). It combines a **symmetric-key ratchet** (KDF chain) for per-message key derivation with a **Diffie-Hellman ratchet** for periodic root key renewal.

Every message is encrypted with a unique 32-byte key derived from the sender's current chain. Once used, a message key is never stored and cannot be recomputed from subsequent state — this provides **forward secrecy** and **break-in recovery**.

## State Structure

```c
typedef struct {
    uint8_t  root_key[32];        /* Updated on each DH ratchet step */
    uint8_t  send_chain_key[32];  /* Advances with each sent message */
    uint8_t  recv_chain_key[32];  /* Advances with each received message */
    EVP_PKEY *dh_keypair;         /* Our current ephemeral X25519 key */
    EVP_PKEY *peer_dh_pubkey;     /* Peer's last known X25519 public key */
    uint32_t  send_counter;
    uint32_t  recv_counter;
    uint32_t  prev_send_counter;  /* For out-of-order handling */
} RatchetState;
```

## Initialization

After the DH handshake produces a 32-byte shared secret `S`:

```
initial_material = HKDF-SHA256(
    salt  = 0x00 * 32,
    IKM   = S,
    info  = "DoubleRatchetInit",
    L     = 96
)

root_key       = initial_material[0:32]
send_chain_key = initial_material[32:64]  (initiator)
recv_chain_key = initial_material[64:96]  (initiator)

# Responder swaps send and recv chain keys
```

## KDF Functions

### KDF_CK — Advance chain key and derive message key

```
msg_key       = HMAC-SHA256(chain_key, 0x01)
chain_key_new = HMAC-SHA256(chain_key, 0x02)
```

`kdf_ck(chain_key, chain_key_out, msg_key_out)` in `src/crypto/crypto_common.c`.

### KDF_RK — Derive new root key and chain key from DH output

```
(root_key_new, chain_key_new) = HKDF-SHA256(
    salt  = root_key,
    IKM   = DH_output,
    info  = "RatchetDH",
    L     = 64
)
```

`kdf_rk(root_key, dh_output, dh_len, rk_out, ck_out)` in `src/crypto/crypto_common.c`.

## Symmetric Ratchet (Per-Message)

### Sending a message

```
msg_key          = ratchet_send_step(&state)   // advances send_chain_key
iv               = RAND_bytes(16)
ciphertext       = AES-256-CBC(msg_key, iv, msg_pad(plaintext))
payload          = iv || ciphertext            // always AES_IV_LEN + MSG_PADDED_SIZE bytes
```

### Receiving a message

```
msg_key          = ratchet_recv_step(&state)   // advances recv_chain_key
plaintext        = AES-256-CBC-decrypt(msg_key, iv, ciphertext)
message          = msg_unpad(plaintext)
```

Message keys are immediately zeroed with `OPENSSL_cleanse()` after use and are never stored.

## DH Ratchet (Periodic)

A DH ratchet step rotates the root key and both chain keys using a fresh Diffie-Hellman exchange. This bounds the impact of a chain key compromise.

### Trigger

The sender initiates a DH ratchet step every `engine.dh_ratchet_freq` messages:

- `MODE_NORMAL` / `MODE_UNSTABLE`: every 10 messages
- `MODE_HIGH_RISK`: every message

### Step (client initiates)

1. Client generates a new X25519 ephemeral keypair `new_kp`
2. Client replaces `state.dh_keypair = new_kp`
3. Client sends `MSG_RATCHET_DH` containing `new_kp.public_key`

### Step (server receives MSG_RATCHET_DH)

```
dh_out                  = X25519(server.dh_keypair.private, peer_new_pubkey)
(root_key, recv_chain)  = KDF_RK(root_key, dh_out)
state.recv_chain_key    = recv_chain

server_new_kp           = X25519_keygen()
dh_out2                 = X25519(server_new_kp.private, peer_new_pubkey)
(root_key, send_chain)  = KDF_RK(root_key, dh_out2)
state.send_chain_key    = send_chain
state.dh_keypair        = server_new_kp
```

Server sends `MSG_RATCHET_DH` with `server_new_kp.public_key`.

### Step (client receives server's MSG_RATCHET_DH)

Symmetric to the server step above.

After the DH ratchet step:
- Both parties share a new root key derived from fresh DH output
- All previous chain keys are replaced — a compromise of the new chains reveals nothing about messages encrypted under old chains

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Forward secrecy | Each message key is derived and immediately discarded; cannot be recovered from later state |
| Break-in recovery | DH ratchet step after N messages replaces all chain keys; future messages are secure even if current chains are exposed |
| Key uniqueness | `send_counter` increments before every `kdf_ck` call; no two messages share a key within a session |
| Zero-copy key lifecycle | All message keys are stack-allocated and `OPENSSL_cleanse()`d after use |

## State Serialization

The ratchet state is serialized to a 174-byte buffer:

```
root_key[32] | send_chain_key[32] | recv_chain_key[32]
send_counter[4] | recv_counter[4] | prev_send_counter[4]
has_dh_privkey[1] | dh_privkey_raw[32]   (X25519 private key)
has_peer_pubkey[1] | peer_pubkey_raw[32] (X25519 public key)
```

DH keys are serialized as raw 32-byte X25519 key material using `EVP_PKEY_get_raw_private_key` / `EVP_PKEY_get_raw_public_key` and restored with `EVP_PKEY_new_raw_private_key` / `EVP_PKEY_new_raw_public_key`.

The serialized buffer is encrypted with AES-256-CBC using a PBKDF2-HMAC-SHA256 derived key (10,000 iterations, random 16-byte salt per save) and written to `~/.aschat/<username>.ratchet` with mode `0600`.

## Wire Protocol for Ratchet Messages

### MSG_RATCHET_DH (0x0C)

```
MsgHeader (28 bytes)
  msg_type = 0x0C
  payload_len = 32
payload: raw X25519 public key (32 bytes)
```

Both client and server send this message when initiating or responding to a DH ratchet step. The receiver calls `ratchet_dh_step()` and immediately sends back its own new public key.

## References

- Trevor Perrin, Moxie Marlinspike — "The Double Ratchet Algorithm" (2016)
  https://signal.org/docs/specifications/doubleratchet/
- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 5869 — HKDF
