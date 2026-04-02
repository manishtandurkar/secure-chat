#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

/* Server configuration constants */
#define SERVER_PORT           8080
#define UDP_PORT              8081
#define MAX_CLIENTS           50
#define MAX_USERNAME_LEN      32
#define MAX_MSG_LEN           4096
#define MSG_PADDED_SIZE       4096    /* All messages padded to this size */
#define MAX_ROOM_NAME_LEN     64

/* Cryptographic constants */
#define AES_KEY_LEN           32      /* 256-bit */
#define AES_IV_LEN            16
#define RSA_KEY_BITS          2048
#define RATCHET_KEY_LEN       32
#define MSG_ID_LEN            16      /* Random 128-bit message ID */
#define DH_PUBKEY_LEN         32      /* X25519 public key size */

/* Deduplication and queue constants */
#define DEDUP_WINDOW          1024    /* Recent message IDs to remember */
#define OFFLINE_QUEUE_MAX     500     /* Max queued messages per user */

/* Adaptive Engine thresholds */
#define LOSS_THRESHOLD_UNSTABLE    0.05f   /* 5% packet loss → Unstable */
#define LOSS_THRESHOLD_HIGH_RISK   0.20f   /* 20% → High-Risk */
#define AUTH_FAIL_THRESHOLD        5       /* 5 failures → High-Risk */
#define REPLAY_THRESHOLD           3       /* 3 replays → High-Risk */

/* Priority levels */
#define PRIORITY_NORMAL    0
#define PRIORITY_URGENT    1
#define PRIORITY_CRITICAL  2

/* Intrusion Detection constants */
#define BLOCK_DURATION_SEC    300   /* 5-minute block */
#define MAX_BLOCKED_IPS       256

/* Protocol version */
#define PROTOCOL_VERSION      0x02  /* Updated for new features */
#define MSG_VERSION           PROTOCOL_VERSION  /* Message header version */

/* Error codes */
#define SUCCESS           0
#define ERROR_GENERAL    -1
#define ERROR_MEMORY     -2
#define ERROR_NETWORK    -3
#define ERROR_CRYPTO     -4
#define ERROR_AUTH       -5

/* Buffer sizes */
#define RECV_BUFFER_SIZE  8192
#define SEND_BUFFER_SIZE  8192

#endif /* COMMON_H */