#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

#define SERVER_PORT           8080
#define UDP_PORT              8081
#define MAX_CLIENTS           50
#define MAX_USERNAME_LEN      32
#define MAX_MSG_LEN           4096
#define MSG_PADDED_SIZE       4096
#define MAX_ROOM_NAME_LEN     64
#define AES_KEY_LEN           32
#define AES_IV_LEN            16
#define RSA_KEY_BITS          2048
#define RATCHET_KEY_LEN       32
#define MSG_ID_LEN            16
#define DEDUP_WINDOW          1024
#define OFFLINE_QUEUE_MAX     500

#define LOSS_THRESHOLD_UNSTABLE    0.05f
#define LOSS_THRESHOLD_HIGH_RISK   0.20f
#define AUTH_FAIL_THRESHOLD        5
#define REPLAY_THRESHOLD           3

#define PRIORITY_NORMAL    0
#define PRIORITY_URGENT    1
#define PRIORITY_CRITICAL  2

#define BLOCK_DURATION_SEC    300
#define MAX_BLOCKED_IPS       256

#define ENGINE_EVAL_INTERVAL_MS  1000

#define ERR_OK             0
#define ERR_GENERIC       -1
#define ERR_CRYPTO        -2
#define ERR_NETWORK       -3
#define ERR_AUTH          -4
#define ERR_QUEUE_FULL    -5
#define ERR_BLOCKED       -6

#endif /* COMMON_H */
