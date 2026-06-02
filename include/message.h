#ifndef MESSAGE_H
#define MESSAGE_H

#include "common.h"
#include <stdint.h>

/* Message types for wire protocol */
typedef enum {
    MSG_PREKEY_UPLOAD  = 0x01,  /* Client uploads their public PreKeyBundle to server */
    MSG_PREKEY_REQ     = 0x02,  /* Client A requests Client B's PreKeyBundle */
    MSG_PREKEY_RESP    = 0x03,  /* Server returns Client B's PreKeyBundle */
    MSG_AUTH_REQ       = 0x04,  /* Login: username + Ed25519 signature of challenge */
    MSG_AUTH_OK        = 0x05,  /* Authentication success */
    MSG_AUTH_FAIL      = 0x06,  /* Authentication failure */
    MSG_CHAT           = 0x07,  /* E2EE chat message payload (E2EEChatPayload) */
    MSG_JOIN_ROOM      = 0x08,  /* Client joining a room */
    MSG_LEAVE_ROOM     = 0x09,  /* Client leaving a room */
    MSG_FILE_START     = 0x0A,  /* Begin file transfer */
    MSG_FILE_CHUNK     = 0x0B,  /* File chunk */
    MSG_FILE_END       = 0x0C,  /* File transfer complete */
    MSG_RATCHET_DH     = 0x0D,  /* NEW: carry new DH public key for ratchet step */
    MSG_OFFLINE_STORED = 0x0E,  /* NEW: server confirms message queued for offline user */
    MSG_PRIORITY       = 0x0F,  /* NEW: urgent/critical message signal */
    MSG_ENGINE_STATE   = 0x10,  /* NEW: server broadcasts current adaptive mode to clients */
    MSG_USER_LIST_REQ  = 0x11,  /* Client requests current online user list */
    MSG_USER_LIST_RESP = 0x12,  /* Server responds with comma-separated online users */
    MSG_ERROR          = 0xFF,  /* Error response */
} MsgType;

/* Message header - 28 bytes total, all fields in network byte order */
typedef struct {
    uint8_t  version;              /* Always 0x02 for new protocol */
    uint8_t  msg_type;             /* See MsgType enum above */
    uint8_t  priority;             /* PRIORITY_NORMAL / URGENT / CRITICAL */
    uint8_t  flags;                /* Bit 0: has_dh_pubkey, Bit 1: is_offline_replay */
    uint8_t  msg_id[MSG_ID_LEN];  /* 16-byte random message ID for dedup */
    uint32_t payload_len;          /* Length of payload */
    uint32_t checksum;             /* CRC32 of payload */
} __attribute__((packed)) MsgHeader;

/* E2EE Encrypted message payload */
typedef struct {
    char     sender[MAX_USERNAME_LEN];
    uint8_t  nonce[12];                  /* 96-bit AES-GCM nonce */
    uint8_t  tag[16];                    /* 128-bit AES-GCM auth tag */
    uint8_t  dh_pubkey[32];              /* Ephemeral DR X25519 public key */
    uint32_t message_counter;            /* Sequence counter */
    uint8_t  alice_dh_identity_pub[32];  /* Alice's X3DH DH Identity Pub */
    uint8_t  alice_ephemeral_pub[32];    /* Alice's X3DH Ephemeral Pub */
    uint8_t  ciphertext[MSG_PADDED_SIZE];
} __attribute__((packed)) E2EEChatPayload;

/* Authentication request payload */
typedef struct {
    char username[MAX_USERNAME_LEN];
    uint64_t timestamp;  /* Unix epoch ms, network byte order */
    uint8_t signature[64];  /* Ed25519 signature */
    size_t sig_len;
} __attribute__((packed)) AuthRequest;

/* Chat message payload (before encryption, client-side only) */
typedef struct {
    char username[MAX_USERNAME_LEN];
    char room[MAX_ROOM_NAME_LEN];
    char message[MAX_MSG_LEN];
    uint64_t timestamp;  /* Unix epoch ms, network byte order */
} __attribute__((packed)) ChatMessage;

/* Room join/leave payload */
typedef struct {
    char username[MAX_USERNAME_LEN];
    char room[MAX_ROOM_NAME_LEN];
} __attribute__((packed)) RoomMessage;

/* Function declarations */
uint32_t calculate_crc32(const void *data, size_t len);

#endif /* MESSAGE_H */