#ifndef MESSAGE_H
#define MESSAGE_H

#include "common.h"
#include <stdint.h>

/* Message types for wire protocol */
typedef enum {
    MSG_DH_INIT        = 0x01,  /* DH public key from client */
    MSG_DH_RESP        = 0x02,  /* DH public key from server */
    MSG_AUTH_REQ       = 0x03,  /* Login: username + RSA signature */
    MSG_AUTH_OK        = 0x04,  /* Authentication success */
    MSG_AUTH_FAIL      = 0x05,  /* Authentication failure */
    MSG_CHAT           = 0x06,  /* Encrypted chat message: IV(16) + padded_ciphertext */
    MSG_JOIN_ROOM      = 0x07,  /* Client joining a room */
    MSG_LEAVE_ROOM     = 0x08,  /* Client leaving a room */
    MSG_FILE_START     = 0x09,  /* Begin file transfer */
    MSG_FILE_CHUNK     = 0x0A,  /* File chunk */
    MSG_FILE_END       = 0x0B,  /* File transfer complete */
    MSG_RATCHET_DH     = 0x0C,  /* NEW: carry new DH public key for ratchet step */
    MSG_OFFLINE_STORED = 0x0D,  /* NEW: server confirms message queued for offline user */
    MSG_PRIORITY       = 0x0E,  /* NEW: urgent/critical message signal */
    MSG_ENGINE_STATE   = 0x0F,  /* NEW: server broadcasts current adaptive mode to clients */
    MSG_ERROR          = 0xFF,  /* Error response */
} MsgType;

/* Message header - 28 bytes total, all fields in network byte order */
typedef struct {
    uint8_t  version;              /* Always 0x02 for new protocol */
    uint8_t  msg_type;             /* See MsgType enum above */
    uint8_t  priority;             /* PRIORITY_NORMAL / URGENT / CRITICAL */
    uint8_t  flags;                /* Bit 0: has_dh_pubkey, Bit 1: is_offline_replay */
    uint8_t  msg_id[MSG_ID_LEN];  /* 16-byte random message ID for dedup */
    uint32_t payload_len;          /* Length of payload (always MSG_PADDED_SIZE for CHAT) */
    uint32_t checksum;             /* CRC32 of payload */
} __attribute__((packed)) MsgHeader;

/* Authentication request payload */
typedef struct {
    char username[MAX_USERNAME_LEN];
    uint64_t timestamp;  /* Unix epoch ms, network byte order */
    uint8_t signature[256];  /* RSA signature */
    size_t sig_len;
} __attribute__((packed)) AuthRequest;

/* Chat message payload (before encryption) */
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