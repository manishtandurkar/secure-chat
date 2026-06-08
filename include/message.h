#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdint.h>
#include "common.h"

typedef enum {
    MSG_DH_INIT        = 0x01,
    MSG_DH_RESP        = 0x02,
    MSG_AUTH_REQ       = 0x03,
    MSG_AUTH_OK        = 0x04,
    MSG_AUTH_FAIL      = 0x05,
    MSG_CHAT           = 0x06,
    MSG_JOIN_ROOM      = 0x07,
    MSG_LEAVE_ROOM     = 0x08,
    MSG_FILE_START     = 0x09,
    MSG_FILE_CHUNK     = 0x0A,
    MSG_FILE_END       = 0x0B,
    MSG_RATCHET_DH     = 0x0C,
    MSG_OFFLINE_STORED = 0x0D,
    MSG_PRIORITY       = 0x0E,
    MSG_ENGINE_STATE   = 0x0F,
    MSG_USER_LIST_REQ  = 0x10,
    MSG_USER_LIST_RESP = 0x11,
    MSG_ERROR          = 0xFF,
} MsgType;

/* Flags */
#define MSG_FLAG_HAS_DH_PUBKEY    0x01
#define MSG_FLAG_IS_OFFLINE_REPLAY 0x02

typedef struct {
    uint8_t  version;
    uint8_t  msg_type;
    uint8_t  priority;
    uint8_t  flags;
    uint8_t  msg_id[MSG_ID_LEN];
    uint32_t payload_len;
    uint32_t checksum;
} __attribute__((packed)) MsgHeader;

/* Total header size: 1+1+1+1+16+4+4 = 28 bytes */
#define MSG_HEADER_SIZE  28

uint32_t msg_crc32(const void *buf, size_t len);

#endif /* MESSAGE_H */
