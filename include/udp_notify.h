#ifndef UDP_NOTIFY_H
#define UDP_NOTIFY_H

#include "common.h"
#include <netinet/in.h>

/* Notification types */
typedef enum {
    NOTIFY_ONLINE    = 1,   /* User came online */
    NOTIFY_OFFLINE   = 2,   /* User went offline */
    NOTIFY_TYPING    = 3,   /* User is typing */
    NOTIFY_STOP_TYPE = 4,   /* User stopped typing */
} NotifyType;

/* UDP notification packet structure */
typedef struct {
    uint8_t  type;                         /* NotifyType */
    char     username[MAX_USERNAME_LEN];   /* Who triggered it */
    char     room[MAX_ROOM_NAME_LEN];      /* Which room */
    uint64_t timestamp;                    /* Unix epoch ms, network byte order */
} __attribute__((packed)) UdpNotification;

/**
 * Create and bind a UDP socket on UDP_NOTIFY_PORT. Returns fd or -1.
 */
int udp_notify_create_socket(void);

/**
 * Send a notification to a specific IP:port. Returns 0 or -1.
 */
int udp_notify_send(int sockfd, const UdpNotification *notif,
                    const struct sockaddr_in *dest);

/**
 * Blocking receive of one notification. Returns 0 or -1.
 */
int udp_notify_recv(int sockfd, UdpNotification *notif_out,
                    struct sockaddr_in *sender_out);

/**
 * Create a UDP notification structure
 */
void create_notification(UdpNotification *notif, NotifyType type,
                        const char *username, const char *room);

#endif /* UDP_NOTIFY_H */