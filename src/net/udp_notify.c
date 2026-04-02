#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE
#define _DEFAULT_SOURCE
#include "udp_notify.h"
#include "platform_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#ifdef PLATFORM_WINDOWS
/* Windows doesn't have gettimeofday or endian.h */
#include <time.h>
static inline int gettimeofday(struct timeval *tv, void *tz) {
    (void)tz;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    unsigned long long t = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t /= 10;  /* Convert to microseconds */
    t -= 11644473600000000ULL;  /* Convert from Windows epoch to Unix epoch */
    tv->tv_sec = (long)(t / 1000000UL);
    tv->tv_usec = (long)(t % 1000000UL);
    return 0;
}
#define htobe64(x) _byteswap_uint64(x)
#define be64toh(x) _byteswap_uint64(x)
#else
#include <sys/time.h>
#include <endian.h>
#endif

/* Create UDP socket for notifications */
int udp_notify_init(int port) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("UDP socket creation failed");
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("UDP bind failed");
        socket_close(sockfd);
        return -1;
    }
    
    return sockfd;
}

/* Close UDP socket */
void udp_notify_close(int sockfd) {
    if (sockfd >= 0) {
        socket_close(sockfd);
    }
}

/* Create UDP socket for notifications (wrapper for udp_notify_init) */
int udp_notify_create_socket(void) {
    return udp_notify_init(UDP_PORT);
}

/* Send notification using UdpNotification structure */
int udp_notify_send(int sockfd, const UdpNotification *notif,
                    const struct sockaddr_in *dest) {
    if (!notif || !dest) {
        return -1;
    }
    
    ssize_t sent = sendto(sockfd, notif, sizeof(UdpNotification), 0,
                         (struct sockaddr *)dest, sizeof(*dest));
    
    return (sent == sizeof(UdpNotification)) ? 0 : -1;
}

/* Receive notification using UdpNotification structure */
int udp_notify_recv(int sockfd, UdpNotification *notif_out,
                    struct sockaddr_in *sender_out) {
    if (!notif_out || !sender_out) {
        return -1;
    }
    
    socklen_t addr_len = sizeof(*sender_out);
    
    ssize_t received = recvfrom(sockfd, notif_out, sizeof(UdpNotification), 0,
                               (struct sockaddr *)sender_out, &addr_len);
    
    return (received == sizeof(UdpNotification)) ? 0 : -1;
}

/* Create a UDP notification structure */
void create_notification(UdpNotification *notif, NotifyType type,
                        const char *username, const char *room) {
    if (!notif) {
        return;
    }
    
    memset(notif, 0, sizeof(UdpNotification));
    notif->type = type;
    
    if (username) {
        strncpy(notif->username, username, MAX_USERNAME_LEN - 1);
        notif->username[MAX_USERNAME_LEN - 1] = '\0';
    }
    
    if (room) {
        strncpy(notif->room, room, MAX_ROOM_NAME_LEN - 1);
        notif->room[MAX_ROOM_NAME_LEN - 1] = '\0';
    }
    
    /* Set timestamp in network byte order */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t timestamp_ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    notif->timestamp = htobe64(timestamp_ms);
}
