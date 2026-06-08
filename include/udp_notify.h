#ifndef UDP_NOTIFY_H
#define UDP_NOTIFY_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

int  udp_socket_create(int port);
int  udp_send(int fd, const struct sockaddr_in *dest,
              const void *buf, size_t len);
int  udp_recv(int fd, void *buf, size_t len,
              struct sockaddr_in *src_addr);

/* Presence/heartbeat */
int  udp_send_presence(int fd, const struct sockaddr_in *dest,
                       const char *username);

#endif /* UDP_NOTIFY_H */
