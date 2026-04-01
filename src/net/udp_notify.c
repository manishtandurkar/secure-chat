#include "udp_notify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

/* Send UDP notification */
int udp_notify_send(int sockfd, const char *dest_ip, int dest_port,
                    const void *data, size_t len) {
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        return -1;
    }
    
    ssize_t sent = sendto(sockfd, data, len, 0,
                         (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    
    return (sent == (ssize_t)len) ? 0 : -1;
}

/* Receive UDP notification */
int udp_notify_recv(int sockfd, void *buf, size_t buf_len,
                    char *src_ip, size_t ip_len) {
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    ssize_t received = recvfrom(sockfd, buf, buf_len, 0,
                               (struct sockaddr *)&src_addr, &addr_len);
    
    if (received < 0) {
        return -1;
    }
    
    if (src_ip && ip_len > 0) {
        inet_ntop(AF_INET, &src_addr.sin_addr, src_ip, ip_len);
    }
    
    return (int)received;
}

/* Close UDP socket */
void udp_notify_close(int sockfd) {
    if (sockfd >= 0) {
        close(sockfd);
    }
}
