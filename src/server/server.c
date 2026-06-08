#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include "server.h"
#include "socket_utils.h"
#include "tls_layer.h"
#include "adaptive_engine.h"
#include "intrusion.h"
#include "common.h"

static volatile int g_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

int main(void) {
    signal(SIGINT,  handle_sigint);
    signal(SIGPIPE, SIG_IGN);

    /* Init subsystems */
    client_table_init();
    ids_init();

    if (engine_init(&g_engine_state) < 0) {
        fprintf(stderr, "engine_init failed\n");
        return 1;
    }
    memset(&g_metrics, 0, sizeof(g_metrics));

    /* TLS */
    SSL_CTX *ctx = tls_create_server_ctx("certs/server.crt", "certs/server.key");
    if (!ctx) {
        fprintf(stderr, "Failed to create TLS context\n");
        return 1;
    }

    int server_fd = socket_create_server(SERVER_PORT);
    if (server_fd < 0) return 1;

    printf("[SERVER] Listening on port %d (TLS 1.3)\n", SERVER_PORT);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int connfd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (connfd < 0) {
            if (g_running) perror("accept");
            continue;
        }

        char ip_str[48];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));

        if (ids_is_blocked(ip_str)) {
            ids_log_event("BLOCKED", ip_str);
            close(connfd);
            continue;
        }

        SSL *ssl = tls_wrap_server_socket(ctx, connfd);
        if (!ssl) {
            close(connfd);
            continue;
        }

        HandlerArg *ha = malloc(sizeof(HandlerArg));
        if (!ha) { tls_close(ssl); close(connfd); continue; }
        ha->connfd = connfd;
        ha->ssl    = ssl;
        strncpy(ha->ip_str, ip_str, sizeof(ha->ip_str) - 1);

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, handle_client, ha) != 0) {
            perror("pthread_create");
            free(ha);
            tls_close(ssl);
        }
        pthread_attr_destroy(&attr);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    engine_destroy();
    printf("[SERVER] Shutdown complete.\n");
    return 0;
}
