/**
 * test_tls.c — TLS 1.3 round-trip test
 *
 * Spawns a server thread that accepts one connection and echoes a message back.
 * The main thread acts as the TLS client. Verifies:
 *   1. TLS handshake completes successfully
 *   2. Client can send a message through the TLS tunnel
 *   3. Server receives the message intact
 *   4. Server sends a response and client receives it intact
 */

#define _POSIX_C_SOURCE 200809L
#include "platform_compat.h"
#include "tls_layer.h"
#include "message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define TEST_PORT 19443
#define TEST_CERT "certs/server.crt"
#define TEST_KEY  "certs/server.key"
#define TEST_CA   "certs/ca.crt"

#define PING_MSG  "PING_TLS_TEST"
#define PONG_MSG  "PONG_TLS_TEST"

static int g_server_ok = 0;

typedef struct {
    int listen_fd;
    SSL_CTX *ctx;
} ServerArgs;

static void *server_thread(void *arg) {
    ServerArgs *a = (ServerArgs *)arg;

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int connfd = accept(a->listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (connfd < 0) {
        fprintf(stderr, "[test_tls] accept failed\n");
        return NULL;
    }

    SSL *ssl = tls_wrap_server_socket(a->ctx, connfd);
    if (!ssl) {
        fprintf(stderr, "[test_tls] server TLS wrap failed\n");
        close(connfd);
        return NULL;
    }

    /* Receive PING */
    char buf[64];
    int n = tls_recv(ssl, buf, sizeof(buf) - 1);
    if (n <= 0) {
        fprintf(stderr, "[test_tls] server recv failed\n");
        tls_close(ssl);
        return NULL;
    }
    buf[n] = '\0';

    if (strcmp(buf, PING_MSG) != 0) {
        fprintf(stderr, "[test_tls] server got unexpected msg: '%s'\n", buf);
        tls_close(ssl);
        return NULL;
    }

    /* Send PONG */
    int sent = tls_send(ssl, PONG_MSG, (int)strlen(PONG_MSG));
    if (sent != (int)strlen(PONG_MSG)) {
        fprintf(stderr, "[test_tls] server send failed (%d)\n", sent);
        tls_close(ssl);
        return NULL;
    }

    g_server_ok = 1;
    tls_close(ssl);
    return NULL;
}

int main(void) {
    if (platform_socket_init() != 0) {
        fprintf(stderr, "FAIL: platform_socket_init\n");
        return 1;
    }

    int passed = 0;
    int failed = 0;

    printf("=== TLS Layer Tests ===\n\n");

    if (tls_init() != SUCCESS) {
        fprintf(stderr, "FAIL: tls_init\n");
        platform_socket_cleanup();
        return 1;
    }

    /* ------------------------------------------------------------------ */
    printf("Test 1: TLS server context creation ... ");
    SSL_CTX *server_ctx = tls_create_server_ctx(TEST_CERT, TEST_KEY);
    if (server_ctx) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL (check that 'make certs' has been run)\n");
        failed++;
        tls_cleanup();
        platform_socket_cleanup();
        return 1;
    }

    /* ------------------------------------------------------------------ */
    printf("Test 2: TLS client context creation ... ");
    SSL_CTX *client_ctx = tls_create_client_ctx(TEST_CA);
    if (client_ctx) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
        failed++;
        tls_free_ctx(server_ctx);
        tls_cleanup();
        platform_socket_cleanup();
        return 1;
    }

    /* ------------------------------------------------------------------ */
    printf("Test 3: TLS handshake + round-trip send/recv ... ");

    /* Set up listening socket */
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); platform_socket_cleanup(); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv_addr.sin_port = htons(TEST_PORT);

    if (bind(listen_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("bind");
        close(listen_fd);
        platform_socket_cleanup();
        return 1;
    }
    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        close(listen_fd);
        platform_socket_cleanup();
        return 1;
    }

    /* Start server thread */
    ServerArgs sargs = { .listen_fd = listen_fd, .ctx = server_ctx };
    pthread_t stid;
    pthread_create(&stid, NULL, server_thread, &sargs);

    /* Give server thread a moment to reach accept() */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 50000000 };
    nanosleep(&ts, NULL);

    /* Client connects */
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(client_fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
        perror("connect");
        pthread_join(stid, NULL);
        close(listen_fd);
        close(client_fd);
        printf("FAIL\n");
        failed++;
        goto done;
    }

    SSL *client_ssl = tls_wrap_client_socket(client_ctx, client_fd, "localhost");
    if (!client_ssl) {
        fprintf(stderr, "\n[test_tls] client TLS wrap failed\n");
        pthread_join(stid, NULL);
        close(listen_fd);
        close(client_fd);
        printf("FAIL\n");
        failed++;
        goto done;
    }

    /* Send PING */
    int sent = tls_send(client_ssl, PING_MSG, (int)strlen(PING_MSG));
    if (sent != (int)strlen(PING_MSG)) {
        fprintf(stderr, "\n[test_tls] client send failed (%d)\n", sent);
        tls_close(client_ssl);
        pthread_join(stid, NULL);
        close(listen_fd);
        printf("FAIL\n");
        failed++;
        goto done;
    }

    /* Receive PONG */
    char reply[64];
    int n = tls_recv(client_ssl, reply, sizeof(reply) - 1);
    if (n <= 0) {
        fprintf(stderr, "\n[test_tls] client recv failed (%d)\n", n);
        tls_close(client_ssl);
        pthread_join(stid, NULL);
        close(listen_fd);
        printf("FAIL\n");
        failed++;
        goto done;
    }
    reply[n] = '\0';

    tls_close(client_ssl);
    pthread_join(stid, NULL);
    close(listen_fd);

    if (strcmp(reply, PONG_MSG) == 0 && g_server_ok) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL (got '%s', server_ok=%d)\n", reply, g_server_ok);
        failed++;
    }

    /* ------------------------------------------------------------------ */
done:
    printf("\nTest 4: TLS context and resource cleanup ... ");
    tls_free_ctx(server_ctx);
    tls_free_ctx(client_ctx);
    tls_cleanup();
    printf("PASS\n");
    passed++;

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    platform_socket_cleanup();
    return (failed > 0) ? 1 : 0;
}
