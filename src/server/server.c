#define _POSIX_C_SOURCE 200809L
#include "platform_compat.h"
#include "server.h"
#include "tls_layer.h"
#include "adaptive_engine.h"
#include "intrusion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

typedef struct {
    int connfd;
    SSL_CTX *tls_ctx;
    EngineState *engine;
    Metrics *metrics;
} ClientThreadArgs;

static void *client_thread_main(void *arg) {
    ClientThreadArgs *args = (ClientThreadArgs *)arg;
    handle_client(args->connfd, args->tls_ctx, args->engine, args->metrics);
    free(args);
    return NULL;
}

/* Signal handler for SIGCHLD to reap zombie processes */
void sigchld_handler(int sig) {
    (void)sig; /* Unused parameter */
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len;
    int opt = 1;
    SSL_CTX *tls_ctx = NULL;
    EngineState engine;
    Metrics metrics = {0};

    (void)argc; /* Unused parameter */
    (void)argv; /* Unused parameter */

    printf("Starting Adaptive Secure Communication System\n");
    printf("Protocol Version: 0x%02x\n", PROTOCOL_VERSION);
    printf("Features: Double Ratchet | Multi-Path | Adaptive Engine | Offline Queue\n\n");

    /* Initialize adaptive engine */
    if (engine_init(&engine) != SUCCESS) {
        fprintf(stderr, "Failed to initialize adaptive engine\n");
        return 1;
    }
    
    printf("[Engine] Initialized in MODE_NORMAL\n");

    /* Create TLS context */
    tls_ctx = tls_create_server_ctx("certs/server.crt", "certs/server.key");
    if (!tls_ctx) {
        fprintf(stderr, "Failed to create TLS context. Run 'make certs' first.\n");
        return 1;
    }
    
    printf("[TLS] Server context created (TLS 1.3)\n");

    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        tls_free_ctx(tls_ctx);
        return 1;
    }

    /* Set SO_REUSEADDR option */
#ifdef PLATFORM_WINDOWS
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) < 0) {
#else
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
#endif
        perror("setsockopt");
        socket_close(server_fd);
        tls_free_ctx(tls_ctx);
        return 1;
    }

    /* Initialize server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(SERVER_PORT);

    /* Bind socket */
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        socket_close(server_fd);
        tls_free_ctx(tls_ctx);
        return 1;
    }

    /* Start listening */
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        socket_close(server_fd);
        tls_free_ctx(tls_ctx);
        return 1;
    }

    printf("[Server] Listening on port %d\n", SERVER_PORT);
    printf("[Server] Waiting for connections...\n\n");

    /* Main accept loop */
    while (1) {
        /* Periodically expire IDS blocks */
        ids_expire_blocks();
        
        /* Evaluate adaptive engine state */
        engine_evaluate(&engine, &metrics);
        
        client_addr_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        
        if (client_fd < 0) {
            int err = socket_errno;
            if (socket_interrupted(err)) {
                continue; /* Interrupted by signal, try again */
            }
            perror("accept");
            continue;
        }

        printf("[Server] New connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port));

        ClientThreadArgs *thread_args = malloc(sizeof(*thread_args));
        if (!thread_args) {
            perror("malloc");
            socket_close(client_fd);
            continue;
        }

        thread_args->connfd = client_fd;
        thread_args->tls_ctx = tls_ctx;
        thread_args->engine = &engine;
        thread_args->metrics = &metrics;

        pthread_t client_thread;
        if (pthread_create(&client_thread, NULL, client_thread_main, thread_args) != 0) {
            perror("pthread_create");
            free(thread_args);
            socket_close(client_fd);
            continue;
        }

        pthread_detach(client_thread);
    }

    socket_close(server_fd);
    tls_free_ctx(tls_ctx);
    return 0;
}

/* Server initialization function */
int server_init(void) {
    /* TODO: Implement server resource initialization
     * 1. Create shared memory segment for EngineState
     * 2. Initialize routing table (username → pid mapping)
     * 3. Create offline_queue directory if not exists
     * 4. Initialize UDP notification socket
     * Returns 0 on success, -1 on error
     */
    fprintf(stderr, "[WARN] server_init not yet implemented (using inline init)\n");
    return 0;
}

/* Server cleanup function */
void server_cleanup(void) {
    /* TODO: Implement server resource cleanup
     * 1. Free shared memory segment
     * 2. Clean up routing table
     * 3. Close UDP notification socket
     * 4. Expire all IDS blocks
     */
    fprintf(stderr, "[WARN] server_cleanup not yet implemented\n");
}

/* Main server entry point (wrapper for main) */
int server_main(int argc, char *argv[]) {
    return main(argc, argv);
}