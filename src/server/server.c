#include "server.h"
#include "tls_layer.h"
#include "adaptive_engine.h"
#include "intrusion.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

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
    pid_t child_pid;
    struct sigaction sa;
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

    /* Install SIGCHLD handler */
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        tls_free_ctx(tls_ctx);
        return 1;
    }

    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        tls_free_ctx(tls_ctx);
        return 1;
    }

    /* Set SO_REUSEADDR option */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
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
        close(server_fd);
        tls_free_ctx(tls_ctx);
        return 1;
    }

    /* Start listening */
    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        close(server_fd);
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
            if (errno == EINTR) {
                continue; /* Interrupted by signal, try again */
            }
            perror("accept");
            continue;
        }

        printf("[Server] New connection from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port));

        /* Fork child process to handle client */
        child_pid = fork();
        
        if (child_pid < 0) {
            perror("fork");
            close(client_fd);
            continue;
        } else if (child_pid == 0) {
            /* Child process */
            close(server_fd);  /* Child doesn't need the listening socket */
            handle_client(client_fd, tls_ctx, &engine, &metrics);
            /* This point should not be reached (child calls exit) */
            exit(0);
        } else {
            /* Parent process */
            close(client_fd);  /* Parent doesn't need the client socket */
        }
    }

    close(server_fd);
    tls_free_ctx(tls_ctx);
    return 0;
}