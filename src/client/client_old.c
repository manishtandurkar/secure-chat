#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>

#define SERVER_PORT 8080
#define BUFFER_SIZE 4096
#define MAX_USERNAME_LEN 32

/* Global variables for thread communication */
static int sockfd = -1;
static char username[MAX_USERNAME_LEN];
static volatile int running = 1;

/* Thread function to receive messages from server */
void *recv_thread(void *arg) {
    (void)arg; /* Unused parameter */
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    while (running) {
        bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) {
            if (bytes_received < 0 && errno != EINTR) {
                perror("recv");
            } else if (bytes_received == 0) {
                printf("\nServer disconnected\n");
            }
            running = 0;
            break;
        }

        /* Null terminate and display message */
        buffer[bytes_received] = '\0';
        printf("Echo: %s", buffer);
        fflush(stdout);
    }

    return NULL;
}

/* Thread function to send messages to server */
void *send_thread(void *arg) {
    (void)arg; /* Unused parameter */
    char buffer[BUFFER_SIZE];
    size_t len;

    printf("\n=== Phase 1 TCP Echo Client ===\n");
    printf("Connected as: %s\n", username);
    printf("Type messages (Ctrl+C to quit):\n");

    while (running) {
        printf("> ");
        fflush(stdout);

        /* Read user input */
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            if (running) {
                printf("\nInput error or EOF\n");
            }
            break;
        }

        /* Check if we should quit */
        if (!running) break;

        len = strlen(buffer);
        if (len > 0) {
            /* Send message to server */
            if (send(sockfd, buffer, len, 0) < 0) {
                perror("send");
                break;
            }
        }
    }

    running = 0;
    return NULL;
}

/* Signal handler for clean shutdown */
void sigint_handler(int sig) {
    (void)sig; /* Unused parameter */
    printf("\nShutting down client...\n");
    running = 0;
}

/* Connect to server using hostname resolution */
int connect_to_server(const char *hostname, int port) {
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sock;

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    /* Resolve hostname */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "ERROR: no such host %s\n", hostname);
        close(sock);
        return -1;
    }

    /* Setup server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(port);

    /* Connect to server */
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    printf("Connected to %s:%d\n", hostname, port);
    return sock;
}

int main(int argc, char *argv[]) {
    const char *hostname = "localhost";
    int port = SERVER_PORT;
    pthread_t recv_tid, send_tid;
    struct sigaction sa;

    /* Parse command line arguments */
    if (argc < 2 || argc > 4) {
        printf("Usage: %s <username> [hostname] [port]\n", argv[0]);
        printf("Examples:\n");
        printf("  %s alice\n", argv[0]);
        printf("  %s bob localhost\n", argv[0]);
        printf("  %s charlie localhost 8080\n", argv[0]);
        return 1;
    }

    /* Copy username */
    strncpy(username, argv[1], MAX_USERNAME_LEN - 1);
    username[MAX_USERNAME_LEN - 1] = '\0';

    /* Parse optional hostname */
    if (argc >= 3) {
        hostname = argv[2];
    }

    /* Parse optional port */
    if (argc >= 4) {
        port = atoi(argv[3]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port: %s\n", argv[3]);
            return 1;
        }
    }

    /* Install signal handler */
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    /* Connect to server */
    sockfd = connect_to_server(hostname, port);
    if (sockfd < 0) {
        return 1;
    }

    /* Create receiver thread */
    if (pthread_create(&recv_tid, NULL, recv_thread, NULL) != 0) {
        perror("pthread_create recv_thread");
        close(sockfd);
        return 1;
    }

    /* Create sender thread */
    if (pthread_create(&send_tid, NULL, send_thread, NULL) != 0) {
        perror("pthread_create send_thread");
        running = 0;
        pthread_cancel(recv_tid);
        close(sockfd);
        return 1;
    }

    /* Wait for threads to complete */
    pthread_join(send_tid, NULL);
    pthread_join(recv_tid, NULL);

    /* Clean up */
    close(sockfd);
    printf("Client shutdown complete\n");
    return 0;
}