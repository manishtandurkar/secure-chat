#ifndef TLS_LAYER_H
#define TLS_LAYER_H

#include "common.h"

/* Forward declarations for OpenSSL types */
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

/* Server-side TLS functions */

/**
 * Create and configure SSL_CTX for server.
 * cert_file: path to server.crt, key_file: path to server.key
 * Returns SSL_CTX* or NULL on failure.
 */
SSL_CTX *tls_create_server_ctx(const char *cert_file, const char *key_file);

/**
 * Wrap an accepted TCP socket with TLS.
 * Performs SSL_accept(). Returns SSL* or NULL on failure.
 */
SSL *tls_wrap_server_socket(SSL_CTX *ctx, int connfd);

/* Client-side TLS functions */

/**
 * Create SSL_CTX for client. ca_cert_file used to verify server certificate.
 * Returns SSL_CTX* or NULL on failure.
 */
SSL_CTX *tls_create_client_ctx(const char *ca_cert_file);

/**
 * Wrap a connected TCP socket with TLS.
 * Performs SSL_connect() and verifies server certificate.
 * Returns SSL* or NULL on failure.
 */
SSL *tls_wrap_client_socket(SSL_CTX *ctx, int sockfd, const char *hostname);

/* Common TLS functions */

/**
 * Send data over TLS. Returns bytes sent or -1.
 */
int tls_send(SSL *ssl, const void *buf, int len);

/**
 * Receive data over TLS. Returns bytes received or -1.
 */
int tls_recv(SSL *ssl, void *buf, int len);

/**
 * Clean shutdown and free SSL connection
 */
void tls_close(SSL *ssl);

/**
 * Free SSL_CTX
 */
void tls_free_ctx(SSL_CTX *ctx);

/**
 * Initialize OpenSSL library (call once at startup)
 */
int tls_init(void);

/**
 * Cleanup OpenSSL library (call once at shutdown)
 */
void tls_cleanup(void);

#endif /* TLS_LAYER_H */