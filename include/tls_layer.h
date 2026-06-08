#ifndef TLS_LAYER_H
#define TLS_LAYER_H

#include <openssl/ssl.h>

SSL_CTX *tls_create_server_ctx(const char *cert_file, const char *key_file);
SSL     *tls_wrap_server_socket(SSL_CTX *ctx, int connfd);
SSL_CTX *tls_create_client_ctx(const char *ca_cert_file);
SSL     *tls_wrap_client_socket(SSL_CTX *ctx, int sockfd, const char *hostname);
int      tls_send(SSL *ssl, const void *buf, int len);
int      tls_recv(SSL *ssl, void *buf, int len);
void     tls_close(SSL *ssl);

#endif /* TLS_LAYER_H */
