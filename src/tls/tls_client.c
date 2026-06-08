#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls_layer.h"

SSL_CTX *tls_create_client_ctx(const char *ca_cert_file) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    if (ca_cert_file) {
        if (SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
}

SSL *tls_wrap_client_socket(SSL_CTX *ctx, int sockfd, const char *hostname) {
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_set_fd(ssl, sockfd);

    if (hostname)
        SSL_set_tlsext_host_name(ssl, hostname);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    return ssl;
}

int tls_send(SSL *ssl, const void *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = SSL_write(ssl, (const char *)buf + total, len - total);
        if (n <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        total += n;
    }
    return total;
}

int tls_recv(SSL *ssl, void *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = SSL_read(ssl, (char *)buf + total, len - total);
        if (n <= 0) {
            ERR_clear_error(); /* peer disconnect / EOF — caller handles -1 */
            return (total > 0) ? total : -1;
        }
        total += n;
    }
    return total;
}

void tls_close(SSL *ssl) {
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}
