#include "tls_layer.h"
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Create TLS server context */
SSL_CTX *tls_create_server_ctx(const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) {
        return NULL;
    }
    
    /* Initialize OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    /* Create TLS 1.3 server context */
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    /* Set minimum TLS version to 1.3 */
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        fprintf(stderr, "Failed to set TLS 1.3 minimum version\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Load certificate */
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Load private key */
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Verify private key matches certificate */
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    return ctx;
}

/* Wrap server socket with TLS */
SSL *tls_wrap_server_socket(SSL_CTX *ctx, int connfd) {
    if (!ctx || connfd < 0) {
        return NULL;
    }
    
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    if (SSL_set_fd(ssl, connfd) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    /* Perform TLS handshake */
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

/* Create TLS client context */
SSL_CTX *tls_create_client_ctx(const char *ca_cert_file) {
    /* Initialize OpenSSL */
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    /* Set minimum TLS version to 1.3 */
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        fprintf(stderr, "Failed to set TLS 1.3 minimum version\n");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    /* Load CA certificate if provided */
    if (ca_cert_file) {
        if (SSL_CTX_load_verify_locations(ctx, ca_cert_file, NULL) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
    
    /* Set verification mode */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    return ctx;
}

/* Wrap client socket with TLS */
SSL *tls_wrap_client_socket(SSL_CTX *ctx, int sockfd, const char *hostname) {
    if (!ctx || sockfd < 0) {
        return NULL;
    }
    
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    if (SSL_set_fd(ssl, sockfd) != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    /* Set SNI hostname if provided */
    if (hostname) {
        SSL_set_tlsext_host_name(ssl, hostname);
    }
    
    /* Perform TLS handshake */
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }
    
    return ssl;
}

/* Send data over TLS */
int tls_send(SSL *ssl, const void *buf, int len) {
    if (!ssl || !buf || len <= 0) {
        return ERROR_NETWORK;
    }
    
    int total_sent = 0;
    while (total_sent < len) {
        int n = SSL_write(ssl, (const char *)buf + total_sent, len - total_sent);
        if (n <= 0) {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                continue; /* Retry */
            }
            ERR_print_errors_fp(stderr);
            return ERROR_NETWORK;
        }
        total_sent += n;
    }
    
    return total_sent;
}

/* Receive data over TLS */
int tls_recv(SSL *ssl, void *buf, int len) {
    if (!ssl || !buf || len <= 0) {
        return ERROR_NETWORK;
    }
    
    int n = SSL_read(ssl, buf, len);
    if (n <= 0) {
        int err = SSL_get_error(ssl, n);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0; /* No data available, not an error */
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0; /* Clean shutdown */
        }
        ERR_print_errors_fp(stderr);
        return ERROR_NETWORK;
    }
    
    return n;
}

/* Close TLS connection */
void tls_close(SSL *ssl) {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}

/* Free TLS context */
void tls_free_ctx(SSL_CTX *ctx) {
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}
