#include <stdio.h>
#include <assert.h>
#include "tls_layer.h"

/* TLS smoke test — just verifies CTX creation doesn't crash */
static int test_ctx_creation(void) {
    /* Client CTX without CA cert (no-verify mode) */
    SSL_CTX *ctx = tls_create_client_ctx(NULL);
    assert(ctx != NULL);
    SSL_CTX_free(ctx);
    printf("[PASS] TLS client CTX creation\n");
    return 0;
}

int main(void) {
    printf("=== test_tls ===\n");
    test_ctx_creation();
    printf("All TLS tests passed.\n");
    return 0;
}
