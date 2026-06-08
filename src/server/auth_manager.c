#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "server.h"
#include "crypto.h"
#include "common.h"

/* Simple file-backed keystore: data/keys/<username>.pub */
#define KEY_DIR "data/keys"

static int ensure_key_dir(void) {
    struct stat st;
    if (stat(KEY_DIR, &st) == 0) return 0;
    if (mkdir(KEY_DIR, 0700) < 0) { perror(KEY_DIR); return -1; }
    return 0;
}

int auth_register_pubkey(const char *username, const char *pem_pubkey) {
    if (ensure_key_dir() < 0) return -1;

    char path[256];
    snprintf(path, sizeof(path), "%s/%s.pub", KEY_DIR, username);

    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return -1; }
    chmod(path, 0600);
    fputs(pem_pubkey, f);
    fclose(f);
    return 0;
}

int auth_verify(const char *username,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *challenge, size_t challenge_len) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s.pub", KEY_DIR, username);

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "auth: no pubkey for %s\n", username);
        return -1;
    }

    char pem_buf[4096] = {0};
    size_t n = fread(pem_buf, 1, sizeof(pem_buf) - 1, f);
    fclose(f);
    if (n == 0) return -1;

    EVP_PKEY *pubkey = rsa_pubkey_from_pem(pem_buf, n);
    if (!pubkey) return -1;

    int rc = rsa_verify(pubkey, challenge, challenge_len, sig, sig_len);
    EVP_PKEY_free(pubkey);
    return rc;
}
