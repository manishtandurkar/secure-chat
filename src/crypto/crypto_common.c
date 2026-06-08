#include <string.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include "crypto.h"

int random_bytes(uint8_t *buf, size_t len) {
    if (RAND_bytes(buf, (int)len) != 1) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int hmac_sha256(const uint8_t *key, size_t key_len,
                const uint8_t *data, size_t data_len,
                uint8_t *out) {
    unsigned int out_len = 32;
    if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    return 0;
}

int hkdf_derive(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return -1;

    int rc = -1;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, (int)salt_len) <= 0) goto done;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, (int)ikm_len) <= 0) goto done;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, (int)info_len) <= 0) goto done;
    if (EVP_PKEY_derive(pctx, out, &out_len) <= 0) goto done;
    rc = 0;

done:
    EVP_PKEY_CTX_free(pctx);
    if (rc < 0) ERR_print_errors_fp(stderr);
    return rc;
}

void kdf_ck(const uint8_t *chain_key,
            uint8_t *chain_key_out,
            uint8_t *msg_key_out) {
    static const uint8_t MSG_CONST  = 0x01;
    static const uint8_t CK_CONST   = 0x02;
    hmac_sha256(chain_key, RATCHET_KEY_LEN, &MSG_CONST, 1, msg_key_out);
    hmac_sha256(chain_key, RATCHET_KEY_LEN, &CK_CONST,  1, chain_key_out);
}

void kdf_rk(const uint8_t *root_key,
            const uint8_t *dh_output, size_t dh_len,
            uint8_t *rk_out, uint8_t *ck_out) {
    uint8_t tmp[64];
    static const uint8_t info_rk[] = "ratchet_rk";
    static const uint8_t info_ck[] = "ratchet_ck";

    hkdf_derive(root_key, RATCHET_KEY_LEN,
                dh_output, dh_len,
                info_rk, sizeof(info_rk) - 1,
                rk_out, RATCHET_KEY_LEN);

    hkdf_derive(root_key, RATCHET_KEY_LEN,
                dh_output, dh_len,
                info_ck, sizeof(info_ck) - 1,
                ck_out, RATCHET_KEY_LEN);

    OPENSSL_cleanse(tmp, sizeof(tmp));
}

EVP_PKEY *dh_generate_keypair(void) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return NULL;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto done;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        pkey = NULL;
    }
done:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

int dh_compute_shared_secret(EVP_PKEY *privkey, EVP_PKEY *peer_pubkey,
                              uint8_t *secret_out, size_t *secret_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!pctx) return -1;

    int rc = -1;
    if (EVP_PKEY_derive_init(pctx) <= 0) goto done;
    if (EVP_PKEY_derive_set_peer(pctx, peer_pubkey) <= 0) goto done;
    if (EVP_PKEY_derive(pctx, NULL, secret_len) <= 0) goto done;
    if (EVP_PKEY_derive(pctx, secret_out, secret_len) <= 0) goto done;
    rc = 0;

done:
    EVP_PKEY_CTX_free(pctx);
    if (rc < 0) ERR_print_errors_fp(stderr);
    return rc;
}
