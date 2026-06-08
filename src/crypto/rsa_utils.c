#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "crypto.h"
#include "common.h"

EVP_PKEY *rsa_generate_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        ERR_print_errors_fp(stderr);
        pkey = NULL;
    }
done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int rsa_pubkey_to_pem(EVP_PKEY *key, char *buf, size_t buf_len) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return -1;

    int rc = -1;
    if (PEM_write_bio_PUBKEY(bio, key) != 1) goto done;

    BUF_MEM *bm;
    BIO_get_mem_ptr(bio, &bm);
    if (bm->length >= buf_len) goto done;

    memcpy(buf, bm->data, bm->length);
    buf[bm->length] = '\0';
    rc = (int)bm->length;

done:
    BIO_free(bio);
    if (rc < 0) ERR_print_errors_fp(stderr);
    return rc;
}

EVP_PKEY *rsa_pubkey_from_pem(const char *pem_buf, size_t pem_len) {
    BIO *bio = BIO_new_mem_buf(pem_buf, (int)pem_len);
    if (!bio) return NULL;

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) ERR_print_errors_fp(stderr);
    BIO_free(bio);
    return pkey;
}

int rsa_sign(EVP_PKEY *privkey,
             const unsigned char *data, size_t data_len,
             unsigned char *sig_buf, size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privkey) <= 0) goto done;
    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0) goto done;
    if (EVP_DigestSignFinal(ctx, NULL, sig_len) <= 0) goto done;
    if (EVP_DigestSignFinal(ctx, sig_buf, sig_len) <= 0) goto done;
    rc = 0;

done:
    EVP_MD_CTX_free(ctx);
    if (rc < 0) ERR_print_errors_fp(stderr);
    return rc;
}

int rsa_verify(EVP_PKEY *pubkey,
               const unsigned char *data, size_t data_len,
               const unsigned char *sig, size_t sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) goto done;
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0) goto done;
    int vrc = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    if (vrc == 1) rc = 0;
    else if (vrc != 1) ERR_print_errors_fp(stderr);

done:
    EVP_MD_CTX_free(ctx);
    return rc;
}
