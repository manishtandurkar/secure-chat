#include "crypto.h"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/* Generate RSA-2048 keypair */
EVP_PKEY *rsa_generate_keypair(void) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    if (!ctx) {
        return NULL;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Convert RSA public key to PEM string */
int rsa_pubkey_to_pem(EVP_PKEY *key, char *buf, size_t buf_len) {
    if (!key || !buf || buf_len == 0) {
        return ERROR_CRYPTO;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return ERROR_CRYPTO;
    }
    
    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        BIO_free(bio);
        return ERROR_CRYPTO;
    }
    
    int pem_len = BIO_pending(bio);
    if (pem_len <= 0 || (size_t)pem_len >= buf_len) {
        BIO_free(bio);
        return ERROR_CRYPTO;
    }
    
    if (BIO_read(bio, buf, pem_len) != pem_len) {
        BIO_free(bio);
        return ERROR_CRYPTO;
    }
    
    buf[pem_len] = '\0';
    BIO_free(bio);
    
    return SUCCESS;
}

/* Parse RSA public key from PEM string */
EVP_PKEY *rsa_pubkey_from_pem(const char *pem_buf, size_t pem_len) {
    if (!pem_buf || pem_len == 0) {
        return NULL;
    }
    
    BIO *bio = BIO_new_mem_buf(pem_buf, pem_len);
    if (!bio) {
        return NULL;
    }
    
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    return pkey;
}

/* Sign data with RSA private key */
int rsa_sign(EVP_PKEY *privkey, const unsigned char *data, size_t data_len,
             unsigned char *sig_buf, size_t *sig_len) {
    if (!privkey || !data || !sig_buf || !sig_len) {
        return ERROR_CRYPTO;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return ERROR_CRYPTO;
    }
    
    int ret = ERROR_CRYPTO;
    
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privkey) <= 0) {
        goto cleanup;
    }
    
    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0) {
        goto cleanup;
    }
    
    /* Get signature length */
    size_t required_len = 0;
    if (EVP_DigestSignFinal(ctx, NULL, &required_len) <= 0) {
        goto cleanup;
    }
    
    if (required_len > *sig_len) {
        goto cleanup;
    }
    
    /* Actually compute signature */
    if (EVP_DigestSignFinal(ctx, sig_buf, sig_len) <= 0) {
        goto cleanup;
    }
    
    ret = SUCCESS;
    
cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/* Verify RSA signature */
int rsa_verify(EVP_PKEY *pubkey, const unsigned char *data, size_t data_len,
               const unsigned char *sig, size_t sig_len) {
    if (!pubkey || !data || !sig) {
        return ERROR_CRYPTO;
    }
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return ERROR_CRYPTO;
    }
    
    int ret = ERROR_CRYPTO;
    
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) {
        goto cleanup;
    }
    
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0) {
        goto cleanup;
    }
    
    if (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        ret = SUCCESS;
    }
    
cleanup:
    EVP_MD_CTX_free(ctx);
    return ret;
}

/* Free EVP_PKEY (works for RSA and DH keys) */
void crypto_free_key(EVP_PKEY *key) {
    if (key) {
        EVP_PKEY_free(key);
    }
}
