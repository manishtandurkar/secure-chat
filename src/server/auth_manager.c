#include "server.h"
#include "crypto.h"
#include "message.h"
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>

/* Global RSA public keys storage (simplified) */
static struct {
    char username[MAX_USERNAME_LEN];
    EVP_PKEY *pubkey;
} user_keys[MAX_CLIENTS];
static int user_count = 0;

/* Register user public key */
int auth_register_pubkey(const char *username, EVP_PKEY *pubkey) {
    if (!username || !pubkey || user_count >= MAX_CLIENTS) {
        return ERROR_AUTH;
    }
    
    /* Check if user already registered */
    for (int i = 0; i < user_count; i++) {
        if (strcmp(user_keys[i].username, username) == 0) {
            /* Update existing key */
            if (user_keys[i].pubkey) {
                EVP_PKEY_free(user_keys[i].pubkey);
            }
            user_keys[i].pubkey = pubkey;
            EVP_PKEY_up_ref(pubkey);
            return SUCCESS;
        }
    }
    
    /* Add new user */
    strncpy(user_keys[user_count].username, username, MAX_USERNAME_LEN - 1);
    user_keys[user_count].pubkey = pubkey;
    EVP_PKEY_up_ref(pubkey);
    user_count++;
    
    return SUCCESS;
}

/* Verify RSA signature for authentication */
int auth_verify_login(const char *username, const unsigned char *data,
                      size_t data_len, const unsigned char *signature,
                      size_t sig_len) {
    if (!username || !data || !signature) {
        return ERROR_AUTH;
    }
    
    /* Find user's public key */
    EVP_PKEY *pubkey = NULL;
    for (int i = 0; i < user_count; i++) {
        if (strcmp(user_keys[i].username, username) == 0) {
            pubkey = user_keys[i].pubkey;
            break;
        }
    }
    
    if (!pubkey) {
        return ERROR_AUTH; /* User not registered */
    }
    
    /* Verify signature */
    return rsa_verify(pubkey, data, data_len, signature, sig_len);
}
