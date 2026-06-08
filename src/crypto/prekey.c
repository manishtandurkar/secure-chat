#include <string.h>
#include "prekey.h"
#include "crypto.h"

EVP_PKEY *prekey_generate(void) {
    return dh_generate_keypair();
}

PreKeyBundle prekey_bundle_create(EVP_PKEY *identity_key) {
    PreKeyBundle bundle = {0};
    bundle.identity_key = identity_key;
    bundle.signed_prekey = dh_generate_keypair();
    bundle.one_time_prekey = dh_generate_keypair();

    if (bundle.signed_prekey && identity_key) {
        uint8_t pub_bytes[32];
        size_t  pub_len = sizeof(pub_bytes);
        if (EVP_PKEY_get_raw_public_key(bundle.signed_prekey, pub_bytes, &pub_len) == 1) {
            bundle.sig_len = sizeof(bundle.signed_prekey_sig);
            rsa_sign(identity_key, pub_bytes, pub_len,
                     bundle.signed_prekey_sig, &bundle.sig_len);
        }
    }
    return bundle;
}

void prekey_bundle_free(PreKeyBundle *bundle) {
    if (!bundle) return;
    if (bundle->signed_prekey)    EVP_PKEY_free(bundle->signed_prekey);
    if (bundle->one_time_prekey)  EVP_PKEY_free(bundle->one_time_prekey);
    memset(bundle, 0, sizeof(*bundle));
}
