/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/keychain.h>
#include <keychain/cipher/arc4.h>
#include <keychain/cipher/seal.h>
#include <keychain/cipher/rabbit.h>
#include <keychain/cipher/aes.h>
#include <keychain/cipher/des.h>
#include <keychain/cipher/idea.h>
#include <memory/memory.h>
#include <kryptos.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct keychain_algo_params_ctx {
    ssize_t key_size;
    const char *name;
    blackcat_cipher_processor processor;
    kryptos_cipher_mode_t mode;
};

static void blackcat_NULL(kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer);

#define register_ciphering_scheme(k, n, p, m) { (k), (n), blackcat_ ## p, kKryptos ## m }

static struct keychain_algo_params_ctx g_keychain_algo_param[] = {
    register_ciphering_scheme( -1, "arc4", arc4, CipherModeNr),
    register_ciphering_scheme( -1, "seal", seal, CipherModeNr),
    register_ciphering_scheme( -1, "rabbit", rabbit, CipherModeNr),
    register_ciphering_scheme( 16, "aes-128-cbc", aes128, CBC),
    register_ciphering_scheme( 24, "aes-192-cbc", aes192, CBC),
    register_ciphering_scheme( 32, "aes-256-cbc", aes256, CBC),
    register_ciphering_scheme(  8, "des-cbc", des, CBC),
    register_ciphering_scheme( 24, "3des-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "3des-ede-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "idea-cbc", idea, CBC),
    register_ciphering_scheme(128, "rc2-cbc", NULL, CBC), // WARN(Rafael): Let's use it in its maximum key size.
    register_ciphering_scheme( 64, "rc5-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "rc6-128-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "rc6-192-cbc", NULL, CBC),
    register_ciphering_scheme( 32, "rc6-256-cbc", NULL, CBC),
    register_ciphering_scheme(  8, "feal-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "cast5-cbc", NULL, CBC),
    register_ciphering_scheme( 20, "camellia-128-cbc", NULL, CBC), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_ciphering_scheme( 30, "camellia-192-cbc", NULL, CBC), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_ciphering_scheme( 40, "camellia-256-cbc", NULL, CBC), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_ciphering_scheme(  8, "safer-k64-cbc", NULL, CBC),
    register_ciphering_scheme( 56, "blowfish-cbc", NULL, CBC), // WARN(Rafael): Let's use it in its maximum key size.
    register_ciphering_scheme( 32, "serpent-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "tea-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "xtea-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "misty1-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "mars-128-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "mars-192-cbc", NULL, CBC),
    register_ciphering_scheme( 32, "mars-256-cbc", NULL, CBC),
    register_ciphering_scheme( 10, "present-80-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "present-128-cbc", NULL, CBC),
    register_ciphering_scheme( 64, "shacal1-cbc", NULL, CBC),
    register_ciphering_scheme( 64, "shacal2-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "noekeon-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "noekeon-d-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "aes-128-ofb", aes128, OFB),
    register_ciphering_scheme( 24, "aes-192-ofb", aes192, OFB),
    register_ciphering_scheme( 32, "aes-256-ofb", aes256, OFB),
    register_ciphering_scheme(  8, "des-ofb", des, OFB),
    register_ciphering_scheme( 24, "3des-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "3des-ede-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "idea-ofb", idea, OFB),
    register_ciphering_scheme(128, "rc2-ofb", NULL, OFB),
    register_ciphering_scheme( 64, "rc5-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "rc6-128-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "rc6-192-ofb", NULL, OFB),
    register_ciphering_scheme( 32, "rc6-256-ofb", NULL, OFB),
    register_ciphering_scheme(  8, "feal-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "cast5-ofb", NULL, OFB),
    register_ciphering_scheme( 20, "camellia-128-ofb", NULL, OFB),
    register_ciphering_scheme( 30, "camellia-192-ofb", NULL, OFB),
    register_ciphering_scheme( 40, "camellia-256-ofb", NULL, OFB),
    register_ciphering_scheme(  8, "safer-k64-ofb", NULL, OFB),
    register_ciphering_scheme( 56, "blowfish-ofb", NULL, OFB),
    register_ciphering_scheme( 32, "serpent-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "tea-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "xtea-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "misty1-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "mars-128-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "mars-192-ofb", NULL, OFB),
    register_ciphering_scheme( 32, "mars-256-ofb", NULL, OFB),
    register_ciphering_scheme( 10, "present-80-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "present-128-ofb", NULL, OFB),
    register_ciphering_scheme( 64, "shacal1-ofb", NULL, OFB),
    register_ciphering_scheme( 64, "shacal2-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "noekeon-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "noekeon-d-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "aes-128-ctr", aes128, CTR),
    register_ciphering_scheme( 24, "aes-192-ctr", aes192, CTR),
    register_ciphering_scheme( 32, "aes-256-ctr", aes256, CTR),
    register_ciphering_scheme(  8, "des-ctr", des, CTR),
    register_ciphering_scheme( 24, "3des-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "3des-ede-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "idea-ctr", idea, CTR),
    register_ciphering_scheme(128, "rc2-ctr", NULL, CTR),
    register_ciphering_scheme( 64, "rc5-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "rc6-128-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "rc6-192-ctr", NULL, CTR),
    register_ciphering_scheme( 32, "rc6-256-ctr", NULL, CTR),
    register_ciphering_scheme(  8, "feal-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "cast5-ctr", NULL, CTR),
    register_ciphering_scheme( 20, "camellia-128-ctr", NULL, CTR),
    register_ciphering_scheme( 30, "camellia-192-ctr", NULL, CTR),
    register_ciphering_scheme( 40, "camellia-256-ctr", NULL, CTR),
    register_ciphering_scheme(  8, "safer-k64-ctr", NULL, CTR),
    register_ciphering_scheme( 56, "blowfish-ctr", NULL, CTR),
    register_ciphering_scheme( 32, "serpent-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "tea-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "xtea-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "misty1-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "mars-128-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "mars-192-ctr", NULL, CTR),
    register_ciphering_scheme( 32, "mars-256-ctr", NULL, CTR),
    register_ciphering_scheme( 10, "present-80-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "present-128-ctr", NULL, CTR),
    register_ciphering_scheme( 64, "shacal1-ctr", NULL, CTR),
    register_ciphering_scheme( 64, "shacal2-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "noekeon-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "noekeon-d-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-aes-128-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "hmac-aes-192-cbc", NULL, CBC),
    register_ciphering_scheme( 32, "hmac-aes-256-cbc", NULL, CBC),
    register_ciphering_scheme(  8, "hmac-des-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "hmac-3des-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "hmac-3des-ede-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-idea-cbc", NULL, CBC),
    register_ciphering_scheme(128, "hmac-rc2-cbc", NULL, CBC),
    register_ciphering_scheme( 64, "hmac-rc5-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-rc6-128-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "hmac-rc6-192-cbc", NULL, CBC),
    register_ciphering_scheme( 32, "hmac-rc6-256-cbc", NULL, CBC),
    register_ciphering_scheme(  8, "hmac-feal-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-cast5-cbc", NULL, CBC),
    register_ciphering_scheme( 20, "hmac-camellia-128-cbc", NULL, CBC),
    register_ciphering_scheme( 30, "hmac-camellia-192-cbc", NULL, CBC),
    register_ciphering_scheme( 40, "hmac-camellia-256-cbc", NULL, CBC),
    register_ciphering_scheme(  8, "hmac-safer-k64-cbc", NULL, CBC),
    register_ciphering_scheme( 56, "hmac-blowfish-cbc", NULL, CBC),
    register_ciphering_scheme( 32, "hmac-serpent-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-tea-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-xtea-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-misty1-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-mars-128-cbc", NULL, CBC),
    register_ciphering_scheme( 24, "hmac-mars-192-cbc", NULL, CBC),
    register_ciphering_scheme( 32, "hmac-mars-256-cbc", NULL, CBC),
    register_ciphering_scheme( 10, "hmac-present-80-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-present-128-cbc", NULL, CBC),
    register_ciphering_scheme( 64, "hmac-shacal1-cbc", NULL, CBC),
    register_ciphering_scheme( 64, "hmac-shacal2-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-noekeon-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-noekeon-d-cbc", NULL, CBC),
    register_ciphering_scheme( 16, "hmac-aes-128-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "hmac-aes-192-ofb", NULL, OFB),
    register_ciphering_scheme( 32, "hmac-aes-256-ofb", NULL, OFB),
    register_ciphering_scheme(  8, "hmac-des-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "hmac-3des-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "hmac-3des-ede-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-idea-ofb", NULL, OFB),
    register_ciphering_scheme(128, "hmac-rc2-ofb", NULL, OFB),
    register_ciphering_scheme( 64, "hmac-rc5-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-rc6-128-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "hmac-rc6-192-ofb", NULL, OFB),
    register_ciphering_scheme( 32, "hmac-rc6-256-ofb", NULL, OFB),
    register_ciphering_scheme(  8, "hmac-feal-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-cast5-ofb", NULL, OFB),
    register_ciphering_scheme( 20, "hmac-camellia-128-ofb", NULL, OFB),
    register_ciphering_scheme( 30, "hmac-camellia-192-ofb", NULL, OFB),
    register_ciphering_scheme( 40, "hmac-camellia-256-ofb", NULL, OFB),
    register_ciphering_scheme(  8, "hmac-safer-k64-ofb", NULL, OFB),
    register_ciphering_scheme( 56, "hmac-blowfish-ofb", NULL, OFB),
    register_ciphering_scheme( 32, "hmac-serpent-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-tea-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-xtea-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-misty1-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-mars-128-ofb", NULL, OFB),
    register_ciphering_scheme( 24, "hmac-mars-192-ofb", NULL, OFB),
    register_ciphering_scheme( 32, "hmac-mars-256-ofb", NULL, OFB),
    register_ciphering_scheme( 10, "hmac-present-80-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-present-128-ofb", NULL, OFB),
    register_ciphering_scheme( 64, "hmac-shacal1-ofb", NULL, OFB),
    register_ciphering_scheme( 64, "hmac-shacal2-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-noekeon-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-noekeon-d-ofb", NULL, OFB),
    register_ciphering_scheme( 16, "hmac-aes-128-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "hmac-aes-192-ctr", NULL, CTR),
    register_ciphering_scheme( 32, "hmac-aes-256-ctr", NULL, CTR),
    register_ciphering_scheme(  8, "hmac-des-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "hmac-3des-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "hmac-3des-ede-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-idea-ctr", NULL, CTR),
    register_ciphering_scheme(128, "hmac-rc2-ctr", NULL, CTR),
    register_ciphering_scheme( 64, "hmac-rc5-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-rc6-128-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "hmac-rc6-192-ctr", NULL, CTR),
    register_ciphering_scheme( 32, "hmac-rc6-256-ctr", NULL, CTR),
    register_ciphering_scheme(  8, "hmac-feal-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-cast5-ctr", NULL, CTR),
    register_ciphering_scheme( 20, "hmac-camellia-128-ctr", NULL, CTR),
    register_ciphering_scheme( 30, "hmac-camellia-192-ctr", NULL, CTR),
    register_ciphering_scheme( 40, "hmac-camellia-256-ctr", NULL, CTR),
    register_ciphering_scheme(  8, "hmac-safer-k64-ctr", NULL, CTR),
    register_ciphering_scheme( 56, "hmac-blowfish-ctr", NULL, CTR),
    register_ciphering_scheme( 32, "hmac-serpent-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-tea-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-xtea-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-misty1-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-mars-128-ctr", NULL, CTR),
    register_ciphering_scheme( 24, "hmac-mars-192-ctr", NULL, CTR),
    register_ciphering_scheme( 32, "hmac-mars-256-ctr", NULL, CTR),
    register_ciphering_scheme( 10, "hmac-present-80-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-present-128-ctr", NULL, CTR),
    register_ciphering_scheme( 64, "hmac-shacal1-ctr", NULL, CTR),
    register_ciphering_scheme( 64, "hmac-shacal2-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-noekeon-ctr", NULL, CTR),
    register_ciphering_scheme( 16, "hmac-noekeon-d-ctr", NULL, CTR)
};

static size_t g_keychain_algo_param_nr = sizeof(g_keychain_algo_param) / sizeof(g_keychain_algo_param[0]);

static kryptos_u8_t *keychain_hash_user_weak_key(const kryptos_u8_t *key, const size_t key_size, ssize_t *wanted_size);

static kryptos_u8_t *blackcat_derive_key(const size_t algo, const kryptos_u8_t *key, const size_t key_size,
                                         size_t *derived_size);

static ssize_t get_algo_index(const char *algo_params);

void blackcat_set_keychain(blackcat_protlayer_chain_ctx **protlayer,
                           const char *algo_params, const kryptos_u8_t *key, const size_t key_size) {
    ssize_t algo = get_algo_index(algo_params);
    blackcat_protlayer_chain_ctx *p;

    if (algo == -1 || protlayer == NULL) {
        return;
    }

    p = (*protlayer);

    p->key = blackcat_derive_key(algo, key, key_size, &p->key_size);
    p->processor = g_keychain_algo_param[algo].processor;
    p->mode = g_keychain_algo_param[algo].mode;
}

static ssize_t get_algo_index(const char *algo_params) {
    ssize_t a;

    if (algo_params == NULL) {
        return -1;
    }

    for (a = 0; a < g_keychain_algo_param_nr; a++) {
        if (strstr(g_keychain_algo_param[a].name, algo_params) == &g_keychain_algo_param[a].name[0]) {
            return a;
        }
    }

    return -1;
}

static kryptos_u8_t *blackcat_derive_key(const size_t algo, const kryptos_u8_t *key, const size_t key_size,
                                         size_t *derived_size) {
    if (key == NULL || derived_size == NULL || algo > g_keychain_algo_param_nr) {
        return NULL;
    }

    *derived_size = g_keychain_algo_param[algo].key_size;

    return keychain_hash_user_weak_key(key, key_size, derived_size);
}

static kryptos_u8_t *keychain_hash_user_weak_key(const kryptos_u8_t *key, const size_t key_size,
                                                 ssize_t *wanted_size) {
    kryptos_u8_t *kp = NULL;
    kryptos_task_ctx t, *ktask = &t;
    size_t kp_size, curr_size;

    if (*wanted_size == - 1) {
        kp = (kryptos_u8_t *) blackcat_getseg(key_size);
        memcpy(kp, key, key_size); // XXX(Rafael): Maybe hash it too.
        *wanted_size = key_size;
    } else {
        kp = (kryptos_u8_t *) blackcat_getseg(*wanted_size);
        kp_size = *wanted_size;
        kryptos_task_set_in(ktask, (kryptos_u8_t *)key, key_size);

        while (kp_size > 0) {
            kryptos_hash(sha3_512, ktask, (kryptos_u8_t *)ktask->in, ktask->in_size, 0);
            curr_size = (ktask->out_size < kp_size) ? ktask->out_size : kp_size;
            memcpy(kp, ktask->out, kp_size);
            if (ktask->in == key) {
                ktask->in = NULL;
                ktask->in_size = 0;
            }
            kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
            kp_size -= curr_size;
        }
    }

    return kp;
}

static void blackcat_NULL(kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer) {
    printf("PANIC: Hi there! You have hit a NULL cipher processor there is nothing beyond here.\n"
           "       If you are seeing this message it means that a pretty stupid developer screwed up something.\n"
           "       Please report this error to someone smarter (if possible) and cross your fingers.\n"
           "       Thanks!\n");
    exit(1);
}

#undef register_ciphering_scheme
