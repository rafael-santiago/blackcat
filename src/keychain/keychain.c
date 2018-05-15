/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/keychain.h>
#include <memory/memory.h>
#include <kryptos.h>
#include <stdlib.h>

struct keychain_algo_ksize_ctx {
    ssize_t key_size;
};

// INFO(Rafael): 'algorithm' is only to force a straightforward documentantion.

#define register_algo_ksize(s, algorithm) { (s) }

static struct keychain_algo_ksize_ctx g_keychain_algo_ksize[] = {
    register_algo_ksize( -1, ARC4),
    register_algo_ksize( -1, SEAL),
    register_algo_ksize( -1, RABBIT),
    register_algo_ksize( 16, AES128),
    register_algo_ksize( 24, AES192),
    register_algo_ksize( 32, AES256),
    register_algo_ksize(  8, DES),
    register_algo_ksize( 24, 3DES),
    register_algo_ksize( 24, 3DESEDE),
    register_algo_ksize( 16, IDEA),
    register_algo_ksize(128, RC2),         // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 64, RC5),
    register_algo_ksize( 16, RC6128),
    register_algo_ksize( 24, RC6192),
    register_algo_ksize( 32, RC6256),
    register_algo_ksize(  8, FEAL),
    register_algo_ksize( 16, CAST5),
    register_algo_ksize( 20, CAMELLIA128), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_algo_ksize( 30, CAMELLIA192), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_algo_ksize( 40, CAMELLIA256), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_algo_ksize(  8, SAFERK64),
    register_algo_ksize( 56, BLOWFISH),    // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 32, SERPENT),
    register_algo_ksize( 16, TEA),
    register_algo_ksize( 16, XTEA),
    register_algo_ksize( 16, MISTY1),
    register_algo_ksize( 16, MARS128),
    register_algo_ksize( 24, MARS192),
    register_algo_ksize( 32, MARS256),
    register_algo_ksize( 10, PRESENT80),
    register_algo_ksize( 16, PRESENT128),
    register_algo_ksize( 64, SHACAL1),     // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 64, SHACAL2),     // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 16, NOEKEON),
    register_algo_ksize( 16, NOEKEOND),    // WARN(Rafael): Even direct mode here is a kind of indirect.
    register_algo_ksize( -1, ARC4HMAC),
    register_algo_ksize( -1, SEALHMAC),
    register_algo_ksize( -1, RABBITHMAC),
    register_algo_ksize( 16, AES128HMAC),
    register_algo_ksize( 24, AES192HMAC),
    register_algo_ksize( 32, AES256HMAC),
    register_algo_ksize(  8, DESHMAC),
    register_algo_ksize( 24, 3DESHMAC),
    register_algo_ksize( 24, 3DESEDEHMAC),
    register_algo_ksize( 16, IDEAHMAC),
    register_algo_ksize(128, RC2HMAC),         // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 64, RC5HMAC),
    register_algo_ksize( 16, RC6128HMAC),
    register_algo_ksize( 24, RC6192HMAC),
    register_algo_ksize( 32, RC6256HMAC),
    register_algo_ksize(  8, FEALHMAC),
    register_algo_ksize( 16, CAST5HMAC),
    register_algo_ksize( 20, CAMELLIA128HMAC), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_algo_ksize( 30, CAMELLIA192HMAC), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_algo_ksize( 40, CAMELLIA256HMAC), // WARN(Rafael): Yes, camellia is less obvious, do not mess.
    register_algo_ksize(  8, SAFERK64HMAC),
    register_algo_ksize( 56, BLOWFISHHMAC),    // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 32, SERPENTHMAC),
    register_algo_ksize( 16, TEAHMAC),
    register_algo_ksize( 16, XTEAHMAC),
    register_algo_ksize( 16, MISTY1HMAC),
    register_algo_ksize( 16, MARS128HMAC),
    register_algo_ksize( 24, MARS192HMAC),
    register_algo_ksize( 32, MARS256HMAC),
    register_algo_ksize( 10, PRESENT80HMAC),
    register_algo_ksize( 16, PRESENT128HMAC),
    register_algo_ksize( 64, SHACAL1HMAC),     // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 64, SHACAL2HMAC),     // WARN(Rafael): Let's use it in its maximum key size.
    register_algo_ksize( 16, NOEKEONHMAC),
    register_algo_ksize( 16, NOEKEONDHMAC)     // WARN(Rafael): Even direct mode here is a kind of indirect.
};

static size_t g_keychain_algo_ksize_nr = sizeof(g_keychain_algo_ksize) / sizeof(g_keychain_algo_ksize[0]);

static kryptos_u8_t *keychain_hash_user_weak_key(const kryptos_u8_t *key, const size_t key_size, ssize_t *wanted_size);

kryptos_u8_t *blackcat_derive_key(const blackcat_protlayer_t algo, const kryptos_u8_t *key, const size_t key_size,
                                  size_t *derived_size) {
    if (key == NULL || derived_size == NULL || algo > g_keychain_algo_ksize_nr) {
        return NULL;
    }

    *derived_size = g_keychain_algo_ksize[algo].key_size;

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

        while (kp_size > 0) {
            kryptos_hash(sha3_512, ktask, (kryptos_u8_t *)key, key_size, 0);
            curr_size = ktask->out_size % kp_size;
            memcpy(kp, ktask->out, curr_size);
            kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
            kp_size -= curr_size;
        }
    }

    return kp;
}

#undef register_algo_ksize
