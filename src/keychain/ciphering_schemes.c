/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/ciphering_schemes.h>
#include <kryptos_random.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define is_hmac(processor, cipher) ( processor == blackcat_hmac ## _sha224_ ## cipher   ||\
                                     processor == blackcat_hmac ## _sha256_ ## cipher   ||\
                                     processor == blackcat_hmac ## _sha384_ ## cipher   ||\
                                     processor == blackcat_hmac ## _sha512_ ## cipher   ||\
                                     processor == blackcat_hmac ## _sha3_224_ ## cipher ||\
                                     processor == blackcat_hmac ## _sha3_256_ ## cipher ||\
                                     processor == blackcat_hmac ## _sha3_384_ ## cipher ||\
                                     processor == blackcat_hmac ## _sha3_512_ ## cipher ||\
                                     processor == blackcat_hmac ## _tiger_ ## cipher    ||\
                                     processor == blackcat_hmac ## _whirlpool_ ## cipher )

void blackcat_NULL(kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer) {
    printf("PANIC: Hi there! You have hit a NULL cipher processor there is nothing beyond here.\n"
           "       If you are seeing this message it means that a pretty stupid developer screwed up something.\n"
           "       Please report this error to someone smarter (if possible) telling what version you are using and\n"
           "       cross your fingers.\n"
           "       Thanks!\n");
    exit(1);
}

int blackcat_NULL_args(const char *algo_params,
                       void **args, const size_t args_nr,
                       kryptos_u8_t *key, const size_t key_size,
                       size_t *argc, char *err_msg) {
    printf("PANIC: Hi there! You have hit a NULL cipher args reader there is nothing beyond here.\n"
           "       If you are seeing this message it means that a pretty stupid developer screwed up something.\n"
           "       Please report this error to someone smarter (if possible) telling what version you are using and\n"
           "       cross your fingers.\n"
           "       Thanks!\n");
    exit(1);
    return 1;
}

ssize_t get_algo_index(const char *algo_params) {
    ssize_t a;

    if (algo_params == NULL) {
        return -1;
    }

    for (a = 0; a < g_blackcat_ciphering_schemes_nr; a++) {
        if (strstr(algo_params, g_blackcat_ciphering_schemes[a].name) == algo_params) {
            return a;
        }
    }

    return -1;
}

blackcat_hash_processor get_hash_processor(const char *name) {
    size_t h;

    if (name == NULL) {
        return NULL;
    }

    for (h = 0; h < g_blackcat_hashing_algos_nr; h++) {
        if (strcmp(g_blackcat_hashing_algos[h].name, name) == 0) {
            return g_blackcat_hashing_algos[h].processor;
        }
    }

    return NULL;
}

blackcat_hash_size_func get_hash_size(const char *name) {
    size_t h;

    if (name == NULL) {
        return NULL;
    }

    for (h = 0; h < g_blackcat_hashing_algos_nr; h++) {
        if (strcmp(g_blackcat_hashing_algos[h].name, name) == 0) {
            return g_blackcat_hashing_algos[h].size;
        }
    }

    return NULL;
}

int is_hmac_processor(blackcat_cipher_processor processor) {
    return is_hmac(processor, aes128)         ||
           is_hmac(processor, aes192)         ||
           is_hmac(processor, aes256)         ||
           is_hmac(processor, des)            ||
           is_hmac(processor, triple_des)     ||
           is_hmac(processor, triple_des_ede) ||
           is_hmac(processor, idea)           ||
           is_hmac(processor, rc2)            ||
           is_hmac(processor, rc5)            ||
           is_hmac(processor, rc6_128)        ||
           is_hmac(processor, rc6_192)        ||
           is_hmac(processor, rc6_256)        ||
           is_hmac(processor, feal)           ||
           is_hmac(processor, cast5)          ||
           is_hmac(processor, camellia128)    ||
           is_hmac(processor, camellia192)    ||
           is_hmac(processor, camellia256)    ||
           is_hmac(processor, saferk64)       ||
           is_hmac(processor, blowfish)       ||
           is_hmac(processor, serpent)        ||
           is_hmac(processor, tea)            ||
           is_hmac(processor, xtea)           ||
           is_hmac(processor, misty1)         ||
           is_hmac(processor, mars128)        ||
           is_hmac(processor, mars192)        ||
           is_hmac(processor, mars256)        ||
           is_hmac(processor, present80)      ||
           is_hmac(processor, present128)     ||
           is_hmac(processor, shacal1)        ||
           is_hmac(processor, shacal2)        ||
           is_hmac(processor, noekeon)        ||
           is_hmac(processor, noekeon_d);
}

int is_weak_hash_funcs_usage(blackcat_hash_processor h1, blackcat_hash_processor h2) {
    struct forbidden_hash_func_usage {
        blackcat_hash_processor h1, h2;
    };
#define register_forbidden_usage(hash_1, hash_2) { kryptos_ ## hash_1 ## _hash, kryptos_ ## hash_2 ## _hash }
    static struct forbidden_hash_func_usage fhfu[] = {
        register_forbidden_usage(sha224, sha224),
        register_forbidden_usage(sha256, sha256),
        register_forbidden_usage(sha384, sha384),
        register_forbidden_usage(sha512, sha512),
        register_forbidden_usage(sha224, sha256),
        register_forbidden_usage(sha256, sha224),
        register_forbidden_usage(sha384, sha512),
        register_forbidden_usage(sha512, sha384),
        register_forbidden_usage(sha3_224, sha3_224),
        register_forbidden_usage(sha3_256, sha3_256),
        register_forbidden_usage(sha3_384, sha3_384),
        register_forbidden_usage(sha3_512, sha3_512),
        register_forbidden_usage(sha3_224, sha3_256),
        register_forbidden_usage(sha3_224, sha3_384),
        register_forbidden_usage(sha3_224, sha3_512),
        register_forbidden_usage(sha3_256, sha3_224),
        register_forbidden_usage(sha3_256, sha3_384),
        register_forbidden_usage(sha3_256, sha3_512),
        register_forbidden_usage(sha3_384, sha3_224),
        register_forbidden_usage(sha3_384, sha3_256),
        register_forbidden_usage(sha3_384, sha3_512),
        register_forbidden_usage(sha3_512, sha3_224),
        register_forbidden_usage(sha3_512, sha3_256),
        register_forbidden_usage(sha3_512, sha3_384),
        register_forbidden_usage(tiger, tiger),
        register_forbidden_usage(whirlpool, whirlpool)
    };
#undef register_forbidden_usage
    size_t fhfu_nr = sizeof(fhfu) / sizeof(fhfu[0]), f;
    int is_weak = 0;

    for (f = 0; f < fhfu_nr && !is_weak; f++) {
        is_weak = (fhfu[f].h1 == h1 && fhfu[f].h2 == h2);
    }

    return is_weak;
}

#undef is_hmac

const char *get_hash_processor_name(blackcat_hash_processor processor) {
    size_t h;

    for (h = 0; h < g_blackcat_hashing_algos_nr; h++) {
        if (processor == g_blackcat_hashing_algos[h].processor) {
            return &g_blackcat_hashing_algos[h].name[0];
        }
    }

    return NULL;
}

const struct blackcat_hmac_catalog_algorithms_ctx *get_hmac_catalog_scheme(const char *name) {
    size_t s;

    for (s = 0; s < g_blackcat_hmac_catalog_schemes_nr; s++) {
        if (strcmp(name, g_blackcat_hmac_catalog_schemes[s].name) == 0) {
            return &g_blackcat_hmac_catalog_schemes[s];
        }
    }

    return NULL;
}

const struct blackcat_hmac_catalog_algorithms_ctx *get_random_hmac_catalog_scheme(void) {
    size_t s = ((size_t) kryptos_get_random_byte() << 24) |
               ((size_t) kryptos_get_random_byte() << 16) |
               ((size_t) kryptos_get_random_byte() <<  8) |
               ((size_t) kryptos_get_random_byte());
    return &g_blackcat_hmac_catalog_schemes[s % g_blackcat_hmac_catalog_schemes_nr];
}
