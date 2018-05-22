/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/ciphering_schemes.h>
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


#undef is_hmac
