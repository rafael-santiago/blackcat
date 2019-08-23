/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_BASEDEFS_DEFS_H
#define BLACKCAT_BASEDEFS_DEFS_H 1

#include <kryptos_types.h>
#include <unistd.h>
#include <stdio.h>

typedef struct blackcat_protlayer_chain blackcat_protlayer_chain_ctx;

typedef void (*blackcat_cipher_processor)(kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer);

typedef int (*blackcat_cipher_args_reader)(const char *algo_params,
                                           void **args, const size_t args_nr,
                                           kryptos_u8_t *key, const size_t key_size,
                                           size_t *argc, char *err_msg);

typedef void (*blackcat_hash_processor)(kryptos_task_ctx **ktask, const int to_hex);

typedef size_t (*blackcat_hash_size_func)(void);

typedef void (*blackcat_encoder)(kryptos_task_ctx **ktask);

typedef kryptos_u8_t *(*blackcat_data_processor)(const blackcat_protlayer_chain_ctx *protlayer,
                                                 kryptos_u8_t *in, size_t in_size,
                                                 size_t *out_size);

typedef kryptos_u8_t *(*blackcat_kdf_func)(kryptos_u8_t *ikm, size_t ikm_size, size_t okm_size, void **args);

#define DECL_BLACKCAT_CIPHER_PROCESSOR(name, ktask, p_layer)\
    void blackcat_ ## name (kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer);

#define IMPL_BLACKCAT_CIPHER_PROCESSOR(name, ktask, p_layer, stmt) \
    void blackcat_ ## name (kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer) {\
        stmt;\
        /*if (kryptos_last_task_succeed((*ktask)) == 0) {\
            printf("BLACKCAT PROCESSOR PANIC [at blackcat_%s()]: %s\n", #name, (*ktask)->result_verbose);\
            exit(1);\
        }*/\
        if ((*ktask)->iv != NULL && (*ktask)->mode != kKryptosCipherModeNr) {\
            kryptos_freeseg((*ktask)->iv, (*ktask)->iv_size);\
            (*ktask)->iv = NULL;\
            (*ktask)->iv_size = 0;\
        }\
    }

#define BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(name, algo_params, args, args_nr, key, key_size, argc, err_mesg)\
    int blackcat_ ## name ## _args(const char *algo_params,\
                                   void **args, const size_t args_nr,\
                                   kryptos_u8_t *key, const size_t key_size,\
                                   size_t *argc, char *err_mesg)

#define BLACKCAT_PROTLAYER_EXTRA_ARGS_NR 10

#define DECL_BLACKCAT_ENCODER_PROCESSOR(name, ktask)\
    void blackcat_ ## name (kryptos_task_ctx **ktask);

#define IMPL_BLACKCAT_ENCODER_PROCESSOR(name, ktask)\
    void blackcat_ ## name(kryptos_task_ctx **ktask) {\
        kryptos_ ## name ##_setup(*ktask);\
        kryptos_ ## name ## _processor(ktask);\
        (*ktask)->encoder = kKryptosEncodingNr;\
    }

#define DECL_BLACKCAT_KDF_PROCESSOR(name, ikm, ikm_size, okm_size, args)\
    kryptos_u8_t *blackcat_ ## name(kryptos_u8_t *ikm, size_t ikm_size, size_t okm_size, void **args);

#define IMPL_BLACKCAT_KDF_PROCESSOR(name, ikm, ikm_size, okm_size, args, stmt)\
    kryptos_u8_t *blackcat_ ## name(kryptos_u8_t *ikm, size_t ikm_size, size_t okm_size, void **args) {\
        stmt;\
    }\

#define BLACKCAT_KDF_ARGS_NR 10

struct blackcat_kdf_clockwork_ctx {
    blackcat_kdf_func kdf;
    void *arg_data[BLACKCAT_KDF_ARGS_NR];
    size_t arg_size[BLACKCAT_KDF_ARGS_NR];
};

struct blackcat_keychain_handle_ctx {
    blackcat_hash_processor hash;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork;
};

typedef struct blackcat_protlayer_chain {
    struct blackcat_protlayer_chain *head, *tail;
    int is_hmac;
    blackcat_encoder encoder;
    blackcat_cipher_processor processor;
    blackcat_hash_processor hash;
    kryptos_u8_t *key;
    size_t key_size;
    kryptos_u8_t *repo_key_hash;
    size_t repo_key_hash_size;
    kryptos_cipher_mode_t mode;
    void *arg[BLACKCAT_PROTLAYER_EXTRA_ARGS_NR];
    size_t argc;
    struct blackcat_protlayer_chain *last, *next;
}blackcat_protlayer_chain_ctx;

#endif
