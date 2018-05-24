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

#define DECL_BLACKCAT_CIPHER_PROCESSOR(name, ktask, p_layer)\
    void blackcat_ ## name (kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer);

#define IMPL_BLACKCAT_CIPHER_PROCESSOR(name, ktask, p_layer, stmt) \
    void blackcat_ ## name (kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer) {\
        stmt;\
        if (kryptos_last_task_succeed((*ktask)) == 0) {\
            printf("BLACKCAT PROCESSOR PANIC [at blackcat_%s()]: %s %d\n", #name, (*ktask)->result_verbose, (*ktask)->cipher);\
            exit(1);\
        }\
        if ((*ktask)->iv != NULL && (*ktask)->mode != kKryptosCipherModeNr) {\
            kryptos_freeseg((*ktask)->iv);\
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

typedef struct blackcat_protlayer_chain {
    struct blackcat_protlayer_chain *head, *tail;
    int is_hmac;
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
