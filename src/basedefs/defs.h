/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_BASEDEFS_DEFS_H
#define BLACKCAT_BASEDEFS_DEFS_H 1

#include <kryptos_types.h>

typedef struct blackcat_protlayer_chain blackcat_protlayer_chain_ctx;

typedef void (*blackcat_cipher_processor)(kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer);

#define DECL_BLACKCAT_CIPHER_PROCESSOR(name, ktask, p_layer)\
    void blackcat_ ## name (kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer);

#define IMPL_BLACKCAT_CIPHER_PROCESSOR(name, ktask, p_layer, stmt) \
    void blackcat_ ## name (kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer) {\
        stmt;\
    }

#define BLACKCAT_PROTLAYER_EXTRA_ARGS_NR 10

typedef struct blackcat_protlayer_chain {
    struct blackcat_protlayer_chain *head, *tail;
    blackcat_cipher_processor processor;
    kryptos_u8_t *key;
    size_t key_size;
    kryptos_cipher_mode_t mode;
    void *arg[BLACKCAT_PROTLAYER_EXTRA_ARGS_NR];
    struct blackcat_protlayer_chain *last, *next;
}blackcat_protlayer_chain_ctx;

#endif
