/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <ctx/ctx.h>
#include <basedefs/defs.h>
#include <keychain/keychain.h>
#include <kryptos_memory.h>
#include <string.h>
#include <stdio.h>

#define new_blackcat_protlayer_chain_ctx(b) {\
    (b) = (blackcat_protlayer_chain_ctx *) kryptos_newseg(sizeof(blackcat_protlayer_chain_ctx));\
    if ((b) != NULL) {\
        (b)->head = (b)->tail = (b)->next = (b)->last = NULL;\
        (b)->key = NULL;\
        (b)->key_size = 0;\
        (b)->processor = NULL;\
        (b)->argc = 0;\
        (b)->is_hmac = 0;\
        (b)->encoder = NULL;\
    }\
}

static blackcat_protlayer_chain_ctx *get_protlayer_chain_tail(blackcat_protlayer_chain_ctx *chain);

blackcat_protlayer_chain_ctx *add_composite_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                               const char *piped_ciphers, const size_t piped_ciphers_size,
                                                               kryptos_u8_t **key,
                                                               size_t *key_size, struct blackcat_keychain_handle_ctx *handle,
                                                               blackcat_encoder encoder) {
    char curr_algo_param[65535];
    const char *p, *p_end, *cp;
    size_t curr_algo_param_size;

    if (piped_ciphers == NULL || key == NULL || key_size == NULL || handle == NULL) {
        return chain;
    }

    p = piped_ciphers;
    p_end = p + piped_ciphers_size;

    memset(curr_algo_param, 0, sizeof(curr_algo_param));

    while (p < p_end) {
        while (p != p_end && (*p == ' ' || *p == '\t' || *p == '\n')) {
            p++;
        }

        cp = p;

        while (p != p_end && *p != ',') {
            p++;
        }

        if ((p - cp) > sizeof(curr_algo_param)) {
            fprintf(stderr, "ERROR: Unable to process the current algo param. Aborted.\n");
            return NULL;
        }

        curr_algo_param_size = p - cp;

        memcpy(curr_algo_param, cp, curr_algo_param_size);

        chain = add_protlayer_to_chain(chain, curr_algo_param, curr_algo_param_size, key, key_size, handle);

        if (chain == NULL) {
            fprintf(stderr, "ERROR: Invalid algorithm '%s'.\n", curr_algo_param);
            goto add_composite_protlayer_to_chain_epilogue;
        }

        memset(curr_algo_param, 0, sizeof(curr_algo_param));

        p++;
    }

add_composite_protlayer_to_chain_epilogue:

    if (chain != NULL && encoder != NULL) {
        // INFO(Rafael): Until now the encoding will not be layered.
        chain->head->encoder = encoder;
    }

    memset(curr_algo_param, 0, sizeof(curr_algo_param));
    curr_algo_param_size = 0;

    kryptos_freeseg(*key, *key_size);
    *key = NULL;
    *key_size = 0;

    return chain;
}

blackcat_protlayer_chain_ctx *add_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                     const char *algo_params, const size_t algo_params_size,
                                                     kryptos_u8_t **key, size_t *key_size,
                                                     struct blackcat_keychain_handle_ctx *handle) {
    blackcat_protlayer_chain_ctx *hp, *cp;
    char err_mesg[1024];

    if (handle == NULL) {
        return chain;
    }

    hp = cp = chain;

    if (hp != NULL) {
        cp = (hp->tail == NULL) ? get_protlayer_chain_tail(hp) : hp->tail;
        new_blackcat_protlayer_chain_ctx(cp->next);
        if (cp->next == NULL) {
            fprintf(stderr, "ERROR: Not enough memory to add protection layer to chain.\n");
            goto add_protlayer_to_chain_epilogue;
        }
        cp->next->last = cp;
        cp = cp->next;
        hp->tail = cp;
    } else {
        new_blackcat_protlayer_chain_ctx(hp);
        hp->head = hp->tail = cp = hp;
        if (hp == NULL) {
            fprintf(stderr, "ERROR: Not enough memory to add protection layer to chain.\n");
            goto add_protlayer_to_chain_epilogue;
        }
    }

    memset(err_mesg, 0, sizeof(err_mesg));

    if (blackcat_set_keychain(&cp, algo_params, algo_params_size,
                              key, key_size, BLACKCAT_PROTLAYER_EXTRA_ARGS_NR, handle, err_mesg) == 0) {
        fprintf(stderr, "%s", err_mesg);
        del_protlayer_chain_ctx(hp);
        hp = NULL;
    }

add_protlayer_to_chain_epilogue:

    return hp;
}

void del_protlayer_chain_ctx(blackcat_protlayer_chain_ctx *chain) {
    blackcat_protlayer_chain_ctx *t, *p;
    size_t a;

    for (t = p = chain; t != NULL; p = t) {
        t = p->next;

        if (p->key != NULL) {
            kryptos_freeseg(p->key, p->key_size);
            p->key_size = 0;
        }

        for (a = 0; a < p->argc; a++) {
            kryptos_freeseg(p->arg[a], 0);
        }

        kryptos_freeseg(p, sizeof(blackcat_protlayer_chain_ctx));
    }
}

static blackcat_protlayer_chain_ctx *get_protlayer_chain_tail(blackcat_protlayer_chain_ctx *chain) {
    blackcat_protlayer_chain_ctx *c;

    if (chain == NULL) {
        return NULL;
    }

    for (c = chain; c->next != NULL; c = c->next)
        ;

    return c;
}
