/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <ctx/ctx.h>
#include <basedefs/defs.h>
#include <memory/memory.h>
#include <keychain/keychain.h>
#include <kryptos_memory.h>
#include <string.h>
#include <stdio.h>

#define new_blackcat_protlayer_chain_ctx(b) {\
    (b) = (blackcat_protlayer_chain_ctx *) blackcat_getseg(sizeof(blackcat_protlayer_chain_ctx));\
    (b)->head = (b)->tail = (b)->next = (b)->last = NULL;\
    (b)->key = NULL;\
    (b)->key_size = 0;\
    (b)->processor = NULL;\
    (b)->argc = 0;\
    (b)->is_hmac = 0;\
}

static blackcat_protlayer_chain_ctx *get_protlayer_chain_tail(blackcat_protlayer_chain_ctx *chain);

blackcat_protlayer_chain_ctx *add_composite_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                               const char *piped_ciphers, kryptos_u8_t **key,
                                                               size_t *key_size, blackcat_hash_processor hash) {
    char curr_algo_param[100];
    const char *p, *p_end, *cp;

    if (piped_ciphers == NULL || key == NULL || key_size == NULL || hash == NULL) {
        return chain;
    }

    p = piped_ciphers;
    p_end = p + strlen(piped_ciphers);

    memset(curr_algo_param, 0, sizeof(curr_algo_param));

    while (p < p_end) {
        while (p != p_end && (*p == ' ' || *p == '\t' || *p == '\n')) {
            p++;
        }

        cp = p;

        while (p != p_end && *p != '|') {
            p++;
        }

        if ((p - cp) > sizeof(curr_algo_param)) {
            fprintf(stderr, "ERROR: Unable to process the current algo param. Aborted.\n");
            return NULL;
        }

        memcpy(curr_algo_param, cp, p - cp);

        chain = add_protlayer_to_chain(chain, curr_algo_param, key, key_size, hash);
        memset(curr_algo_param, 0, sizeof(curr_algo_param));

        p++;
    }

    kryptos_freeseg(*key);
    *key = NULL;
    *key_size = 0;

    return chain;
}

blackcat_protlayer_chain_ctx *add_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                     const char *algo_params, kryptos_u8_t **key, size_t *key_size,
                                                     blackcat_hash_processor hash) {
    blackcat_protlayer_chain_ctx *hp, *cp;
    char err_mesg[1024] = "";

    hp = cp = chain;

    if (hp != NULL) {
        cp = (hp->tail == NULL) ? get_protlayer_chain_tail(hp) : hp->tail;
        new_blackcat_protlayer_chain_ctx(cp->next);
        cp->next->last = cp;
        cp = cp->next;
        hp->tail = cp;
    } else {
        new_blackcat_protlayer_chain_ctx(hp);
        hp->head = hp->tail = cp = hp;
    }

    if (blackcat_set_keychain(&cp, algo_params, key, key_size, BLACKCAT_PROTLAYER_EXTRA_ARGS_NR, hash, err_mesg) == 0) {
        fprintf(stderr, "%s", err_mesg);
        del_protlayer_chain_ctx(hp);
        hp = NULL;
    }

    return hp;
}

void del_protlayer_chain_ctx(blackcat_protlayer_chain_ctx *chain) {
    blackcat_protlayer_chain_ctx *t, *p;
    size_t a;

    for (t = p = chain; t != NULL; p = t) {
        t = p->next;

        if (p->key != NULL) {
            blackcat_free(p->key, &p->key_size);
        }

        for (a = 0; a < p->argc; a++) {
            free(p->arg[a]);
        }

        free(p);
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
