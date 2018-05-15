/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <ctx/ctx.h>
#include <basedefs/defs.h>
#include <memory/memory.h>
#include <keychain/keychain.h>

#define new_blackcat_protlayer_chain_ctx(b) {\
    (b) = (blackcat_protlayer_chain_ctx *) blackcat_getseg(sizeof(blackcat_protlayer_chain_ctx));\
    (b)->head = (b)->tail = (b)->next = (b)->last = NULL;\
    (b)->key = NULL;\
    (b)->key_size = 0;\
    (b)->processor = NULL;\
    (b)->argc = 0;\
}

static blackcat_protlayer_chain_ctx *get_protlayer_chain_tail(blackcat_protlayer_chain_ctx *chain);

blackcat_protlayer_chain_ctx *add_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                     const char *algo_params, const kryptos_u8_t *key, const size_t key_size) {
    blackcat_protlayer_chain_ctx *hp, *cp;

    hp = cp = chain;

    if (hp != NULL) {
        cp = get_protlayer_chain_tail(hp);
        new_blackcat_protlayer_chain_ctx(cp->next);
        cp->next->last = cp;
        cp = cp->next;
        hp->tail = cp;
    } else {
        new_blackcat_protlayer_chain_ctx(hp);
        hp->head = hp->tail = cp = hp;
    }

    blackcat_set_keychain(&cp, algo_params, key, key_size);

    return hp;
}

void del_protlayer_chain_ctx(blackcat_protlayer_chain_ctx *chain) {
    blackcat_protlayer_chain_ctx *t, *p;

    for (t = p = chain; t; p = t) {
        t = p->next;

        if (p->key != NULL) {
            blackcat_free(p->key, &p->key_size);
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
