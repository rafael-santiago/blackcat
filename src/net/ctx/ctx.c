/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <net/ctx/ctx.h>
#include <ctx/ctx.h>
#include <kryptos_memory.h>
#include <string.h>

#define new_bnt_channel_rule_ctx(r) {\
    (r) = (bnt_channel_rule_ctx *) kryptos_newseg(sizeof(bnt_channel_rule_ctx));\
    memset(&(r)->assertion, 0, sizeof(struct bnt_channel_rule_assertion));\
    (r)->head = (r)->tail = (r)->next = (r)->last = NULL;\
    (r)->pchain = NULL;\
}

static bnt_channel_rule_ctx *get_bnt_channel_rule_tail(bnt_channel_rule_ctx *rules);

bnt_channel_rule_ctx *add_bnt_channel_rule(bnt_channel_rule_ctx *rules,
                                           const char *ruleid,
                                           const struct bnt_channel_rule_assertion assertion,
                                           const char *protection_layer,
                                           kryptos_u8_t **key,
                                           size_t *key_size,
                                           blackcat_hash_processor hash,
                                           blackcat_encoder encoder) {
    bnt_channel_rule_ctx *hp, *cp;

    if (ruleid == NULL || protection_layer == NULL) {
        return rules;
    }

    if (rules == NULL) {
        new_bnt_channel_rule_ctx(rules);
        hp = cp = rules;
    } else {
        hp = rules;
        cp = rules->tail;
        new_bnt_channel_rule_ctx(cp->next);
        cp->next->last = cp;
        cp = cp->next;
    }

    rules->tail = cp;

    cp->ruleid_size = strlen(ruleid);
    cp->ruleid = (char *) kryptos_newseg(cp->ruleid_size + 1);

    if (cp->ruleid == NULL) {
        printf("ERROR: No memory!\n");
        return NULL;
    }

    memset(cp->ruleid, 0, cp->ruleid_size + 1);
    memcpy(cp->ruleid, ruleid, cp->ruleid_size);
    memcpy(&cp->assertion, &assertion, sizeof(struct bnt_channel_rule_assertion));

    cp->pchain = add_composite_protlayer_to_chain(cp->pchain,
                                                  protection_layer, key, key_size, hash, encoder);

    return hp;
}

bnt_channel_rule_ctx *del_bnt_channel_rule(bnt_channel_rule_ctx *rules, const char *ruleid) {
    bnt_channel_rule_ctx *tp, *hp;

    if ((tp = get_bnt_channel_rule(ruleid, rules)) == NULL) {
        return rules;
    }

    if (tp == rules) {
        hp = tp->next;
        if (hp != NULL) {
            hp->head = hp;
        }
    } else {
        hp = rules;
        tp->last->next = tp->next;
        tp->next->last = tp->last;
    }

    if (hp != NULL && hp->tail == tp) {
        hp->tail = tp->last;
    }

    tp->next = NULL;

    del_bnt_channel_rule_ctx(tp);

    return hp;
}

bnt_channel_rule_ctx *get_bnt_channel_rule(const char *ruleid, bnt_channel_rule_ctx *rules) {
    bnt_channel_rule_ctx *rp;

    if (ruleid == NULL) {
        return NULL;
    }

    for (rp = rules; rp != NULL; rp = rp->next) {
        if (strcmp(rp->ruleid, ruleid) == 0) {
            return rp;
        }
    }

    return NULL;
}

void del_bnt_channel_rule_ctx(bnt_channel_rule_ctx *rules) {
    bnt_channel_rule_ctx *t, *p;

    for (t = p = rules; t; p = t) {
        t = p->next;

        if (p->ruleid != NULL) {
            kryptos_freeseg(p->ruleid, p->ruleid_size);
        }

        memset(&p->assertion, 0, sizeof(p->assertion));

        del_protlayer_chain_ctx(p->pchain);

        free(p);
    }
}

#undef new_bnt_channel_rule_ctx
