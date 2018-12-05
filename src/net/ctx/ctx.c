/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <net/ctx/ctx.h>
#include <ctx/ctx.h>
#include <kryptos.h>
#include <string.h>

#define new_bnt_channel_rule_ctx(r) {\
    (r) = (bnt_channel_rule_ctx *) kryptos_newseg(sizeof(bnt_channel_rule_ctx));\
    memset(&(r)->assertion, 0, sizeof(struct bnt_channel_rule_assertion));\
    (r)->head = (r)->tail = (r)->next = (r)->last = NULL;\
    (r)->pchain = NULL;\
}

#define new_bnt_keychunk_ctx(k) {\
    (k) = (bnt_keychunk_ctx *) kryptos_newseg(sizeof(bnt_keychunk_ctx));\
    (k)->data = NULL;\
    (k)->data_size = 0;\
    (k)->next = (k)->tail = NULL;\
}

#define new_bnt_keychain_ctx(k) {\
    (k) = (bnt_keychain_ctx *) kryptos_newseg(sizeof(bnt_keychain_ctx));\
    (k)->tail = (k)->next = (k)->last = NULL;\
    k->key = NULL;\
}

struct bnt_keyset_priv_ctx {
    kryptos_u64_t seqno;
    kryptos_u64_t max_seqno_delta;
    kryptos_hash_func h;
    kryptos_hash_size_func h_input_size;
    kryptos_hash_size_func h_size;
    kryptos_mp_value_t *xchgd_key;
    kryptos_u8_t *send_seed;
    size_t send_seed_size;
    kryptos_u8_t *recv_seed;
    size_t recv_seed_size;
};

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

bnt_keychunk_ctx *add_bnt_keychunk(bnt_keychunk_ctx *kchunk, const kryptos_u8_t *data, const size_t data_size) {
    bnt_keychunk_ctx *hp, *cp;

    if (kchunk == NULL) {
        new_bnt_keychunk_ctx(kchunk);
        hp = cp = kchunk->tail = kchunk;
    } else {
        new_bnt_keychunk_ctx(kchunk->tail->next);
        kchunk->tail = kchunk->tail->next;
        hp = kchunk;
        cp = kchunk->tail;
    }

    cp->data = (kryptos_u8_t *) kryptos_newseg(data_size);
    cp->data_size = data_size;
    memcpy(cp->data, data, data_size);

    return hp;
}

bnt_keychain_ctx *add_bnt_keychain(bnt_keychain_ctx *kchain, const kryptos_u64_t seqno) {

    if (get_bnt_keychain(seqno, kchain) != NULL) {
        return kchain;
    }

    if (kchain == NULL) {
        new_bnt_keychain_ctx(kchain);
        kchain->seqno = seqno;
        kchain->tail = kchain;
    } else {
        new_bnt_keychain_ctx(kchain->tail->next);
        kchain->tail->next->last = kchain->tail;
        kchain->tail = kchain->tail->next;
        kchain->tail->seqno = seqno;
    }
    return kchain;
}

bnt_keychain_ctx *del_bnt_keychain_seqno(bnt_keychain_ctx *kchain, const kryptos_u64_t seqno) {
    bnt_keychain_ctx *t;

    if ((t = get_bnt_keychain(seqno, kchain)) != NULL) {
        if (t == kchain) {
            if (kchain->next != NULL) {
                kchain->next->tail = kchain->tail;
            }
            kchain = kchain->next;
        } else if (t == kchain->tail) {
            kchain->tail = t->last;
            t->last->next = t->next;
        } else {
            t->last->next = t->next;
            t->next->last = t->last;
        }

        t->next = NULL;

        del_bnt_keychain(t);
    }

    return kchain;
}

void del_bnt_keychunk(bnt_keychunk_ctx *keychunk) {
    bnt_keychunk_ctx *t, *p;
    for (t = p = keychunk; t != NULL; p = t) {
        t = p->next;
        if (p->data != NULL) {
            kryptos_freeseg(p->data, p->data_size);
        }
        free(p);
    }
}

void del_bnt_keychain(bnt_keychain_ctx *keychain) {
    bnt_keychain_ctx *t, *p;
    for (t = p = keychain; t != NULL; p = t) {
        t = p->next;
        if (p->key != NULL) {
            del_bnt_keychunk(p->key);
        }
        free(p);
    }
}

bnt_keychain_ctx *get_bnt_keychain(const kryptos_u64_t seqno, bnt_keychain_ctx *kchain) {
    bnt_keychain_ctx *kcp;

    if (kchain == NULL) {
        return NULL;
    }

    for (kcp = kchain; kcp != NULL; kcp = kcp->next) {
        if (kcp->seqno == seqno) {
            return kcp;
        }
    }

    return NULL;
}

int init_bnt_keyset(bnt_keyset_ctx **keyset, const blackcat_protlayer_chain_ctx *pchain,
                    const kryptos_u64_t max_seqno_delta, kryptos_hash_func h, kryptos_hash_size_func h_input_size,
                    kryptos_hash_size_func h_size, kryptos_mp_value_t *xchgd_key,
                    const kryptos_u8_t *send_seed, const size_t send_seed_size,
                    const kryptos_u8_t *recv_seed, const size_t recv_seed_size) {
    bnt_keyset_ctx *ksp;
    const blackcat_protlayer_chain_ctx *p;
    const kryptos_u8_t *sp, *sp_end;
    kryptos_u8_t *kp, *kp_end;

    if (keyset == NULL || *keyset == NULL) {
        return 0;
    }

    ksp = *keyset;

    ksp->priv = (struct bnt_keyset_priv_ctx *) kryptos_newseg(sizeof(struct bnt_keyset_priv_ctx));

    if (ksp->priv == NULL) {
        return 0;
    }

    ksp->priv->seqno = 0;
    ksp->priv->max_seqno_delta = max_seqno_delta;
    ksp->priv->h = h;
    ksp->priv->h_input_size = h_input_size;
    ksp->priv->h_size = h_size;
    ksp->send_seqno = 0;

    if (xchgd_key != NULL) {
        ksp->priv->xchgd_key = kryptos_assign_mp_value(&ksp->priv->xchgd_key, xchgd_key);
    } else {
        ksp->priv->xchgd_key = NULL;
    }

    ksp->priv->send_seed = ksp->priv->recv_seed = NULL;
    ksp->priv->send_seed_size = ksp->priv->recv_seed_size = 0;
    ksp->send_chain = ksp->recv_chain = NULL;

    ksp->priv->send_seed = (kryptos_u8_t *) kryptos_newseg(send_seed_size);

    if (ksp->priv->send_seed == NULL) {
        deinit_bnt_keyset(ksp);
        return 0;
    }

    ksp->priv->send_seed_size = send_seed_size;
    memcpy(ksp->priv->send_seed, send_seed, send_seed_size);

    ksp->priv->recv_seed = (kryptos_u8_t *) kryptos_newseg(recv_seed_size);

    if (ksp->priv->recv_seed == NULL) {
        deinit_bnt_keyset(ksp);
        return 0;
    }

    ksp->priv->recv_seed_size = recv_seed_size;
    memcpy(ksp->priv->recv_seed, recv_seed, recv_seed_size);

    // TODO(Rafael): Encontrar melhor forma de dissociar as duas chains. Talvez um send e um recv nonce.

    ksp->send_chain = add_bnt_keychain(ksp->send_chain, 0);
    sp_end = ksp->priv->send_seed + ksp->priv->send_seed_size;

    for (p = pchain; p != NULL; p = p->next) {
        kp = p->key;
        kp_end = kp + p->key_size;
        sp = ksp->priv->send_seed;

        while (kp != kp_end) {
            *kp = *kp ^ *sp;
            kp++;
            sp++;
            if (sp == sp_end) {
                sp = ksp->priv->send_seed;
            }
        }

        ksp->send_chain->key = add_bnt_keychunk(ksp->send_chain->key, p->key, p->key_size);

        kp = p->key;
        sp = ksp->priv->send_seed;

        while (kp != kp_end) {
            *kp = *kp ^ *sp;
            kp++;
            sp++;
            if (sp == sp_end) {
                sp = ksp->priv->send_seed;
            }
        }
    }

    ksp->recv_chain = add_bnt_keychain(ksp->recv_chain, 0);
    sp_end = ksp->priv->recv_seed + ksp->priv->recv_seed_size;

    for (p = pchain; p != NULL; p = p->next) {
        kp = p->key;
        kp_end = kp + p->key_size;
        sp = ksp->priv->recv_seed;

        while (kp != kp_end) {
            *kp = *kp ^ *sp;
            kp++;
            sp++;
            if (sp == sp_end) {
                sp = ksp->priv->recv_seed;
            }
        }

        ksp->recv_chain->key = add_bnt_keychunk(ksp->recv_chain->key, p->key, p->key_size);

        kp = p->key;
        sp = ksp->priv->recv_seed;

        while (kp != kp_end) {
            *kp = *kp ^ *sp;
            kp++;
            sp++;
            if (sp == sp_end) {
                sp = ksp->priv->recv_seed;
            }
        }
    }

    return 1;
}

void deinit_bnt_keyset(bnt_keyset_ctx *keyset) {
    if (keyset == NULL) {
        return;
    }

    if (keyset->send_chain != NULL) {
        del_bnt_keychain(keyset->send_chain);
    }

    if (keyset->send_chain != NULL) {
        del_bnt_keychain(keyset->recv_chain);
    }

    if (keyset->priv->xchgd_key != NULL) {
        kryptos_del_mp_value(keyset->priv->xchgd_key);
    }

    if (keyset->priv->send_seed != NULL) {
        kryptos_freeseg(keyset->priv->send_seed, keyset->priv->send_seed_size);
        keyset->priv->send_seed = NULL;
        keyset->priv->send_seed_size = 0;
    }

    if (keyset->priv->recv_seed != NULL) {
        kryptos_freeseg(keyset->priv->recv_seed, keyset->priv->recv_seed_size);
        keyset->priv->recv_seed = NULL;
        keyset->priv->recv_seed_size = 0;
    }

    if (keyset->priv != NULL) {
        memset(keyset->priv, 0, sizeof(struct bnt_keyset_priv_ctx));
        free(keyset->priv);
        keyset->priv = NULL;
    }

}

int step_bnt_keyset(bnt_keyset_ctx **keyset, const kryptos_u64_t intended_seqno) {
    bnt_keyset_ctx *ksp;
    kryptos_u8_t *key;
    bnt_keychunk_ctx *kcp;

    if (keyset == NULL || *keyset == NULL ||
        (*keyset)->send_chain == NULL || (*keyset)->recv_chain == NULL ||
        intended_seqno <= (*keyset)->priv->seqno ||
        abs(intended_seqno - (*keyset)->priv->seqno) > (*keyset)->priv->max_seqno_delta) {
        return 0;
    }

    ksp = *keyset;

    while (ksp->priv->seqno < intended_seqno) {
        ksp->priv->seqno++;

        ksp->send_chain = add_bnt_keychain(ksp->send_chain, ksp->priv->seqno);

        for (kcp = ksp->send_chain->tail->last->key; kcp != NULL; kcp = kcp->next) {
            key = kryptos_do_hkdf(kcp->data,
                                  kcp->data_size,
                                  ksp->priv->h,
                                  ksp->priv->h_input_size,
                                  ksp->priv->h_size,
                                  NULL, 0,
                                  NULL, 0,
                                  kcp->data_size);
            if (key == NULL) {
                fprintf(stderr, "ERROR: KDF returned a NULL okm.\n");
                return 0;
            }

            ksp->send_chain->tail->key = add_bnt_keychunk(ksp->send_chain->tail->key, key, kcp->data_size);
            kryptos_freeseg(key, kcp->data_size);
        }

        ksp->recv_chain = add_bnt_keychain(ksp->recv_chain, ksp->priv->seqno);

        for (kcp = ksp->recv_chain->tail->last->key; kcp != NULL; kcp = kcp->next) {
            key = kryptos_do_hkdf(kcp->data,
                                  kcp->data_size,
                                  ksp->priv->h,
                                  ksp->priv->h_input_size,
                                  ksp->priv->h_size,
                                  NULL, 0,
                                  NULL, 0,
                                  kcp->data_size);

            if (key == NULL) {
                fprintf(stderr, "ERROR: KDF returned a NULL okm.\n");
                return 0;
            }

            ksp->recv_chain->tail->key = add_bnt_keychunk(ksp->recv_chain->tail->key, key, kcp->data_size);
            kryptos_freeseg(key, kcp->data_size);
        }
    }

    return 1;
}

int set_protlayer_key_by_keychain_seqno(const kryptos_u64_t seqno,
                                       blackcat_protlayer_chain_ctx *pchain, bnt_keychain_ctx **keychain) {
    bnt_keychain_ctx *kcp;
    bnt_keychunk_ctx *kp;
    blackcat_protlayer_chain_ctx *p;

    if (keychain == NULL || (kcp = get_bnt_keychain(seqno, *keychain)) == NULL) {
        return 0;
    }

    for (kp = kcp->key, p = pchain; kp != NULL && p != NULL; kp = kp->next, p = p->next) {
        memcpy(p->key, kp->data, kp->data_size);
    }

    (*keychain) = del_bnt_keychain_seqno(*keychain, seqno);

    return 1;
}

#undef new_bnt_channel_rule_ctx

#undef new_bnt_keychunk_ctx

#undef new_bnt_keychain_ctx
