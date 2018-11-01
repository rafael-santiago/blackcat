/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <net/db/db.h>
#include <net/ctx/ctx.h>
#include <keychain/ciphering_schemes.h>
#include <ctx/ctx.h>
#include <kryptos_memory.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

static kryptos_u8_t *g_net_db_buffer = NULL;

static size_t *g_net_db_buffer_size = 0;

static int netdb_write(const char *buf, const size_t buf_size);

int blackcat_netdb_add(const char *rule_id,
                       const char *rule_type,
                       const char *hash,
                       const char *target,
                       const char *pchain,
                       const char *encoder,
                       char *error) {
    kryptos_u8_t *key;
    size_t key_size;
    blackcat_protlayer_chain_ctx *p_layer = NULL;
    char *buf;
    size_t buf_size;
    int err = EINVAL;

    if (rule_id == NULL || rule_type == NULL || hash == NULL || pchain == NULL || error == NULL) {
        goto blackcat_netdb_add_epilogue;
    }

    if (strcmp(rule_type, "socket") != 0 &&
        strcmp(rule_type, "af_inet") != 0 &&
        strcmp(rule_type, "af_inet6") != 0) {
        sprintf(error, "ERROR: invalid rule type : '%s'.\n", rule_type);
        goto blackcat_netdb_add_epilogue;
    }

    if (strcmp(rule_type, "socket") != 0 && target == NULL) {
        sprintf(error, "ERROR: target cannot be null.\n");
        goto blackcat_netdb_add_epilogue;
    } else if (strcmp(rule_type, "socket") == 0 && target != NULL) {
        sprintf(error, "ERROR: target must be null.\n");
        goto blackcat_netdb_add_epilogue;
    } else {
        // TODO(Rafael): Verify target buffer.
    }

    if (get_hash_processor(hash) == NULL) {
        sprintf(error, "ERROR: unknown hash algorithm : '%s'.\n", hash);
        goto blackcat_netdb_add_epilogue;
    }

    if (encoder != NULL && get_encoder(encoder) == NULL) {
        sprintf(error, "ERROR: unknown encoding algorithm : '%s'.\n", encoder);
        goto blackcat_netdb_add_epilogue;
    }

    if ((key = (kryptos_u8_t *) kryptos_newseg(8)) == NULL) {
        sprintf(error, "ERROR: no memory!\n");
        err = ENOMEM;
        goto blackcat_netdb_add_epilogue;
    }

    key_size = 8;

    p_layer = add_composite_protlayer_to_chain(p_layer,
                                               pchain, &key, &key_size, get_hash_processor(hash), get_encoder(encoder));

    if (key != NULL) {
        kryptos_freeseg(key, key_size);
    }

    if (p_layer == NULL) {
        sprintf(error, "ERROR: invalid protection layer : '%s'\n", pchain);
        goto blackcat_netdb_add_epilogue;
    }

    del_protlayer_chain_ctx(p_layer);

    buf_size = strlen(rule_id) + strlen(rule_type) + strlen(hash) + strlen(pchain) + 100;

    if (target != NULL) {
        buf_size += strlen(target);
    }

    if (encoder != NULL) {
        buf_size += strlen(encoder);
    }

    buf = (char *) kryptos_newseg(buf_size);
    memset(buf, 0, buf_size);

    if (target == NULL) {
        sprintf(buf, "%s: %s %s %s %s\n", rule_id, rule_type, hash, pchain, (encoder != NULL) ? encoder : "");
    } else {
        sprintf(buf, "%s: %s %s %s %s %s\n", rule_id, rule_type, hash, target, pchain, (encoder != NULL) ? encoder : "");
    }

    buf_size = strlen(buf);

    if ((err = netdb_write(buf, buf_size)) != 0) {
        sprintf(error, "ERROR: while writing rule to database.\n");
    }

    kryptos_freeseg(buf, buf_size);

blackcat_netdb_add_epilogue:

    return err;
}

static int netdb_write(const char *buf, const size_t buf_size) {
    return 1;
}

int blackcat_netdb_drop(const char *rule_id) {
    return 1;
}

int blackcat_netdb_load(const char *filepath) {
    return 1;
}

int blackcat_netdb_unload(const char *filepath) {
    return 1;
}

bnt_channel_rule_ctx *blackcat_netdb_select(const char *rule_id) {
    return NULL;
}
