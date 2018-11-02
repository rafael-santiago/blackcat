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
#include <kryptos.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#define BCNETDB_HMAC_SCHEME "BCNETDB HMAC SCHEME"

#define BCNETDB_DATA "BCNETDB DATA"

static kryptos_u8_t *g_netdb_buffer = NULL;

static size_t g_netdb_buffer_size = 0;

static const struct blackcat_hmac_catalog_algorithms_ctx *g_hmac = NULL;

static int netdb_write(const char *buf, const size_t buf_size, const kryptos_u8_t *key, const size_t key_size);

static int netdb_buffer_handler(const kryptos_u8_t *key, const size_t key_size, const kryptos_action_t action);

#define netdb_decrypt_buffer(k, ks) netdb_buffer_handler((k), (ks), kKryptosDecrypt)

#define netdb_encrypt_buffer(k, ks) netdb_buffer_handler((k), (ks), kKryptosEncrypt)

static int netdb_flush_data(const kryptos_u8_t *data, const size_t data_size);

int blackcat_netdb_add(const char *rule_id,
                       const char *rule_type,
                       const char *hash,
                       const char *target,
                       const char *pchain,
                       const char *encoder,
                       char *error,
                       const kryptos_u8_t *key,
                       const size_t key_size) {
    kryptos_u8_t *temp_key;
    size_t temp_key_size;
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

    if ((temp_key = (kryptos_u8_t *) kryptos_newseg(8)) == NULL) {
        sprintf(error, "ERROR: no memory!\n");
        err = ENOMEM;
        goto blackcat_netdb_add_epilogue;
    }

    temp_key_size = 8;

    p_layer = add_composite_protlayer_to_chain(p_layer,
                                               pchain, &temp_key, &temp_key_size,
                                               get_hash_processor(hash), get_encoder(encoder));

    if (temp_key != NULL) {
        kryptos_freeseg(temp_key, temp_key_size);
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

    if ((err = netdb_write(buf, buf_size, key, key_size)) != 0) {
        sprintf(error, "ERROR: while writing rule to database.\n");
    }

    kryptos_freeseg(buf, buf_size);

blackcat_netdb_add_epilogue:

    return err;
}

static int netdb_flush_data(const kryptos_u8_t *data, const size_t data_size) {
    if (g_hmac == NULL) {
        return EFAULT;
    }

    if (g_netdb_buffer != NULL) {
        kryptos_freeseg(g_netdb_buffer, g_netdb_buffer_size);
        g_netdb_buffer = NULL;
    }

    g_netdb_buffer_size = 0;

    if (kryptos_pem_put_data(&g_netdb_buffer, &g_netdb_buffer_size,
                             BCNETDB_HMAC_SCHEME, g_hmac->name, strlen(g_hmac->name)) != kKryptosSuccess) {
        return EFAULT;
    }

    if (kryptos_pem_put_data(&g_netdb_buffer, &g_netdb_buffer_size,
                             BCNETDB_DATA, data, data_size) != kKryptosSuccess) {
        return EFAULT;
    }

    return 0;
}

static int netdb_write(const char *buf, const size_t buf_size, const kryptos_u8_t *key, const size_t key_size) {
    int err = EFAULT;
    kryptos_u8_t *data = NULL;
    size_t data_size = 0;
    kryptos_u8_t *old_netdb_buffer = NULL;
    size_t old_netdb_buffer_size = 0;

    if ((err = netdb_decrypt_buffer(key, key_size)) == 0) {

        if ((data = kryptos_pem_get_data(BCNETDB_DATA, g_netdb_buffer, g_netdb_buffer_size, &data_size)) == NULL) {
            goto netdb_write_epilogue;
        }

        if ((data = kryptos_realloc(data, data_size + buf_size)) == NULL) {
            err = ENOMEM;
            goto netdb_write_epilogue;
        }

        memcpy(data + data_size, buf, buf_size);
        data_size += buf_size;

        if ((err = netdb_flush_data(data, data_size)) == 0) {
            err = netdb_encrypt_buffer(key, key_size);
        }
    }

netdb_write_epilogue:

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
        data = NULL;
        data_size = 0;
    }

    return err;
}

static int netdb_buffer_handler(const kryptos_u8_t *key, const size_t key_size, const kryptos_action_t action) {
    kryptos_task_ctx t, *ktask = &t;
    blackcat_protlayer_chain_ctx p_layer;
    int err = EFAULT;

    memset(&p_layer, 0, sizeof(blackcat_protlayer_chain_ctx));

    if (g_netdb_buffer == NULL) {
        goto netdb_write_epilogue;
    }

    p_layer.key_size = get_hmac_key_size(g_hmac->processor);
    p_layer.key = kryptos_hkdf((kryptos_u8_t *)key, key_size, sha3_512, "", 0, "", 0, p_layer.key_size);

    if (p_layer.key == NULL) {
        goto netdb_write_epilogue;
    }

    p_layer.mode = g_hmac->mode;

    ktask->in = kryptos_pem_get_data(BCNETDB_DATA, g_netdb_buffer, g_netdb_buffer_size, &ktask->in_size);
    ktask->action = action;

    g_hmac->processor(&ktask, &p_layer);

    if (!kryptos_last_task_succeed(ktask)) {
        goto netdb_write_epilogue;
    }

    g_netdb_buffer = ktask->out;
    g_netdb_buffer_size = ktask->out_size;

    if (action == kKryptosDecrypt) {
        g_hmac = get_random_hmac_catalog_scheme();
    }

    err = netdb_flush_data(ktask->out, ktask->out_size);

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);

netdb_write_epilogue:

    if (p_layer.key != NULL) {
        kryptos_freeseg(p_layer.key, p_layer.key_size);
    }

    kryptos_task_init_as_null(ktask);

    return err;
}

int blackcat_netdb_drop(const char *rule_id, const kryptos_u8_t *key, const size_t key_size) {
    int err = EFAULT;
    kryptos_u8_t *entry_head = NULL, *entry_tail = NULL, *end, *newdb = NULL;
    size_t data_size = 0, newdb_size;
    char needle[1024];

    if ((err = netdb_decrypt_buffer(key, key_size)) == 0) {
        sprintf(needle, "%s: ", rule_id);

        if ((entry_head = strstr(g_netdb_buffer, needle)) != NULL) {
            end = g_netdb_buffer + g_netdb_buffer_size;
            entry_tail = entry_head;
            while (entry_tail != end && *entry_tail != '\n') {
                entry_tail++;
            }

            newdb_size = g_netdb_buffer_size - (entry_tail - entry_head);
            newdb = (kryptos_u8_t *) kryptos_newseg(newdb_size + 1);
            if (newdb == NULL) {
                err = ENOMEM;
                goto blackcat_netdb_drop_epilogue;
            }

            memset(newdb, 0, newdb_size + 1);
            memcpy(newdb, g_netdb_buffer, entry_head - g_netdb_buffer);
            memcpy(newdb + (entry_head - g_netdb_buffer), entry_tail + 1, end - entry_tail + 1);

            kryptos_freeseg(g_netdb_buffer, g_netdb_buffer_size);
            g_netdb_buffer = newdb;
            g_netdb_buffer_size = newdb_size;

            err = netdb_encrypt_buffer(key, key_size);
        }
    } else {
        err = ENOENT;
    }

blackcat_netdb_drop_epilogue:

    return err;
}

int blackcat_netdb_load(const char *filepath) {
    FILE *db = NULL;
    kryptos_u8_t *hmac_scheme = NULL;
    size_t hmac_scheme_size = 0;

    blackcat_netdb_unload();

    if ((db = fopen(filepath, "r")) == NULL) {
        return ENOENT;
    }

    fseek(db, 0L, SEEK_END);
    g_netdb_buffer_size = ftell(db);
    fseek(db, 0L, SEEK_SET);

    if ((g_netdb_buffer = (kryptos_u8_t *) kryptos_newseg(g_netdb_buffer_size + 1)) == NULL) {
        return ENOMEM;
    }

    memset(g_netdb_buffer, 0, g_netdb_buffer_size + 1);

    fread(g_netdb_buffer, g_netdb_buffer_size, sizeof(kryptos_u8_t), db);

    fclose(db);

    hmac_scheme = kryptos_pem_get_data(BCNETDB_HMAC_SCHEME, g_netdb_buffer, g_netdb_buffer_size, &hmac_scheme_size);

    if (g_hmac == NULL) {
        return EFAULT;
    }

    g_hmac = get_hmac_catalog_scheme(hmac_scheme);

    kryptos_freeseg(hmac_scheme, hmac_scheme_size);

    return 0;
}

int blackcat_netdb_unload(void) {
    if (g_netdb_buffer != NULL) {
        kryptos_freeseg(g_netdb_buffer, g_netdb_buffer_size);
    }

    g_netdb_buffer = NULL;
    g_netdb_buffer_size = 0;
    g_hmac = NULL;

    return 0;
}

bnt_channel_rule_ctx *blackcat_netdb_select(const char *rule_id, const kryptos_u8_t *key, const size_t key_size) {
    return NULL;
}

#undef BCNETDB_HMAC_SCHEME

#undef BCNETDB_DATA

#undef netdb_decrypt_buffer

#undef netdb_encrypt_buffer
