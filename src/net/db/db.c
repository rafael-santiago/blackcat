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
#include <sys/file.h>

#define BCNETDB_HMAC_SCHEME "BCNETDB HMAC SCHEME"

#define BCNETDB_DATA "BCNETDB DATA"

struct netdb_ctx {
    kryptos_u8_t filepath[4096];
    FILE *db;
    kryptos_u8_t *buf;
    size_t buf_size;
    // TODO(Rafael): Add a mutex here and lock the file.
};

static struct netdb_ctx g_netdb = { "", NULL, NULL, 0 };

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
    bnt_channel_rule_ctx *rule = NULL;

    if (rule_id == NULL || rule_type == NULL || hash == NULL || pchain == NULL || error == NULL || key == NULL) {
        goto blackcat_netdb_add_epilogue;
    }

    if ((temp_key = (kryptos_u8_t *) kryptos_newseg(8)) == NULL) {
        sprintf(error, "ERROR: no memory!\n");
        err = ENOMEM;
        goto blackcat_netdb_add_epilogue;
    }

    temp_key_size = 8;

    if ((rule = blackcat_netdb_select(rule_id, key, key_size, &temp_key, &temp_key_size)) != NULL) {
        sprintf(error, "ERROR: The rule '%s' already exists.\n", rule_id);
        goto blackcat_netdb_add_epilogue;
    }

    if (temp_key != NULL) {
        kryptos_freeseg(temp_key, temp_key_size);
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

    if (rule != NULL) {
        del_bnt_channel_rule_ctx(rule);
    }

    return err;
}

static int netdb_flush_data(const kryptos_u8_t *data, const size_t data_size) {
    if (g_hmac == NULL) {
        return EFAULT;
    }

    if (g_netdb.buf != NULL) {
        kryptos_freeseg(g_netdb.buf, g_netdb.buf_size);
        g_netdb.buf = NULL;
    }

    g_netdb.buf_size = 0;

    if (kryptos_pem_put_data(&g_netdb.buf, &g_netdb.buf_size,
                             BCNETDB_HMAC_SCHEME, g_hmac->name, strlen(g_hmac->name)) != kKryptosSuccess) {
        return EFAULT;
    }

    if (kryptos_pem_put_data(&g_netdb.buf, &g_netdb.buf_size,
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

    if (g_netdb.buf_size > 0) {
        if ((err = netdb_decrypt_buffer(key, key_size)) == 0) {

            if ((data = kryptos_pem_get_data(BCNETDB_DATA, g_netdb.buf, g_netdb.buf_size, &data_size)) == NULL) {
                goto netdb_write_epilogue;
            }

            if (*data == 0) {
                memset(data, 0, data_size);
                data_size = 0;
            }

            if ((data = kryptos_realloc(data, data_size + buf_size)) == NULL) {
                err = ENOMEM;
                goto netdb_write_epilogue;
            }

            memcpy(data + data_size, buf, buf_size);
            data_size += buf_size;
        }
    } else {
        if ((data = (kryptos_u8_t *) kryptos_newseg(buf_size + 1)) == NULL) {
            err = ENOMEM;
            goto netdb_write_epilogue;
        }
        memset(data, 0, buf_size + 1);
        memcpy(data, (kryptos_u8_t *)buf, buf_size);
        data_size = buf_size;
    }

    if ((err = netdb_flush_data(data, data_size)) == 0) {
        err = netdb_encrypt_buffer(key, key_size);
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
    FILE *db = NULL;

    kryptos_task_init_as_null(ktask);

    memset(&p_layer, 0, sizeof(blackcat_protlayer_chain_ctx));

    if (g_netdb.buf == NULL) {
        goto netdb_write_epilogue;
    }

    p_layer.key_size = get_hmac_key_size(g_hmac->processor);
    p_layer.key = kryptos_hkdf((kryptos_u8_t *)key, key_size, sha3_512, "", 0, "", 0, p_layer.key_size);

    if (p_layer.key == NULL) {
        goto netdb_write_epilogue;
    }

    p_layer.mode = g_hmac->mode;

    ktask->in = kryptos_pem_get_data(BCNETDB_DATA, g_netdb.buf, g_netdb.buf_size, &ktask->in_size);
    ktask->action = action;

    g_hmac->processor(&ktask, &p_layer);

    if (!kryptos_last_task_succeed(ktask)) {
        goto netdb_write_epilogue;
    }

    if (action == kKryptosDecrypt) {
        g_hmac = get_random_hmac_catalog_scheme();
    }

    if (netdb_flush_data(ktask->out, ktask->out_size) == 0) {
        if (action == kKryptosEncrypt) {
            if ((db = fopen(g_netdb.filepath, "w")) == NULL) {
                goto netdb_write_epilogue;
            }

            fprintf(db, "%s", g_netdb.buf);
        }

        err = 0;
    }

netdb_write_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);

    if (db != NULL) {
        fclose(db);
    }

    if (p_layer.key != NULL) {
        kryptos_freeseg(p_layer.key, p_layer.key_size);
    }

    kryptos_task_init_as_null(ktask);

    return err;
}

int blackcat_netdb_drop(const char *rule_id, const kryptos_u8_t *key, const size_t key_size) {
    int err = EFAULT;
    kryptos_u8_t *entry_head = NULL, *entry_tail = NULL, *end, *newdb = NULL, *temp;
    size_t data_size = 0, newdb_size, temp_size;
    char needle[1024];

    if ((err = netdb_decrypt_buffer(key, key_size)) == 0) {
        if (strlen(rule_id) > sizeof(needle) - 1) {
            err = EINVAL;
            goto blackcat_netdb_drop_epilogue;
        }

        sprintf(needle, "%s: ", rule_id);

        temp = kryptos_pem_get_data(BCNETDB_DATA, g_netdb.buf, g_netdb.buf_size, &temp_size);

        if (temp == NULL) {
            err = ENOMEM;
        }

        if (temp != NULL && (entry_head = strstr(temp, needle)) != NULL) {
            end = temp + temp_size;
            entry_tail = entry_head;
            while (entry_tail != end && *entry_tail != '\n') {
                entry_tail++;
            }

            newdb_size = temp_size - (entry_tail - entry_head);
            newdb = (kryptos_u8_t *) kryptos_newseg(newdb_size + 1);
            if (newdb == NULL) {
                err = ENOMEM;
            } else {
                memset(newdb, '\n', newdb_size + 1);
                memcpy(newdb, temp, entry_head - temp);
                memcpy(newdb + (entry_head - temp), entry_tail + 1, end - entry_tail + 1);
                err = netdb_flush_data(newdb, newdb_size);
            }
        } else {
            err = ENOENT;
        }

        if (temp != NULL) {
            kryptos_freeseg(temp, temp_size);
        }

        if (newdb != NULL) {
            kryptos_freeseg(newdb, newdb_size);
        }

        netdb_encrypt_buffer(key, key_size);
    }

blackcat_netdb_drop_epilogue:

    return err;
}

int blackcat_netdb_load(const char *filepath) {
    FILE *db = NULL;
    kryptos_u8_t *hmac_scheme = NULL;
    size_t hmac_scheme_size = 0;
    size_t filepath_size;

    blackcat_netdb_unload();

    if ((g_netdb.db = fopen(filepath, "a")) == NULL) {
        return ENOENT;
    }

    if (flock(fileno(g_netdb.db), LOCK_EX) != 0) {
        fclose(g_netdb.db);
        g_netdb.db = NULL;
        return EFAULT;
    }

    if ((db = fopen(filepath, "r")) == NULL) {
        if ((db = fopen(filepath, "w")) == NULL) {
            return ENOENT;
        }
        fclose(db);
        g_hmac = get_random_hmac_catalog_scheme();
        filepath_size = strlen(filepath);
        memset(g_netdb.filepath, 0, sizeof(g_netdb.filepath));
        memcpy(g_netdb.filepath, filepath, filepath_size % (sizeof(g_netdb.filepath) - 1));
        return 0;
    }

    fseek(db, 0L, SEEK_END);
    g_netdb.buf_size = ftell(db);
    fseek(db, 0L, SEEK_SET);

    if ((g_netdb.buf = (kryptos_u8_t *) kryptos_newseg(g_netdb.buf_size + 1)) == NULL) {
        return ENOMEM;
    }

    memset(g_netdb.buf, 0, g_netdb.buf_size + 1);

    fread(g_netdb.buf, g_netdb.buf_size, sizeof(kryptos_u8_t), db);

    fclose(db);

    hmac_scheme = kryptos_pem_get_data(BCNETDB_HMAC_SCHEME, g_netdb.buf, g_netdb.buf_size, &hmac_scheme_size);

    if (hmac_scheme != NULL) {
        g_hmac = get_hmac_catalog_scheme(hmac_scheme);
    } else {
        g_hmac = get_random_hmac_catalog_scheme();
    }

    if (g_hmac == NULL) {
        return EFAULT;
    }

    kryptos_freeseg(hmac_scheme, hmac_scheme_size);

    filepath_size = strlen(filepath);
    memset(g_netdb.filepath, 0, sizeof(g_netdb.filepath));
    memcpy(g_netdb.filepath, filepath, filepath_size % (sizeof(g_netdb.filepath) - 1));

    return 0;
}

int blackcat_netdb_unload(void) {
    if (g_netdb.buf != NULL) {
        kryptos_freeseg(g_netdb.buf, g_netdb.buf_size);
        g_netdb.buf = NULL;
        g_netdb.buf_size = 0;
    }

    if (g_netdb.db != NULL) {
        flock(fileno(g_netdb.db), LOCK_UN);
        fclose(g_netdb.db);
        g_netdb.db = NULL;
    }

    memset(g_netdb.filepath, 0, sizeof(g_netdb.filepath));
    g_hmac = NULL;

    return 0;
}

static void parse_netdb_entry(const char *buf, const char *buf_end,
                              char **rule_id, char **hash, struct bnt_channel_rule_assertion *assertion,
                              char **protection_layer, char **encoder) {
    int state = 0;
    void *data[6];
    const int state_nr = sizeof(data) / sizeof(data[0]);
    size_t data_size;
    const char *bp, *bp_end;

    data[0] = data[1] = data[2] = data[3] = data[4] = data[5] = NULL;
    assertion = NULL;

    for (bp = buf; bp != buf_end; bp = bp_end + 1) {
        bp_end = bp;
        while (bp_end != buf_end && *bp_end != ' ') {
            bp_end++;
        }

        if (bp_end == buf_end) {
            continue;
        }

        if (state >= state_nr) {
            break;
        }

        // TODO(Rafael): Parse assertion for non-socket based rules.

        data_size = bp_end - bp - (state == 0);
        if ((data[state] = (kryptos_u8_t *) kryptos_newseg(data_size + 1)) != NULL) {
            memset(data[state], 0, data_size + 1);
            memcpy(data[state], bp, data_size);
        }

        state += 1;
    }

    if (strcmp(data[1], "socket") == 0) {
        *rule_id = data[0];
        *hash = data[2];
        *protection_layer = data[3];
        *encoder = data[4];
    } else {
        *rule_id = data[0];
        *hash = data[2];
        *protection_layer = data[4];
        *encoder = data[5];
    }

    kryptos_freeseg(data[1], strlen(data[1]));
}

bnt_channel_rule_ctx *blackcat_netdb_select(const char *rule_id, const kryptos_u8_t *key, const size_t key_size,
                                            kryptos_u8_t **rule_key, size_t *rule_key_size) {
    kryptos_u8_t *temp = NULL, *temp_head, *temp_tail, *temp_end;
    size_t temp_size;
    char needle[1024];
    bnt_channel_rule_ctx *rule = NULL;
    char *rule_name = NULL, *hash = NULL, *protection_layer = NULL, *encoder = NULL;
    struct bnt_channel_rule_assertion assertion;

    if (netdb_decrypt_buffer(key, key_size) == 0) {
        if (strlen(rule_id) > sizeof(needle) - 1) {
            goto blackcat_netdb_select_epilogue;
        }

        sprintf(needle, "%s: ", rule_id);

        if ((temp = kryptos_pem_get_data(BCNETDB_DATA, g_netdb.buf, g_netdb.buf_size, &temp_size)) != NULL) {
            if ((temp_head = strstr(temp, needle)) != NULL) {
                temp_tail = temp_head;
                temp_end = temp + temp_size;
                while (temp_tail != temp_end && *temp_tail != '\n') {
                    temp_tail++;
                }
            }
        }

        netdb_encrypt_buffer(key, key_size);

        if (temp_head != NULL) {
            parse_netdb_entry(temp_head, temp_tail,
                              &rule_name, &hash, &assertion, &protection_layer, &encoder);

            rule = add_bnt_channel_rule(rule, rule_name, assertion, protection_layer, rule_key, rule_key_size,
                                        get_hash_processor(hash), get_encoder(encoder));
        }
    }

blackcat_netdb_select_epilogue:

    if (rule_name != NULL) {
        kryptos_freeseg(rule_name, strlen(rule_name));
    }

    if (hash != NULL) {
        kryptos_freeseg(hash, strlen(hash));
    }

    if (protection_layer != NULL) {
        kryptos_freeseg(protection_layer, strlen(protection_layer));
    }

    if (encoder != NULL) {
        kryptos_freeseg(encoder, strlen(encoder));
    }

    if (temp != NULL) {
        kryptos_freeseg(temp, temp_size);
    }

    return rule;
}

#undef BCNETDB_HMAC_SCHEME

#undef BCNETDB_DATA

#undef netdb_decrypt_buffer

#undef netdb_encrypt_buffer
