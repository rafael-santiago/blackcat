/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_NET_DB_DB_H
#define BLACKCAT_NET_DB_DB_H 1

#include <net/base/types.h>

int blackcat_netdb_add(const char *rule_id,
                       const char *rule_type,
                       const char *hash,
                       const char *target,
                       const char *pchain,
                       const char *encoder,
                       char *error,
                       const kryptos_u8_t *key,
                       const size_t key_size);

int blackcat_netdb_drop(const char *rule_id, const kryptos_u8_t *key, const size_t key_size);

int blackcat_netdb_load(const char *filepath);

int blackcat_netdb_unload(void);

bnt_channel_rule_ctx *blackcat_netdb_select(const char *rule_id, const kryptos_u8_t *key, const size_t key_size,
                                            kryptos_u8_t **rule_key, size_t *rule_key_size);

#endif
