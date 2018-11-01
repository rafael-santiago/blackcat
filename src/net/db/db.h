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
                       char *error);

int blackcat_netdb_drop(const char *rule_id);

int blackcat_netdb_load(const char *filepath);

int blackcat_netdb_unload(const char *filepath);

bnt_channel_rule_ctx *blackcat_netdb_select(const char *rule_id);

#endif
