/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_NET_CTX_CTX_H
#define BLACKCAT_NET_CTX_CTX_H 1

#include <basedefs/defs.h>
#include <net/base/types.h>

bnt_channel_rule_ctx *add_bnt_channel_rule(bnt_channel_rule_ctx *rules,
                                           const char *ruleid,
                                           const struct bnt_channel_rule_assertion assertion,
                                           const char *protection_layer,
                                           kryptos_u8_t **key,
                                           size_t *key_size,
                                           blackcat_hash_processor hash,
                                           blackcat_encoder encoder);

bnt_channel_rule_ctx *del_bnt_channel_rule(bnt_channel_rule_ctx *rules, const char *ruleid);

bnt_channel_rule_ctx *get_bnt_channel_rule(const char *ruleid, bnt_channel_rule_ctx *rules);

void del_bnt_channel_rule_ctx(bnt_channel_rule_ctx *rules);

#endif
