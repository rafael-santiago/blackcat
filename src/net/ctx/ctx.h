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

bnt_keychunk_ctx *add_bnt_keychunk(bnt_keychunk_ctx *kchunk, const kryptos_u8_t *data, const size_t data_size);

bnt_keychain_ctx *add_bnt_keychain(bnt_keychain_ctx *kchain, const kryptos_u64_t seqno);

bnt_keychain_ctx *del_bnt_keychain_seqno(bnt_keychain_ctx *kchain, const kryptos_u64_t seqno);

void del_bnt_keychunk(bnt_keychunk_ctx *keychunk);

void del_bnt_keychain(bnt_keychain_ctx *keychain);

bnt_keychain_ctx *get_bnt_keychain(const kryptos_u64_t seqno, bnt_keychain_ctx *kchain);

int init_bnt_keyset(bnt_keyset_ctx **keyset, const blackcat_protlayer_chain_ctx *pchain,
                    const kryptos_u64_t max_seqno_delta, kryptos_hash_func h, kryptos_hash_size_func h_input_size,
                    kryptos_hash_size_func h_size, kryptos_mp_value_t *xchgd_key,
                    const kryptos_u8_t *send_seed, const size_t send_seed_size,
                    const kryptos_u8_t *recv_seed, const size_t recv_seed_size);

void deinit_bnt_keyset(bnt_keyset_ctx *keyset);

int step_bnt_keyset(bnt_keyset_ctx **keyset, const kryptos_u64_t intended_seqno);

int set_protlayer_key_by_keychain_seqno(const kryptos_u64_t seqno,
                                       blackcat_protlayer_chain_ctx *pchain, bnt_keychain_ctx **keychain);

#endif
