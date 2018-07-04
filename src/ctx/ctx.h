/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CTX_H
#define BLACKCAT_CTX_H 1

#include <basedefs/defs.h>

blackcat_protlayer_chain_ctx *add_composite_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                               const char *piped_ciphers, kryptos_u8_t **key,
                                                               size_t *key_size, blackcat_hash_processor hash,
                                                               blackcat_encoder encoder);

blackcat_protlayer_chain_ctx *add_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                     const char *algo_params, kryptos_u8_t **key, size_t *key_size,
                                                     blackcat_hash_processor hash);

void del_protlayer_chain_ctx(blackcat_protlayer_chain_ctx *chain);


#endif
