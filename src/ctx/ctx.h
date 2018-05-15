/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_CTX_H
#define BLACKCAT_CTX_H 1

#include <basedefs/defs.h>

blackcat_protlayer_chain_ctx *add_protlayer_to_chain(blackcat_protlayer_chain_ctx *chain,
                                                     const char *algo_params, const kryptos_u8_t *key, const size_t key_size);

void del_protlayer_chain_ctx(blackcat_protlayer_chain_ctx *chain);


#endif
