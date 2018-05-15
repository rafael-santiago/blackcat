/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_H
#define BLACKCAT_KEYCHAIN_H 1

#include <basedefs/defs.h>
#include <kryptos_types.h>

void blackcat_set_keychain(blackcat_protlayer_chain_ctx **protlayer,
                           const char *algo_params, const kryptos_u8_t *key, const size_t key_size);

#endif
