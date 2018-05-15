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

kryptos_u8_t *blackcat_derive_key(const blackcat_protlayer_t algo, const kryptos_u8_t *key, const size_t key_size,
                                  size_t *derived_size);

#endif
