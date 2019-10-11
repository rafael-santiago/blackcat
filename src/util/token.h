/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_UTIL_TOKEN_H
#define BLACKCAT_UTIL_TOKEN_H 1

#include <stdlib.h>
#include <kryptos.h>

int token_wrap(kryptos_u8_t **key, size_t *key_size, const kryptos_u8_t *token, const size_t token_size);

#endif
