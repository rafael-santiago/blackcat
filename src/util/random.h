/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_UTIL_RANDOM_H
#define BLACKCAT_UTIL_RANDOM_H 1

#include <kryptos.h>
#include <stdlib.h>

kryptos_u8_t *random_printable_padding(size_t *size);

#endif
