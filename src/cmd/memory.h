/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CMD_MEMORY_H
#define BLACKCAT_CMD_MEMORY_H 1

// INFO(Rafael): The acrobatic usage of memset is just for ensure the cleanup memsets by getting rid off the compiler
//               optimization heuristics.
//
//               The memcmp overwrite is a mitigation for timing attacks.

#include <stdlib.h>

#undef memset
#define memset blackcat_cmd_memset

void *blackcat_cmd_memset(void *s, int c, size_t n);

int memcmp(const void *s1, const void *s2, size_t n);

#endif
