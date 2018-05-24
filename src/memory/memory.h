/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_MEMORY_H
#define BLACKCAT_MEMORY_H 1

#include <stdlib.h>

void *blackcat_getseg(const size_t ssize);

void blackcat_free(void *seg, size_t *ssize);

#endif
