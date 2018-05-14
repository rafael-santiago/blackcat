/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_MEMORY_H
#define BLACKCAT_MEMORY_H 1

#include <stdlib.h>

void *blackcat_getseg(const size_t ssize);

void blackcat_free(void *seg, size_t *ssize);

#endif
