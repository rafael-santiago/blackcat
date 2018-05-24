/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_FS_BCREPO_BCREPO_H
#define BLACKCAT_FS_BCREPO_BCREPO_H 1

#include <fs/base/types.h>

int bcrepo_write(const char *filepath, const bfs_catalog_ctx *catalog);

kryptos_u8_t *bcrepo_read(const char *filepath, size_t out_size);

#endif
