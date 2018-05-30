/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_FS_CTX_FSCTX_H
#define BLACKCAT_FS_CTX_FSCTX_H 1

#include <fs/base/types.h>

bfs_catalog_relpath_ctx *add_file_to_relpath_ctx(bfs_catalog_relpath_ctx *files,
                                                 kryptos_u8_t *path,
                                                 size_t path_size,
                                                 bfs_file_status_t status,
                                                 const char *timestamp);

bfs_catalog_relpath_ctx *del_file_from_relpath_ctx(bfs_catalog_relpath_ctx *files, const kryptos_u8_t *path);

void del_bfs_catalog_relpath_ctx(bfs_catalog_relpath_ctx *files);

void del_bfs_catalog_ctx(bfs_catalog_ctx *catalog);

bfs_catalog_ctx *new_bfs_catalog_ctx(void);

#endif
