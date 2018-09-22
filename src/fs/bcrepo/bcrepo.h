/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_FS_BCREPO_BCREPO_H
#define BLACKCAT_FS_BCREPO_BCREPO_H 1

#include <basedefs/defs.h>
#include <fs/base/types.h>

char *remove_go_ups_from_path(char *path, const size_t path_size);

int bcrepo_write(const char *filepath, bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size);

kryptos_u8_t *bcrepo_read(const char *filepath, bfs_catalog_ctx *catalog, size_t *out_size);

int bcrepo_stat(bfs_catalog_ctx **catalog,
                const kryptos_u8_t *key, const size_t key_size,
                kryptos_u8_t **data, size_t *data_size);

int bcrepo_validate_key(const bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size);

char *bcrepo_get_rootpath(void);

int bcrepo_add(bfs_catalog_ctx **catalog,
               const char *rootpath, const size_t rootpath_size,
               const char *pattern, const size_t pattern_size, const int plain);

int bcrepo_rm(bfs_catalog_ctx **catalog,
              const char *rootpath, const size_t rootpath_size,
              const char *pattern, const size_t pattern_size, const int force);

int bcrepo_lock(bfs_catalog_ctx **catalog,
                const char *rootpath, const size_t rootpath_size,
                const char *pattern, const size_t pattern_size);

int bcrepo_unlock(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size);

int bcrepo_init(bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size);

int bcrepo_deinit(const char *rootpath, const size_t rootpath_size, const kryptos_u8_t *key, const size_t key_size);

int bcrepo_pack(bfs_catalog_ctx **catalog, const char *rootpath, const size_t rootpath_size,
                             const char *wpath);

int bcrepo_unpack(const char *wpath, const char *rootpath);

int bcrepo_reset_repo_settings(bfs_catalog_ctx **catalog,
                               const char *rootpath, const size_t rootpath_size,
                               kryptos_u8_t *catalog_key, const size_t catalog_key_size,
                               kryptos_u8_t **protlayer_key, size_t *protlayer_key_size,
                               const char *protection_layer,
                               blackcat_hash_processor catalog_hash_proc,
                               blackcat_hash_processor key_hash_proc,
                               blackcat_hash_processor protlayer_hash_proc,
                               blackcat_encoder encoder);

char *bcrepo_catalog_file(char *buf, const size_t buf_size, const char *rootpath);

int bcrepo_bury(bfs_catalog_ctx **catalog,
                const char *rootpath, const size_t rootpath_size,
                const char *pattern, const size_t pattern_size);

int bcrepo_dig_up(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size);

#endif
