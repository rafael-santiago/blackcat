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

typedef int (*bfs_checkpoint_func)(void *ckpt_args);

char *remove_go_ups_from_path(char *path, const size_t path_size);

int bcrepo_write(const char *filepath, bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size);

kryptos_u8_t *bcrepo_read(const char *filepath, bfs_catalog_ctx *catalog, size_t *out_size);

int bcrepo_stat(bfs_catalog_ctx **catalog,
                const kryptos_u8_t *key, const size_t key_size,
                kryptos_u8_t **data, size_t *data_size);

int bcrepo_validate_key(const bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size);

kryptos_u8_t *bcrepo_hash_key(const kryptos_u8_t *key,
                              const size_t key_size, blackcat_hash_processor h, void *h_args, size_t *hsize);

char *bcrepo_get_rootpath(void);

int bcrepo_add(bfs_catalog_ctx **catalog,
               const char *rootpath, const size_t rootpath_size,
               const char *pattern, const size_t pattern_size, const int plain);

int bcrepo_rm(bfs_catalog_ctx **catalog,
              const char *rootpath, const size_t rootpath_size,
              const char *pattern, const size_t pattern_size, const int force);

int bcrepo_lock(bfs_catalog_ctx **catalog,
                const char *rootpath, const size_t rootpath_size,
                const char *pattern, const size_t pattern_size,
                bfs_checkpoint_func ckpt,
                void *ckpt_args);

int bcrepo_unlock(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size,
                  bfs_checkpoint_func ckpt,
                  void *ckpt_args);

int bcrepo_init(bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size);

int bcrepo_deinit(const char *rootpath, const size_t rootpath_size, const kryptos_u8_t *key, const size_t key_size);

int bcrepo_pack(bfs_catalog_ctx **catalog, const char *rootpath, const size_t rootpath_size,
                             const char *wpath, bfs_checkpoint_func ckpt, void *ckpt_args);

int bcrepo_unpack(const char *wpath, const char *rootpath);

int bcrepo_reset_repo_settings(bfs_catalog_ctx **catalog,
                               const char *rootpath, const size_t rootpath_size,
                               kryptos_u8_t *catalog_key, const size_t catalog_key_size,
                               kryptos_u8_t **protlayer_key, size_t *protlayer_key_size,
                               const char *protection_layer,
                               blackcat_hash_processor catalog_hash_proc,
                               blackcat_hash_processor key_hash_proc,
                               void *key_hash_proc_args,
                               blackcat_hash_processor protlayer_hash_proc,
                               blackcat_encoder encoder,
                               bfs_checkpoint_func ckpt,
                               void *ckpt_args);

char *bcrepo_catalog_file(char *buf, const size_t buf_size, const char *rootpath);

char *bcrepo_rescue_file(char *buf, const size_t buf_size, const char *rootpath);

int bcrepo_bury(bfs_catalog_ctx **catalog,
                const char *rootpath, const size_t rootpath_size,
                const char *pattern, const size_t pattern_size);

int bcrepo_dig_up(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size);

int bcrepo_remove_rescue_file(const char *rootpath, const size_t rootpath_size);

int bcrepo_restore(const bfs_catalog_ctx *catalog, const char *rootpath, const size_t rootpath_size);

int bcrepo_decoy(const char *filepath, const size_t chaff_size, blackcat_encoder encoder, const int overwrite);

int bcrepo_info(bfs_catalog_ctx *catalog);

int bcrepo_detach_metainfo(const char *rootpath, const size_t rootpath_size, const char *dest, const size_t dest_size);

int bcrepo_attach_metainfo(const char *src, const size_t src_size);

#endif
