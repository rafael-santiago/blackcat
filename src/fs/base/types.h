/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_FS_BASE_TYPES_H
#define BLACKCAT_FS_BASE_TYPES_H 1

#include <kryptos_types.h>
#include <basedefs/defs.h>

typedef enum {
    kBfsFileStatusPlain     = 'P',
    kBfsFileStatusLocked    = 'L',
    kBfsFileStatusUnlocked  = 'U',
    kBfsFileStatusNr        = 0x3
}bfs_file_status_t;

typedef struct bfs_catalog_relpath {
    struct bfs_catalog_relpath *head, *tail;
    kryptos_u8_t *path;
    size_t path_size;
    bfs_file_status_t status;
    char timestamp[20];
    kryptos_u8_t *seed;
    size_t seed_size;
    struct bfs_catalog_relpath *last, *next;
}bfs_catalog_relpath_ctx;

typedef struct bfs_catalog {
    char *bc_version;
    const struct blackcat_hmac_catalog_algorithms_ctx *hmac_scheme;
    int otp;
    blackcat_hash_processor key_hash_algo, protlayer_key_hash_algo, catalog_key_hash_algo;
    blackcat_hash_size_func key_hash_algo_size, protlayer_key_hash_algo_size, catalog_key_hash_algo_size;
    blackcat_encoder encoder;
    kryptos_u8_t *key_hash;
    size_t key_hash_size;
    kryptos_u8_t *config_hash;
    size_t config_hash_size;
    blackcat_data_processor encrypt_data, decrypt_data;
    char *protection_layer;
    blackcat_protlayer_chain_ctx *protlayer;
    bfs_catalog_relpath_ctx *files;
}bfs_catalog_ctx;

#endif

