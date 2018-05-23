/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_FS_BASE_TYPES_H
#define BLACKCAT_FS_BASE_TYPES_H 1

#include <kryptos_types.h>
#include <basedefs/defs.h>

typedef enum {
    kBfsFileStatusPlain     = 'P',
    kBfsFileStatusEncrypted = 'E',
    kBfsFileStatusDecrypted = 'D',
    kBfsFileStatusNr = 3
}bfs_file_status_t;

typedef struct bfs_catalog_relpath {
    kryptos_u8_t *data;
    size_t data_size;
    bfs_file_status_t status;
    char timestamp[20];
    struct bfs_container_path *last, *next;
}bfs_catalog_relpath_ctx;

typedef struct bfs_catalog {
    const char *bc_version;
    blackcat_hash_processor key_hash_algo, protlayer_key_hash_algo;
    const kryptos_u8_t *key_hash;
    const size_t key_hash_size;
    const char *protection_layer;
    bfs_catalog_relpath *path;
}bfs_catalog_ctx;

#endif

