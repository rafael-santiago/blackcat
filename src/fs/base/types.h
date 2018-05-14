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

typedef enum {
    kBfsFileStatusPlain,
    kBfsFileStatusEncrypted,
    kBfsFileStatusDecrypted,
    kBfsFileStatusNr
}bfs_file_status_t;

typedef struct bfs_container_path {
    kryptos_u8_t *data;
    size_t data_size;
    bfs_file_status_t status;
    struct bfs_container_path *last, *next;
}bfs_container_path_ctx;

typedef struct bfs_container_config {
    kryptos_u8_t *password;
    size_t password_size;
    bfs_container_path_ctx *path;
}bfs_container_config_ctx;

#endif

