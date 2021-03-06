/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CMD_SESSION_H
#define BLACKCAT_CMD_SESSION_H 1

#include <fs/ctx/fsctx.h>
#include <kryptos_memory.h>

typedef struct blackcat_exec_session {
    char *rootpath;
    size_t rootpath_size;
    bfs_catalog_ctx *catalog;
    kryptos_u8_t *key[2];
    size_t key_size[2];
}blackcat_exec_session_ctx;

int new_blackcat_exec_session_ctx(blackcat_exec_session_ctx **session, const int build_protlayer);

#define del_blackcat_exec_session_ctx(es) {\
    if ((es)->rootpath != NULL) {\
        kryptos_freeseg((es)->rootpath, (es)->rootpath_size);\
    }\
    if ((es)->key[0] != NULL) {\
        kryptos_freeseg((es)->key[0], (es)->key_size[0]);\
    }\
    if ((es)->key[1] != NULL) {\
        kryptos_freeseg((es)->key[1], (es)->key_size[1]);\
    }\
    if ((es)->catalog != NULL) {\
        del_bfs_catalog_ctx((es)->catalog);\
    }\
    kryptos_freeseg((es), sizeof(blackcat_exec_session_ctx));\
}

#endif
