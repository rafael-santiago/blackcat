/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <fs/ctx/fsctx.h>
#include <kryptos_memory.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define new_relpath_ctx(r) ( (r) = (bfs_catalog_relpath_ctx *) kryptos_newseg(sizeof(bfs_catalog_relpath_ctx)),\
                             (r)->head = (r)->tail = (r)->last = (r)->next = NULL,\
                             (r)->path = NULL,\
                             memset((r)->timestamp, 0, sizeof((r)->timestamp)),\
                             (r)->status = kBfsFileStatusNr,\
                             (r)->path_size = 0 )

static bfs_catalog_relpath_ctx *get_relpath_ctx_tail(bfs_catalog_relpath_ctx *head);

bfs_catalog_relpath_ctx *add_file_to_relpath_ctx(bfs_catalog_relpath_ctx *files,
                                                 kryptos_u8_t *path,
                                                 size_t path_size,
                                                 bfs_file_status_t status,
                                                 const char *timestamp) {
    bfs_catalog_relpath_ctx *h, *c;

    if (files == NULL) {
        new_relpath_ctx(files);
        files->head = files;
        files->tail = files;
        h = c = files;
    } else {
        h = files;

        if (get_entry_from_relpath_ctx(h, path) != NULL) {
            goto add_file_to_relpath_ctx_epilogue;
        }

        if (files->tail == NULL) {
            c = get_relpath_ctx_tail(files);
        } else {
            c = files->tail;
        }

        new_relpath_ctx(c->next);

        c->next->last = c;
        c = c->next;
        files->tail = c;
    }

    c->path = (kryptos_u8_t *) kryptos_newseg(path_size + 1);

    if (c->path == NULL) {
        printf("ERROR: While adding a file to the catalog. Not enough memory.\n");
        goto add_file_to_relpath_ctx_epilogue;
    }

    memset(c->path, 0, path_size + 1);
    memcpy(c->path, path, path_size);
    c->path_size = path_size;

    if (timestamp != NULL) {
        sprintf(c->timestamp, "%s", timestamp);
    } else {
        sprintf(c->timestamp, "%d", time(NULL));
    }

    c->status = status;

add_file_to_relpath_ctx_epilogue:

    return h;
}

bfs_catalog_relpath_ctx *del_file_from_relpath_ctx(bfs_catalog_relpath_ctx *files, const kryptos_u8_t *path) {
    bfs_catalog_relpath_ctx *t, *h;

    t = get_entry_from_relpath_ctx(files, path);

    if (t == NULL) {
        return files;
    }

    if (t == files) {
        h = files->next;
        if (h != NULL) {
            h->head = h;
            h->tail = files->tail;
        }
    } else {
        h = files;

        if (t->next == NULL) {
            h->tail = t->last;
        }

        t->last->next = t->next;
    }

    t->next = NULL;

    del_bfs_catalog_relpath_ctx(t);

    return h;
}

bfs_catalog_relpath_ctx *get_entry_from_relpath_ctx(bfs_catalog_relpath_ctx *files, const kryptos_u8_t *path) {
    bfs_catalog_relpath_ctx *p;

    for (p = files; p != NULL; p = p->next) {
        if (strcmp(p->path, path) == 0) {
            return p;
        }
    }

    return NULL;
}

static bfs_catalog_relpath_ctx *get_relpath_ctx_tail(bfs_catalog_relpath_ctx *head) {
    bfs_catalog_relpath_ctx *h;

    for (h = head; h->next != NULL; h = h->next)
        ;

    return h;
}

void del_bfs_catalog_relpath_ctx(bfs_catalog_relpath_ctx *files) {
    bfs_catalog_relpath_ctx *p, *t;

    for (p = t = files; t != NULL; p = t) {
        t = p->next;

        if (p->path != NULL) {
            kryptos_freeseg(p->path);
        }

        kryptos_freeseg(p);
    }
}

void del_bfs_catalog_ctx(bfs_catalog_ctx *catalog) {
    if (catalog->bc_version != NULL) {
        kryptos_freeseg(catalog->bc_version);
    }

    catalog->key_hash_algo = NULL;
    catalog->key_hash_algo_size = NULL;

    catalog->protlayer_key_hash_algo = NULL;
    catalog->protlayer_key_hash_algo_size = NULL;

    if (catalog->protection_layer != NULL) {
        memset(catalog->protection_layer, 0, strlen(catalog->protection_layer));
        kryptos_freeseg(catalog->protection_layer);
    }

    if (catalog->key_hash != NULL) {
        memset(catalog->key_hash, 0, catalog->key_hash_size);
        kryptos_freeseg(catalog->key_hash);
        catalog->key_hash_size = 0;
    }

    if (catalog->files != NULL) {
        del_bfs_catalog_relpath_ctx(catalog->files);
    }

    free(catalog);
}

bfs_catalog_ctx *new_bfs_catalog_ctx(void) {
    bfs_catalog_ctx *catalog = kryptos_newseg(sizeof(bfs_catalog_ctx));
    if (catalog != NULL) {
        catalog->bc_version = NULL;
        catalog->protlayer_key_hash_algo = NULL;
        catalog->protlayer_key_hash_algo_size = NULL;
        catalog->protection_layer = NULL;
        catalog->key_hash = NULL;
        catalog->key_hash_size = 0;
        catalog->files = NULL;
    }
    return catalog;
}
