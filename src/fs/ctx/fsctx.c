/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <fs/ctx/fsctx.h>
#include <ctx/ctx.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define new_relpath_ctx(r) ( (r) = (bfs_catalog_relpath_ctx *) kryptos_newseg(sizeof(bfs_catalog_relpath_ctx)),\
                             (r)->head = (r)->tail = (r)->last = (r)->next = NULL,\
                             (r)->path = NULL,\
                             memset((r)->timestamp, 0, sizeof((r)->timestamp)),\
                             (r)->status = kBfsFileStatusNr,\
                             (r)->path_size = 0,\
                             (r)->seed = NULL,\
                             (r)->seed_size = 0 )

#define BLACKCAT_FILE_SEED_BYTES_NR 8

static bfs_catalog_relpath_ctx *get_relpath_ctx_tail(bfs_catalog_relpath_ctx *head);

bfs_catalog_relpath_ctx *add_file_to_relpath_ctx(bfs_catalog_relpath_ctx *files,
                                                 kryptos_u8_t *path,
                                                 size_t path_size,
                                                 bfs_file_status_t status,
                                                 const char *timestamp) {
    bfs_catalog_relpath_ctx *h, *c;
    kryptos_u8_t *p;
    size_t p_d = 0;

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
        fprintf(stderr, "ERROR: While adding a file to the catalog. Not enough memory.\n");
        goto add_file_to_relpath_ctx_epilogue;
    }

    p = path;

    if (*p == '/') {
        p += 1;
        p_d = 1;
    }

    memset(c->path, 0, path_size + 1);
    c->path_size = path_size - p_d;
    memcpy(c->path, p, c->path_size);

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
        } else {
            t->next->last = t->last;
        }

        t->last->next = t->next;
    }

    t->next = NULL;

    del_bfs_catalog_relpath_ctx(t);

    return h;
}

bfs_catalog_relpath_ctx *get_entry_from_relpath_ctx(bfs_catalog_relpath_ctx *files, const kryptos_u8_t *path) {
    bfs_catalog_relpath_ctx *rp;
    const kryptos_u8_t *p;

    if (path == NULL) {
        return NULL;
    }

    p = path;

    if (*p == '/') {
        p += 1;
    }

    for (rp = files; rp != NULL; rp = rp->next) {
        if (strcmp(rp->path, p) == 0) {
            return rp;
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
            kryptos_freeseg(p->path, p->path_size);
            p->path_size = 0;
        }

        if (p->seed != NULL) {
            kryptos_freeseg(p->seed, p->seed_size);
            p->seed_size = 0;
        }

        kryptos_freeseg(p, sizeof(bfs_catalog_relpath_ctx));
    }
}

void del_bfs_catalog_ctx(bfs_catalog_ctx *catalog) {
    if (catalog->bc_version != NULL) {
        kryptos_freeseg(catalog->bc_version, strlen(catalog->bc_version));
    }

    catalog->key_hash_algo = NULL;
    catalog->key_hash_algo_size = NULL;

    catalog->protlayer_key_hash_algo = NULL;
    catalog->protlayer_key_hash_algo_size = NULL;

    catalog->encoder = NULL;

    if (catalog->protection_layer != NULL) {
        kryptos_freeseg(catalog->protection_layer, strlen(catalog->protection_layer));
    }

    if (catalog->protlayer != NULL) {
        del_protlayer_chain_ctx(catalog->protlayer);
    }

    if (catalog->key_hash != NULL) {
        kryptos_freeseg(catalog->key_hash, catalog->key_hash_size);
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
        catalog->protlayer = NULL;
        catalog->key_hash = NULL;
        catalog->key_hash_size = 0;
        catalog->files = NULL;
        catalog->encoder = NULL;
    }
    return catalog;
}

void get_new_file_seed(kryptos_u8_t **seed, size_t *seed_size) {
    kryptos_u8_t *new_seed;
    size_t ns;

    new_seed = (kryptos_u8_t *) kryptos_newseg(BLACKCAT_FILE_SEED_BYTES_NR);

    if (new_seed == NULL) {
        fprintf(stderr, "WARN: Unable to get a new seed, recycling the old one.\n");
    } else {
        for (ns = 0; ns < BLACKCAT_FILE_SEED_BYTES_NR; ns++) {
            new_seed[ns] = kryptos_get_random_byte();
        }
        ns = 0;
        if (*seed != NULL) {
            kryptos_freeseg(*seed, *seed_size);
        }
        (*seed) = new_seed;
        *seed_size = BLACKCAT_FILE_SEED_BYTES_NR;
    }
}

#undef BLACKCAT_FILE_SEED_BYTES_NR
