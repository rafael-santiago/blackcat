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

#define new_relpath_ctx(r) {\
    (r) = (bfs_catalog_relpath_ctx *) kryptos_newseg(sizeof(bfs_catalog_relpath_ctx));\
    if ((r) != NULL) {\
        (r)->head = (r)->tail = (r)->last = (r)->next = NULL;\
        (r)->path = NULL;\
        memset((r)->timestamp, 0, sizeof((r)->timestamp));\
        (r)->status = kBfsFileStatusNr;\
        (r)->path_size = 0;\
        (r)->seed = NULL;\
        (r)->seed_size = 0;\
    }\
}

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
#if defined(_WIN32)
    kryptos_u8_t *rp;
#endif

    if (files == NULL) {
        new_relpath_ctx(files);
        if (files == NULL) {
            fprintf(stderr, "ERROR: Not enough memory.\n");
            h = NULL;
            goto add_file_to_relpath_ctx_epilogue;
        }
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

        if (c->next == NULL) {
            fprintf(stderr, "ERROR: Not enough memory.\n");
            goto add_file_to_relpath_ctx_epilogue;
        }

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

#if defined(__unix__)
    if (*p == '/') {
        p += 1;
        p_d = 1;
    }
#elif defined(_WIN32)
    if (*p == '\\' || *p == '/') {
        p += 1;
        p_d = 1;
    } else if ((rp = strstr(p, ":\\")) != NULL || (rp = strstr(p, ":/")) != NULL) {
        p = rp;
        p += 2;
        p_d = 2;
    }
#else
# error Some code wanted.
#endif

    memset(c->path, 0, path_size + 1);
    c->path_size = path_size - p_d;
    memcpy(c->path, p, c->path_size);

#if defined(_WIN32)
    // INFO(Rafael): Internally, let's normalize path to a more sane standard.
    rp = c->path;
    while (*rp != 0) {
        if (*rp == '\\') {
            *rp = '/';
        }
        rp++;
    }
#endif

    if (timestamp != NULL) {
        sprintf(c->timestamp, "%s", timestamp);
    } else {
        sprintf(c->timestamp, "%ld", time(NULL));
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
#if defined(_WIN32)
    const kryptos_u8_t *p_head;
    kryptos_u8_t temp[4096];
#endif

    if (path == NULL) {
        return NULL;
    }

#if defined(__unix__)
    p = path;

    if (*p == '/') {
        p += 1;
    }

    for (rp = files; rp != NULL; rp = rp->next) {
        if (strcmp((char *)rp->path, (char *)p) == 0) {
            return rp;
        }
    }
#elif defined(_WIN32)
    p_head = NULL;
    p = path;

    if (*p == '/' || *p == '\\') {
        p += 1;
        p_head = p;
    } else if ((p_head = strstr(p, ":\\")) != NULL || (p_head = strstr(p, ":/")) != NULL) {
        p_head += 2;
        p = p_head;
    }

    if (p_head == NULL) {
        p_head = p;
    }

    for (; *p != 0; p++)
        ;

    if ((p - p_head) >= sizeof(temp)) {
        return NULL;
    }

    memset(temp, 0, sizeof(temp));
    memcpy(temp, p_head, p - p_head);

    for (rp = files; rp != NULL; rp = rp->next) {
        if (strcmp(rp->path, temp) == 0) {
            memset(temp, 0, sizeof(temp));
            p = p_head = NULL;
            return rp;
        }
    }

    memset(temp, 0, sizeof(temp));
    p = p_head = NULL;
#else
# error Some code wanted.
#endif

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

    if (catalog->config_hash != NULL) {
        kryptos_freeseg(catalog->config_hash, catalog->config_hash_size);
        catalog->config_hash_size = 0;
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

    if (catalog->kdf_params != NULL) {
        kryptos_freeseg(catalog->kdf_params, catalog->kdf_params_size);
        catalog->kdf_params_size = 0;
    }

    if (catalog->salt != NULL) {
        kryptos_freeseg(catalog->salt, catalog->salt_size);
        catalog->salt_size = 0;
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
        catalog->config_hash = NULL;
        catalog->config_hash_size = 0;
        catalog->kdf_params = NULL;
        catalog->kdf_params_size = 0;
        // INFO(Rafael): From v1.2.0 first-layer key is always salted.
        catalog->salt = NULL;
        catalog->salt_size = 0;
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
