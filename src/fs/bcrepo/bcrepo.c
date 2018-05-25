/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <fs/bcrepo/bcrepo.h>
#include <keychain/ciphering_schemes.h>
#include <kryptos.h>
#include <stdio.h>
#include <string.h>

#define BCREPO_CATALOG_BC_VERSION               "bc-version: "
#define BCREPO_CATALOG_KEY_HASH_ALGO            "key-hash-algo: "
#define BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO  "protlayer-key-hash-algo: "
#define BCREPO_CATALOG_KEY_HASH                 "key_hash: "
#define BCREPO_CATALOG_PROTECTION_LAYER         "protection-layer: "
#define BCREPO_CATALOG_FILES                    "files: "

#define BCREPO_PEM_HMAC_HDR "BCREPO HMAC SCHEME"
#define BCREPO_PEM_CATALOG_DATA_HDR "BCREPO CATALOG DATA"

typedef kryptos_u8_t *(*bcrepo_dumper)(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static size_t eval_catalog_buf_size(const bfs_catalog_ctx *catalog);

static void dump_catalog_data(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *bc_version_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *key_hash_algo_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *protlayer_key_hash_algo_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *key_hash_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *protection_layer_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *files_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

int bcrepo_write(const char *filepath, const bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size) {
    FILE *fp = NULL;
    int no_error = 1;
    size_t o_size;
    kryptos_u8_t *o = NULL;
    const struct blackcat_hmac_catalog_algorithms_ctx *hmac;
    blackcat_protlayer_chain_ctx p_layer;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *pem_buf = NULL;
    size_t pem_buf_size = 0;

    kryptos_task_init_as_null(ktask);

    o_size = eval_catalog_buf_size(catalog);

    if (o_size == 0) {
        printf("ERROR: Nothing to be written.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    o = (kryptos_u8_t *) kryptos_newseg(o_size);

    if (o == NULL) {
        printf("ERROR: Not enough memory.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    memset(o, 0, o_size);
    dump_catalog_data(o, o_size, catalog);

    hmac = get_random_hmac_catalog_scheme();

    p_layer.key = (kryptos_u8_t *) key;
    p_layer.key_size = key_size;
    p_layer.mode = hmac->mode;

    kryptos_task_set_in(ktask, o, o_size);

    hmac->processor(&ktask, &p_layer);

    p_layer.key = NULL;
    p_layer.key_size = 0;
    p_layer.mode = kKryptosCipherModeNr;

    if (!kryptos_last_task_succeed(ktask)) {
        printf("ERROR: Error while encrypting the catalog data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_HMAC_HDR,
                             hmac->name, strlen(hmac->name)) != kKryptosSuccess) {
        printf("ERROR: Error while writing the catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_CATALOG_DATA_HDR,
                             ktask->out, ktask->out_size) != kKryptosSuccess) {
        printf("ERROR: Error while writing the catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    fp = fopen(filepath, "w");

    if (fp == NULL) {
        printf("ERROR: Unable to write to file '%s'.\n", filepath);
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (fwrite(pem_buf, 1, pem_buf_size, fp) == -1) {
        printf("ERROR: While writing the PEM data to disk.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

bcrepo_write_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IV);

    if (fp != NULL) {
        fclose(fp);
    }

    if (o != NULL) {
        kryptos_freeseg(o);
    }

    if (pem_buf != NULL) {
        kryptos_freeseg(pem_buf);
        pem_buf_size = 0;
    }

    hmac = NULL;

    return no_error;
}

kryptos_u8_t *bcrepo_read(const char *filepath, size_t out_size) {
    return NULL;
}

static size_t eval_catalog_buf_size(const bfs_catalog_ctx *catalog) {
    size_t size;
    const char *hash_name;
    bfs_catalog_relpath_ctx *f;

    if (catalog                   == NULL ||
        catalog->bc_version       == NULL ||
        catalog->key_hash         == NULL ||
        catalog->protection_layer == NULL) {
        // WARN(Rafael): In normal conditions it should never happen.
        return 0;
    }

    hash_name = get_hash_processor_name(catalog->protlayer_key_hash_algo);

    if (hash_name == NULL) {
        // WARN(Rafael): In normal conditions it should never happen.
        return 0;
    }

    size = strlen(hash_name);

    hash_name = get_hash_processor_name(catalog->key_hash_algo);

    if (hash_name == NULL) {
        // WARN(Rafael): In normal conditions it should never happen.
        return 0;
    }

    size += strlen(catalog->bc_version) + strlen(catalog->protection_layer) + catalog->key_hash_size + strlen(hash_name) +
            strlen(BCREPO_CATALOG_BC_VERSION) + 1 +
            strlen(BCREPO_CATALOG_KEY_HASH_ALGO) + 1 +
            strlen(BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO) + 1 +
            strlen(BCREPO_CATALOG_KEY_HASH) + 1 +
            strlen(BCREPO_CATALOG_PROTECTION_LAYER) + 1 +
            strlen(BCREPO_CATALOG_FILES) + 1;

    hash_name = NULL;

    for (f = catalog->files; f != NULL; f = f->next) {
        size += f->data_size + 1 + strlen(f->timestamp) + 1;
    }

    return (size + 2);
}

static void dump_catalog_data(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    // INFO(Rafael): This function dumps to the out buffer the catalog data but it makes the position
    //               of each catalog field random, seeking to avoid the presence of cribs.
    struct bcrepo_dumper_ctx {
        const char *field;
        bcrepo_dumper dumper;
        int done;
    };
    struct bcrepo_dumper_ctx dumpers[] = {
        { BCREPO_CATALOG_BC_VERSION,              bc_version_w,              0 },
        { BCREPO_CATALOG_KEY_HASH_ALGO,           key_hash_algo_w,           0 },
        { BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO, protlayer_key_hash_algo_w, 0 },
        { BCREPO_CATALOG_KEY_HASH,                key_hash_w,                0 },
        { BCREPO_CATALOG_PROTECTION_LAYER,        protection_layer_w,        0 },
        { BCREPO_CATALOG_FILES,                   files_w,                   0 }
    };
    size_t dumpers_nr = sizeof(dumpers) / sizeof(dumpers[0]), d;
    kryptos_u8_t *o;
#define all_dump_done(d) ( (d)[0].done && (d)[1].done && (d)[2].done && (d)[3].done && (d)[4].done && (d)[5].done )

    o = out;

    while (all_dump_done(dumpers)) {
        d = kryptos_get_random_byte() % dumpers_nr;

        if (dumpers[d].done) {
            // INFO(Rafael): This is a little bit inefficient but for the sake of paranoia is better.
            continue;
        }

        o = dumpers[d].dumper(o, out_size, catalog);

        dumpers[d].done = 1;
    }

#undef all_dump_done
}

static kryptos_u8_t *bc_version_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    size = strlen(BCREPO_CATALOG_BC_VERSION);
    memcpy(out, BCREPO_CATALOG_BC_VERSION, size);
    out += size;
    size = strlen(catalog->bc_version);
    memcpy(out, catalog->bc_version, size);
    out += size;
    *out = '\n';
    return (out + 1);
}

static kryptos_u8_t *key_hash_algo_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    const char *hash;
    size = strlen(BCREPO_CATALOG_KEY_HASH_ALGO);
    memcpy(out, BCREPO_CATALOG_KEY_HASH_ALGO, size);
    out += size;
    hash = get_hash_processor_name(catalog->key_hash_algo);
    size = strlen(hash);
    memcpy(out, hash, size);
    out += size;
    *out = '\n';
    return (out + 1);
}

static kryptos_u8_t *protlayer_key_hash_algo_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    const char *hash;
    size = strlen(BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO);
    memcpy(out, BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO, size);
    out += size;
    hash = get_hash_processor_name(catalog->protlayer_key_hash_algo);
    size = strlen(hash);
    memcpy(out, hash, size);
    out += size;
    *out = '\n';
    return (out + 1);
}

static kryptos_u8_t *key_hash_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    const char *hash;
    size = strlen(BCREPO_CATALOG_KEY_HASH);
    memcpy(out, BCREPO_CATALOG_KEY_HASH, size);
    out += size;
    size = catalog->key_hash_size;
    memcpy(out, catalog->key_hash, size);
    out += size;
    *out = '\n';
    return (out + 1);
}

static kryptos_u8_t *protection_layer_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    const char *hash;
    size = strlen(BCREPO_CATALOG_PROTECTION_LAYER);
    memcpy(out, BCREPO_CATALOG_PROTECTION_LAYER, size);
    out += size;
    size = strlen(catalog->protection_layer);
    memcpy(out, catalog->protection_layer, size);
    out += size;
    *out = '\n';
    return (out + 1);
}

static kryptos_u8_t *files_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    kryptos_u8_t *o;
    bfs_catalog_relpath_ctx *f;
    size_t size;

    o = out;

    size = strlen(BCREPO_CATALOG_FILES);
    memcpy(o, BCREPO_CATALOG_FILES, size);
    o += size;
    *o = '\n';
    o += 1;

    for (f = catalog->files; f != NULL; f = f->next) {
        size = f->data_size;
        memcpy(o, f->data, size);
        o += size;

        *o = ',';
        o += 1;

        *o = (kryptos_u8_t)f->status;
        o += 1;

        size = strlen(f->timestamp);
        memcpy(o, f->timestamp, size);
        o += size;

        *o = '\n';
        o += 1;
    }

    *o = '\n';

    return (o + 1);
}

#undef BCREPO_CATALOG_BC_VERSION
#undef BCREPO_CATALOG_KEY_HASH_ALGO
#undef BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO
#undef BCREPO_CATALOG_KEY_HASH
#undef BCREPO_CATALOG_PROTECTION_LAYER
#undef BCREPO_CATALOG_FILES

#undef BCREPO_PEM_HMAC_HDR
#undef BCREPO_PEM_CATALOG_DATA_HDR

