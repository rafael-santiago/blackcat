/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <fs/bcrepo/bcrepo.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/processor.h>
#include <keychain/keychain.h>
#include <ctx/ctx.h>
#include <fs/ctx/fsctx.h>
#include <fs/strglob.h>
#include <dev/defs/io.h>
#include <dev/defs/types.h>
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define BCREPO_CATALOG_BC_VERSION               "bc-version: "
#define BCREPO_CATALOG_KEY_HASH_ALGO            "key-hash-algo: "
#define BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO  "protlayer-key-hash-algo: "
#define BCREPO_CATALOG_KEY_HASH                 "key-hash: "
#define BCREPO_CATALOG_PROTECTION_LAYER         "protection-layer: "
#define BCREPO_CATALOG_FILES                    "files: "

#define BCREPO_PEM_KEY_HASH_ALGO_HDR "BCREPO KEY HASH ALGO"
#define BCREPO_PEM_HMAC_HDR "BCREPO HMAC SCHEME"
#define BCREPO_PEM_CATALOG_DATA_HDR "BCREPO CATALOG DATA"
#define BCREPO_PEM_ENCODER_HDR "BCREPO ENCODER"

#define BCREPO_HIDDEN_DIR ".bcrepo"
#define BCREPO_HIDDEN_DIR_SIZE 7
#define BCREPO_CATALOG_FILE "CATALOG"
#define BCREPO_CATALOG_FILE_SIZE 7

#define BCREPO_RECUR_LEVEL_LIMIT 1024

#define BLACKCAT_DEVPATH "/dev/" CDEVNAME

typedef kryptos_u8_t *(*bcrepo_dumper)(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

typedef int (*bcrepo_reader)(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static size_t eval_catalog_buf_size(const bfs_catalog_ctx *catalog);

static void dump_catalog_data(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *bc_version_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *key_hash_algo_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *protlayer_key_hash_algo_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *key_hash_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *protection_layer_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *files_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_task_result_t decrypt_catalog_data(kryptos_u8_t **data, size_t *data_size,
                                                  const kryptos_u8_t *key, const size_t key_size,
                                                  bfs_catalog_ctx *catalog);

static kryptos_task_result_t encrypt_catalog_data(kryptos_u8_t **data, size_t *data_size,
                                                  const kryptos_u8_t *key, const size_t key_size,
                                                  bfs_catalog_ctx *catalog);

static int bc_version_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int key_hash_algo_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int protlayer_key_hash_algo_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int key_hash_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int protection_layer_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int files_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int read_catalog_data(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static kryptos_u8_t *get_catalog_field(const char *field, const kryptos_u8_t *in, const size_t in_size);

static int root_dir_reached(const char *cwd);

static void get_file_list(bfs_catalog_relpath_ctx **files, bfs_catalog_relpath_ctx *dest_files,
                          const char *rootpath, const size_t rootpath_size,
                          const char *pattern, const size_t pattern_size, int *recur_level, const int recur_max_level);

static int unl_handle_encrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              bfs_file_status_t *f_st);

static int unl_handle_decrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              bfs_file_status_t *f_st);

typedef int (*unl_processor)(const char *rootpath, const size_t rootpath_size,
                             const char *path, const size_t path_size,
                             const blackcat_protlayer_chain_ctx *protlayer,
                             bfs_file_status_t *f_st);

typedef kryptos_u8_t *(*blackcat_data_processor)(const blackcat_protlayer_chain_ctx *protlayer,
                                                 kryptos_u8_t *in, size_t in_size, size_t *out_size);

static int unl_handle_meta_proc(const char *rootpath, const size_t rootpath_size,
                                const char *path, const size_t path_size,
                                const blackcat_protlayer_chain_ctx *protlayer, blackcat_data_processor dproc);

static int unl_handle(bfs_catalog_ctx **catalog,
                      const char *rootpath, const size_t rootpath_size,
                      const char *pattern, const size_t pattern_size, unl_processor proc);

static kryptos_u8_t *bcrepo_read_file_data(const char *rootpath, const size_t rootpath_size,
                                           const char *path, const size_t path_size, size_t *size);

static int bcrepo_write_file_data(const char *rootpath, const size_t rootpath_size,
                                  const char *path, const size_t path_size, const kryptos_u8_t *data, const size_t data_size);

static size_t bcrepo_mkpath(char *path, const size_t path_size,
                            const char *root, const size_t root_size, const char *sub, const size_t sub_size);

static int bfs_data_wiping(const char *rootpath, const size_t rootpath_size,
                           const char *path, const size_t path_size, const size_t data_size);

static void bcrepo_seed_to_hex(char *buf, const size_t buf_size, const kryptos_u8_t *seed, const size_t seed_size);

static void bcrepo_hex_to_seed(kryptos_u8_t **seed, size_t *seed_size, const char *buf, const size_t buf_size);

char *remove_go_ups_from_path(char *path, const size_t path_size);

static kryptos_u8_t *random_printable_padding(size_t *size);

static int bcrepo_mkdtree(const char *dirtree);

static int do_ioctl(unsigned long cmd, const char *path, const size_t path_size);

static int bdup_handler(unsigned long cmd,
                 bfs_catalog_ctx **catalog,
                 const char *rootpath, const size_t rootpath_size,
                 const char *pattern, const size_t pattern_size);

static int bdup_handler(unsigned long cmd,
                 bfs_catalog_ctx **catalog,
                 const char *rootpath, const size_t rootpath_size,
                 const char *pattern, const size_t pattern_size) {
    int count = 0;
    bfs_catalog_ctx *cp = *catalog;
    bfs_catalog_relpath_ctx *fp;

    if (cp == NULL) {
        return 0;
    }

    for (fp = cp->files; fp != NULL; fp = fp->next) {
        if (pattern == NULL || strglob(fp->path, pattern) == 1) {
            if (do_ioctl(cmd, fp->path, fp->path_size) == 0) {
                count += 1;
            } else {
                perror("do_ioctl()");
            }
        }
    }

    return count;
}

int bcrepo_bury(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return bdup_handler(BLACKCAT_BURY, catalog, rootpath, rootpath_size, pattern, pattern_size);
}

int bcrepo_dig_up(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return bdup_handler(BLACKCAT_DIG_UP, catalog, rootpath, rootpath_size, pattern, pattern_size);
}

int bcrepo_reset_repo_settings(bfs_catalog_ctx **catalog,
                               const char *rootpath, const size_t rootpath_size,
                               kryptos_u8_t *catalog_key, const size_t catalog_key_size,
                               kryptos_u8_t **protlayer_key, size_t *protlayer_key_size,
                               const char *protection_layer,
                               blackcat_hash_processor catalog_hash_proc,
                               blackcat_hash_processor key_hash_proc,
                               blackcat_hash_processor protlayer_hash_proc,
                               blackcat_encoder encoder) {
    bfs_catalog_ctx *cp = *catalog;
    kryptos_task_ctx t, *ktask = &t;
    char filepath[4096];
    int no_error = 1;
    size_t temp_size;

    bcrepo_unlock(catalog, rootpath, rootpath_size, "*", 1);

    cp->catalog_key_hash_algo = catalog_hash_proc;
    cp->key_hash_algo = key_hash_proc;
    cp->key_hash_algo_size = get_hash_size(get_hash_processor_name(key_hash_proc));

    kryptos_task_init_as_null(ktask);

    ktask->in = *protlayer_key;
    ktask->in_size = *protlayer_key_size;

    cp->key_hash_algo(&ktask, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        fprintf(stderr, "ERROR: While trying to hash the user key.\n");
        no_error = 0;
        goto bcrepo_reset_repo_settings_epilogue;
    }

    kryptos_freeseg(cp->key_hash, cp->key_hash_size);

    cp->key_hash = ktask->out;
    cp->key_hash_size = ktask->out_size;

    ktask->in = ktask->out = NULL;
    ktask->in_size = ktask->out_size = 0;

    cp->protlayer_key_hash_algo = protlayer_hash_proc;
    cp->protlayer_key_hash_algo_size = get_hash_size(get_hash_processor_name(protlayer_hash_proc));

    cp->encoder = encoder;

    if (protection_layer != NULL) {
        temp_size = strlen(protection_layer);
        cp->protection_layer = (char *)kryptos_newseg(temp_size + 1);

        if (cp->protection_layer == NULL) {
            no_error = 0;
            fprintf(stderr, "ERROR: Not enough memory.\n");
            goto bcrepo_reset_repo_settings_epilogue;
        }

        memset(cp->protection_layer, 0, temp_size + 1);
        memcpy(cp->protection_layer, protection_layer, temp_size);
        temp_size = 0;

        if (cp->protlayer != NULL) {
            del_protlayer_chain_ctx(cp->protlayer);
            cp->protlayer = NULL;
        }

        cp->protlayer = add_composite_protlayer_to_chain(cp->protlayer, cp->protection_layer,
                                                         protlayer_key, protlayer_key_size,
                                                         protlayer_hash_proc, cp->encoder);

        if (cp->protlayer == NULL) {
            fprintf(stderr, "ERROR: While reconstructing the protection layer.\n");
            no_error = 0;
            goto bcrepo_reset_repo_settings_epilogue;
        }
    }

    bcrepo_lock(catalog, rootpath, rootpath_size, "*", 1);

    bcrepo_mkpath(filepath, sizeof(filepath),
                  BCREPO_HIDDEN_DIR, BCREPO_HIDDEN_DIR_SIZE,
                  BCREPO_CATALOG_FILE, BCREPO_CATALOG_FILE_SIZE);

    if ((no_error = bcrepo_write(filepath, cp, catalog_key, catalog_key_size)) != 1) {
        fprintf(stderr, "ERROR: While writing the repo new settings.\n");
        goto bcrepo_reset_repo_settings_epilogue;
    }

bcrepo_reset_repo_settings_epilogue:

    if (no_error == 0) {
        // INFO(Rafael): Trying do not to let unencrypted files. However, it could happen depending on when the failure has
        //               occurred.
        bcrepo_lock(catalog, rootpath, rootpath_size, "*", 1);
    }

    memset(catalog_key, 0, catalog_key_size);

    return no_error;
}

int bcrepo_pack(bfs_catalog_ctx **catalog, const char *rootpath, const size_t rootpath_size,
                             const char *wpath) {
    bfs_catalog_relpath_ctx *fp = NULL;
    bfs_catalog_ctx *cp = *catalog;
    FILE *wp = NULL, *wpp = NULL;
    int no_error = 1;
    char filepath[4096];
    kryptos_u8_t *data = NULL;
    size_t data_size = 0;

    bcrepo_lock(catalog, rootpath, rootpath_size, "*", 1);

    if ((wp = fopen(wpath, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to create the file '%s'.\n", wpath);
        no_error = 0;
        goto bcrepo_roll_ball_of_wool_epilogue;
    }

#define roll_data(filepath, curr_path, wp, wpp, data, data_size, no_error) {\
    if ((wpp = fopen(filepath, "rb")) == NULL) {\
        fprintf(stderr, "ERROR: Uanble to read the file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_roll_ball_of_wool_epilogue;\
    }\
    fseek(wpp, 0L, SEEK_END);\
    data_size = (size_t) ftell(wpp);\
    fseek(wpp, 0L, SEEK_SET);\
    if ((data = (kryptos_u8_t *) kryptos_newseg(data_size)) == NULL) {\
        fprintf(stderr, "ERROR: Not enough memory.\n");\
        no_error = 0;\
        goto bcrepo_roll_ball_of_wool_epilogue;\
    }\
    if (fread(data, 1, data_size, wpp) == -1) {\
        fprintf(stderr, "ERROR: Unable to read data from file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_roll_ball_of_wool_epilogue;\
    }\
    fclose(wpp);\
    wpp = NULL;\
    fprintf(wp, "%s,%d\n", curr_path, data_size);\
    if (fwrite(data, 1, data_size, wp) == -1) {\
        fprintf(stderr, "ERROR: Unable to write data to file '%s'.\n", wpath);\
        no_error = 0;\
        goto bcrepo_roll_ball_of_wool_epilogue;\
    }\
    kryptos_freeseg(data, data_size);\
    data = NULL;\
}

    bcrepo_catalog_file(filepath, sizeof(filepath) - 1, rootpath);

    roll_data(filepath, BCREPO_HIDDEN_DIR "/" BCREPO_CATALOG_FILE, wp, wpp, data, data_size, no_error)

    for (fp = cp->files; fp != NULL; fp = fp->next) {
        bcrepo_mkpath(filepath, sizeof(filepath) - 1, rootpath, rootpath_size, fp->path, fp->path_size);
        roll_data(filepath, fp->path, wp, wpp, data, data_size, no_error)
    }

#undef roll_data

    fclose(wp);
    wp = NULL;

bcrepo_roll_ball_of_wool_epilogue:

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
        data_size = 0;
    }

    if (wpp != NULL) {
        fclose(wpp);
    }

    if (wp != NULL) {
        fclose(wp);
        remove(wpath);
    }

    cp = NULL;

    return no_error;
}

int bcrepo_unpack(const char *wpath, const char *rootpath) {
    int no_error = 1;
    FILE *wool = NULL;
    kryptos_u8_t *data = NULL, *wp_data = NULL, *wp = NULL, *wp_end = NULL, *off = NULL;
    size_t data_size = 0, wp_data_size = 0;
    char filepath[4096], temp[4096], oldcwd[4096], *rp = NULL;

    if ((rp = bcrepo_get_rootpath()) != NULL) {
        fprintf(stderr, "ERROR: Your are inside a previosly initialized repo.\n");
        no_error = 0;
        goto bcrepo_unroll_ball_of_wool_epilogue;
    }

    if ((wool = fopen(wpath, "rb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to read the file '%s'.\n", wpath);
        no_error = 0;
        goto bcrepo_unroll_ball_of_wool_epilogue;
    }

    fseek(wool, 0L, SEEK_END);
    wp_data_size = ftell(wool);
    fseek(wool, 0L, SEEK_SET);

    if ((wp_data = (kryptos_u8_t *) kryptos_newseg(wp_data_size)) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        no_error = 0;
        wp_data_size = 0;
        goto bcrepo_unroll_ball_of_wool_epilogue;
    }

    if (fread(wp_data, 1, wp_data_size, wool) == -1) {
        fprintf(stderr, "ERROR: Unable to read data from file '%s'.\n", wpath);
        no_error = 0;
        goto bcrepo_unroll_ball_of_wool_epilogue;
    }

    fclose(wool);
    wool = NULL;

    if (rootpath != NULL) {
        if (bcrepo_mkdtree(rootpath) != 0) { 
            fprintf(stderr, "ERROR: Unable to create the directory path '%s'.\n", rootpath);
            no_error = 0;
            goto bcrepo_unroll_ball_of_wool_epilogue;
        }
        getcwd(oldcwd, sizeof(oldcwd) - 1);
        if (chdir(rootpath) != 0) {
            fprintf(stderr, "ERROR: Unable to change the current work directory.");\
            no_error = 0;
            goto bcrepo_unroll_ball_of_wool_epilogue;
        }
    }

#define unroll_data(wp, wp_end, filepath, filepath_size, data, data_size, off, temp, temp_size, fp) {\
    off = wp;\
    while (wp != wp_end && *wp != ',') {\
        wp++;\
    }\
    memset(filepath, 0, filepath_size);\
    memcpy(filepath, off, wp - off);\
    wp += 1;\
    if (wp == wp_end) {\
        no_error = 0;\
        fprintf(stderr, "ERROR: Not enough data.\n");\
        goto bcrepo_unroll_ball_of_wool_epilogue;\
    }\
    off = wp;\
    while (wp != wp_end && *wp != '\n') {\
        wp++;\
    }\
    memset(temp, 0, temp_size);\
    memcpy(temp, off, wp - off);\
    data_size = atoi(temp);\
    wp += 1;\
    if ((data = (kryptos_u8_t *)kryptos_newseg(data_size)) == NULL) {\
        no_error = 0;\
        fprintf(stderr, "ERROR: Not enough memory.\n");\
        goto bcrepo_unroll_ball_of_wool_epilogue;\
    }\
    memcpy(data, wp, data_size);\
    wp += data_size;\
    off = &filepath[strlen(filepath) - 1];\
    while (off != (kryptos_u8_t *)&filepath[0] && *off != '/') {\
        off--;\
    }\
    if ((off - (kryptos_u8_t *)&filepath[0]) > 0) {\
        memset(temp, 0, temp_size);\
        memcpy(temp, filepath, off - (kryptos_u8_t *)&filepath[0]);\
        if (bcrepo_mkdtree(temp) != 0) {\
            fprintf(stderr, "ERROR: Unable to create the directory path '%s'.\n", temp);\
            no_error = 0;\
            goto bcrepo_unroll_ball_of_wool_epilogue;\
        }\
    }\
    if ((fp = fopen(filepath, "wb")) == NULL) {\
        fprintf(stderr, "ERROR: Unable to create the file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_unroll_ball_of_wool_epilogue;\
    }\
    if (fwrite(data, 1, data_size, fp) == -1) {\
        fprintf(stderr, "ERROR: Unable to dump data to file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_unroll_ball_of_wool_epilogue;\
    }\
    fclose(fp);\
    fp = NULL;\
    kryptos_freeseg(data, data_size);\
    data = NULL;\
}

    wp = wp_data;
    wp_end = wp + wp_data_size;

    while (wp < wp_end) {
        unroll_data(wp, wp_end, filepath, sizeof(filepath), data, data_size, off, temp, sizeof(temp), wool)
    }

#undef unroll_data

bcrepo_unroll_ball_of_wool_epilogue:

    if (rp != NULL) {
        kryptos_freeseg(rp, strlen(rp));
    }

    if (rootpath != NULL) {
        chdir(oldcwd);
    }

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
        data_size = 0;
    }

    if (wp_data != NULL) {
        kryptos_freeseg(wp_data, wp_data_size);
        wp_data_size = 0;
    }

    if (wool != NULL)  {
        fclose(wool);
    }

    return no_error;
}

static int do_ioctl(unsigned long cmd, const char *path, const size_t path_size) {
    int dev;
    int err = 0;
    const char *rp, *rp_end;

    if ((dev = open(BLACKCAT_DEVPATH, O_WRONLY)) == -1) {
        return ENODEV;
    }

    rp = path;
    rp_end = path + path_size;

    while (rp_end != rp && *rp_end != '/') {
        rp_end--;
    }

    err = ioctl(dev, cmd, rp_end + (*rp_end == '/'));

    close(dev);

    return err;
}

static int bcrepo_mkdtree(const char *dirtree) {
    mode_t oldmask;
    const char *d, *d_end, *s;
    char dir[4096];
    char oldcwd[4096];
    int exit_code = 0;
    struct stat st;

    if (stat(dirtree, &st) == 0) {
        if (st.st_mode != S_IFDIR) {
            return 0;
        }
        return 1;
    }

    oldmask = umask(0);

    getcwd(oldcwd, sizeof(oldcwd) - 1);

    d = dirtree;
    d_end = d + strlen(d);

    do {
        s = d;
        while (d != d_end && *d != '/') {
            d++;
        }

        memset(dir, 0, sizeof(dir));
        memcpy(dir, s, d - s);

        exit_code = mkdir(dir, 0644);

        if (exit_code == 0) {
            exit_code = chdir(dir);
            d++;
        }
    } while (d < d_end && exit_code == 0);

    umask(oldmask);
    chdir(oldcwd);

    return exit_code;
}

char *bcrepo_catalog_file(char *buf, const size_t buf_size, const char *rootpath) {
    if (rootpath == NULL || buf == NULL || buf_size == 0) {
        return buf;
    }
    memset(buf, 0, buf_size);
    if ((strlen(rootpath) + BCREPO_HIDDEN_DIR_SIZE + BCREPO_CATALOG_FILE_SIZE) >= buf_size - 1) {
        return buf;
    }
    sprintf(buf, "%s/%s/%s", rootpath, BCREPO_HIDDEN_DIR, BCREPO_CATALOG_FILE);
    return buf;
}

int bcrepo_init(bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size) {
    char *rootpath = NULL;
    int no_error = 1;
    char filepath[4096];
    mode_t oldmask;

    oldmask = umask(0);

    if (catalog == NULL || key == NULL || key_size == 0) {
        no_error = 0;
        goto bcrepo_init_epilogue;
    }

    rootpath = bcrepo_get_rootpath();

    if (rootpath != NULL) {
        no_error = 0;
        fprintf(stderr, "ERROR: It seems to be previously initialized at '%s'.\n", rootpath);
        goto bcrepo_init_epilogue;
    }

    if (mkdir(BCREPO_HIDDEN_DIR, 0644) != 0) {
        no_error = 0;
        fprintf(stderr, "ERROR: Unable to initialize the current working directory as a blackcat repo.\n");
        goto bcrepo_init_epilogue;
    }

    bcrepo_mkpath(filepath, sizeof(filepath),
                  BCREPO_HIDDEN_DIR, BCREPO_HIDDEN_DIR_SIZE,
                  BCREPO_CATALOG_FILE, BCREPO_CATALOG_FILE_SIZE);

    no_error = bcrepo_write(filepath, catalog, key, key_size);

bcrepo_init_epilogue:

    umask(oldmask);

    if (rootpath != NULL) {
        kryptos_freeseg(rootpath, strlen(rootpath));
    }

    return no_error;
}

int bcrepo_deinit(const char *rootpath, const size_t rootpath_size, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_u8_t *data = NULL;
    size_t data_size = 0, temp_size;
    bfs_catalog_ctx *catalog = NULL;
    int no_error = 1;
    char filepath[4096], tmp[4096];
    size_t filepath_size;

    if (rootpath == NULL || rootpath_size == 0 || key == NULL || key_size == 0) {
        no_error = 0;
        goto bcrepo_deinit_epilogue;
    }

    catalog = new_bfs_catalog_ctx();

    if (catalog == NULL) {
        no_error = 0;
        fprintf(stderr, "ERROR: Not enough memory!\n");
        goto bcrepo_deinit_epilogue;
    }

    if ((rootpath_size + BCREPO_HIDDEN_DIR_SIZE + BCREPO_CATALOG_FILE_SIZE) >= sizeof(filepath)) {
        no_error = 0;
        fprintf(stderr, "ERROR: The catalog file path is too long.\n");
        goto bcrepo_deinit_epilogue;
    }

    data_size = bcrepo_mkpath(tmp, sizeof(tmp), rootpath, rootpath_size, BCREPO_HIDDEN_DIR, BCREPO_HIDDEN_DIR_SIZE);
    filepath_size = bcrepo_mkpath(filepath, sizeof(filepath), tmp, data_size, BCREPO_CATALOG_FILE, BCREPO_CATALOG_FILE_SIZE);

    data = bcrepo_read(filepath, catalog, &data_size);

    if (data == NULL) {
        no_error = 0;
        goto bcrepo_deinit_epilogue;
    }

    temp_size = data_size;

    if ((no_error = bcrepo_stat(&catalog, key, key_size, &data, &data_size)) != 1) {
        goto bcrepo_deinit_epilogue;
    }

    // WARN(Rafael): We cannot perform data wiping before the bcrepo_stat(), otherwise a wrong key will be able to
    //               corrupt the entire repository's catalog without concluding the deinit stuff.

    if (bfs_data_wiping(rootpath, rootpath_size,
                        filepath + rootpath_size + 1, filepath_size - rootpath_size + 1, temp_size) == 0) {
        fprintf(stderr, "WARN: Unable to perform data wiping over the file '%s'\n", filepath);
        fprintf(stderr, "      If you are paranoid enough you should run a data wiping software"
                        " over your entire storage device.\n");
    }

    temp_size = 0;

    if (remove(filepath) != 0) {
        no_error = 0;
        fprintf(stderr, "ERROR: Unable to remove the file '%s'.\n", filepath);
        goto bcrepo_deinit_epilogue;
    }

    bcrepo_mkpath(filepath, sizeof(filepath), rootpath, rootpath_size, BCREPO_HIDDEN_DIR, BCREPO_HIDDEN_DIR_SIZE);

    if (rmdir(filepath) != 0) {
        no_error = 0;
        fprintf(stderr, "ERROR: Unable to remove the directory '%s'.\n", filepath);
        goto bcrepo_deinit_epilogue;
    }

bcrepo_deinit_epilogue:

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
        data_size = 0;
    }

    if (catalog != NULL) {
        del_bfs_catalog_ctx(catalog);
    }

    return no_error;
}

int bcrepo_lock(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return unl_handle(catalog, rootpath, rootpath_size, pattern, pattern_size, unl_handle_encrypt);
}


int bcrepo_unlock(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return unl_handle(catalog, rootpath, rootpath_size, pattern, pattern_size, unl_handle_decrypt);
}

int bcrepo_rm(bfs_catalog_ctx **catalog,
              const char *rootpath, const size_t rootpath_size,
              const char *pattern, const size_t pattern_size, const int force) {
    int rm_nr = 0;
    bfs_catalog_relpath_ctx *files = NULL, *fp, *fpp;
    bfs_catalog_ctx *cp;
    int rl = 0;

    if (catalog == NULL) {
        goto bcrepo_rm_epilogue;
    }

    cp = *catalog;

    get_file_list(&files, NULL, rootpath, rootpath_size, pattern, pattern_size, &rl, BCREPO_RECUR_LEVEL_LIMIT);

    for (fp = files; fp != NULL; fp = fp->next) {
        if ((fpp = get_entry_from_relpath_ctx(cp->files, fp->path)) == NULL) {
            continue;
        }

        if (fpp->status == kBfsFileStatusLocked &&
            bcrepo_unlock(catalog, rootpath, rootpath_size, fpp->path, fpp->path_size) != 1) {
            fprintf(stderr, "WARN: Unable to unlock the file '%s'.\n", fpp->path);
        }

        cp->files = del_file_from_relpath_ctx(cp->files, fpp->path);

        rm_nr++;
    }

    if (force) {
        if (get_entry_from_relpath_ctx(cp->files, pattern) != NULL) {
            cp->files = del_file_from_relpath_ctx(cp->files, pattern);
            rm_nr++;
        }
    }

bcrepo_rm_epilogue:

    if (files != NULL) {
        del_bfs_catalog_relpath_ctx(files);
    }

    return rm_nr;
}

int bcrepo_add(bfs_catalog_ctx **catalog,
               const char *rootpath, const size_t rootpath_size,
               const char *pattern, const size_t pattern_size, const int plain) {
    int add_nr = 0;
    bfs_catalog_relpath_ctx *files = NULL, *fp;
    bfs_catalog_ctx *cp;
    int rl = 0;

    if (catalog == NULL) {
        goto bcrepo_add_epilogue;
    }

    cp = *catalog;

    get_file_list(&files, cp->files, rootpath, rootpath_size, pattern, pattern_size, &rl, BCREPO_RECUR_LEVEL_LIMIT);

    for (fp = files; fp != NULL; fp = fp->next) {
        cp->files = add_file_to_relpath_ctx(cp->files,
                                            fp->path, fp->path_size,
                                            (!plain) ? kBfsFileStatusUnlocked : kBfsFileStatusPlain, fp->timestamp);
        add_nr++;
    }

bcrepo_add_epilogue:

    if (files != NULL) {
        del_bfs_catalog_relpath_ctx(files);
    }

    return add_nr;
}

static int bcrepo_write_file_data(const char *rootpath, const size_t rootpath_size,
                                  const char *path, const size_t path_size, const kryptos_u8_t *data, const size_t data_size) {
    int no_error = 1;
    char fullpath[4096];
    FILE *fp = NULL;

    if ((rootpath_size + path_size + 3) >= sizeof(fullpath) - 1) {
        fprintf(stderr, "ERROR: The path is too long ('%s').\n", path);
        no_error = 0;
        goto bcrepo_write_file_data_epilogue;
    }

    bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, path, path_size);

    if ((fp = fopen(fullpath, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to write the file '%s'.\n", fullpath);
        no_error = 0;
        goto bcrepo_write_file_data_epilogue;
    }

    if (fwrite(data, 1, data_size, fp) == -1) {
        fprintf(stderr, "ERROR: Unable to dump data to the file '%s'.\n", fullpath);
        no_error = 0;
    }

bcrepo_write_file_data_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    memset(fullpath, 0, sizeof(fullpath));

    return no_error;
}

static kryptos_u8_t *bcrepo_read_file_data(const char *rootpath, const size_t rootpath_size,
                                           const char *path, const size_t path_size, size_t *size) {
    FILE *fp = NULL;
    kryptos_u8_t *data = NULL;
    char fullpath[4096];

    if ((rootpath_size + path_size + 3) >= sizeof(fullpath) - 1) {
        fprintf(stderr, "ERROR: The path is too long ('%s').\n", path);
        *size = 0;
        goto bcrepo_read_file_data_epilogue;
    }

    bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, path, path_size);

    if ((fp = fopen(fullpath, "rb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to read the file '%s'.\n", fullpath);
        *size = 0;
        goto bcrepo_read_file_data_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    *size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    data = (kryptos_u8_t *) kryptos_newseg(*size);

    if (data == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to read the file '%s'.\n", path);
        *size = 0;
        goto bcrepo_read_file_data_epilogue;
    }

    fread(data, 1, *size, fp);

bcrepo_read_file_data_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    memset(fullpath, 0, sizeof(fullpath));

    return data;
}

static int unl_handle_meta_proc(const char *rootpath, const size_t rootpath_size,
                                const char *path, const size_t path_size,
                                const blackcat_protlayer_chain_ctx *protlayer, blackcat_data_processor dproc) {
    int no_error = 1, ntry;
    kryptos_u8_t *in = NULL, *out = NULL;
    size_t in_size = 0, out_size;

    in = bcrepo_read_file_data(rootpath, rootpath_size, path, path_size, &in_size);

    if (in == NULL) {
        no_error = 0;
        goto unl_handle_meta_proc_epilogue;
    }

    if (dproc == blackcat_encrypt_data) {
        // INFO(Rafael): Let's to apply some data wiping over the plain data laying on the current file system
        //               before encrypting it.
        ntry = 10;

        while ((no_error = bfs_data_wiping(rootpath, rootpath_size, path, path_size, in_size)) == 0 && ntry-- > 0)
            ;

        if (ntry == 0 && no_error == 0) {
            goto unl_handle_meta_proc_epilogue;
        }
    }

    out = dproc(protlayer, in, in_size, &out_size);

    if (out == NULL) {
        no_error = 0;
        goto unl_handle_meta_proc_epilogue;
    }

    no_error = bcrepo_write_file_data(rootpath, rootpath_size, path, path_size, out, out_size);

unl_handle_meta_proc_epilogue:

    if (in != NULL) {
        kryptos_freeseg(in, in_size);
        in_size = 0;
    }

    if (out != NULL) {
        kryptos_freeseg(out, out_size);
        out_size = 0;
    }

    return no_error;
}

static int bfs_data_wiping(const char *rootpath, const size_t rootpath_size,
                           const char *path, const size_t path_size, const size_t data_size) {
    // WARN(Rafael): This ***is not*** a silver bullet because it depends on the current filesystem (and device) in use.
    //               What optimizations it brings and what heuristics it takes advantage to work on.
    //               Anyway, I am following the basic idea of the DoD standard. Here we do not want to
    //               erase every single trace of the related file. Only its content data is relevant.
    //               Inode infos such as file size, file name and other file metadata are (at first glance)
    //               negligible for an eavesdropper and us either.

    // TODO(Rafael): Try to find a way of removing thumbnails and things like that. If the user takes "advantage"
    //               this kind of disservices would be cool to protect she/he against her/his own naivety.
    char fullpath[4096];
    FILE *fp = NULL;
    kryptos_u8_t *data = NULL;
    int no_error = 1;

    bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, path, path_size);

#define bfs_data_wiping_bit_fliping_step(fn, f, d, ds, bp, ne, esc_text) {\
    if (((f) = fopen((fn), "wb")) == NULL) {\
        fprintf(stderr, "ERROR: Unable to open file '%s' for wiping.\n", (fn));\
        (ne) = 0;\
        goto esc_text;\
    }\
    memset((d), (bp), (ds));\
    if (fwrite((d), 1, (ds), (f)) == -1) {\
        fprintf(stderr, "ERROR: Unable to write data to the file '%s'. The data wiping was skipped!\n", (fn));\
        (ne) = 0;\
        goto esc_text;\
    }\
    if (fflush((f)) != 0) {\
        fprintf(stderr, "ERROR: Unable to write data to the file '%s'. The data wiping was skipped!\n", (fn));\
        (ne) = 0;\
        goto esc_text;\
    }\
    /*INFO(Rafael): Yes, we will flush it twice.*/\
    fclose((f));\
    (f) = NULL;\
}

#define bfs_data_wiping_paranoid_reverie_step(fn, d, ds, f, ne, esc_text) {\
    if (((f) = fopen((fn), "wb")) == NULL) {\
        fprintf(stderr, "ERROR: Unable to open file '%s' for wiping.\n", (fn));\
        (ne) = 0;\
        goto esc_text;\
    }\
    (d) =  kryptos_get_random_block((ds));\
    if ((d) == NULL) {\
        fprintf(stderr, "WARN: Not enough memory. The data wiping was incomplete!\n");\
        (ne) = 0;\
        goto esc_text;\
    }\
    if (fwrite((d), 1, (ds), (f)) == -1) {\
        fprintf(stderr, "WARN: Unable to write data to the file '%s'. The data wiping was incomplete!\n", (fn));\
        (ne) = 0;\
        goto esc_text;\
    }\
    if (fflush((f)) != 0) {\
        fprintf(stderr, "WARN: Unable to flush data to the file '%s'. The data wiping was incomplete!\n", (fn));\
        (ne) = 0;\
        goto esc_text;\
    }\
    /*INFO(Rafael): Yes, we will flush it twice.*/\
    fclose((f));\
    (f) = NULL;\
    kryptos_freeseg((d), (ds));\
    (d) = NULL;\
}

    data = (kryptos_u8_t *) kryptos_newseg(data_size);

    if (data == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to perform data wiping. It was skipped!\n");
        no_error = 0;
        goto bfs_data_wiping_epilogue;
    }

    bfs_data_wiping_bit_fliping_step(fullpath, fp, data, data_size, 255, no_error, bfs_data_wiping_epilogue);
    bfs_data_wiping_bit_fliping_step(fullpath, fp, data, data_size,   0, no_error, bfs_data_wiping_epilogue);

    kryptos_freeseg(data, data_size);
    data = NULL;

    // INFO(Rafael): This step of the implemented data wiping is based on the suggestions given by Bruce Schneier's
    //               in his book Applied Cryptography [228 pp.].

    bfs_data_wiping_paranoid_reverie_step(fullpath, data, data_size, fp, no_error, bfs_data_wiping_epilogue);
    bfs_data_wiping_paranoid_reverie_step(fullpath, data, data_size, fp, no_error, bfs_data_wiping_epilogue);
    bfs_data_wiping_paranoid_reverie_step(fullpath, data, data_size, fp, no_error, bfs_data_wiping_epilogue);
    bfs_data_wiping_paranoid_reverie_step(fullpath, data, data_size, fp, no_error, bfs_data_wiping_epilogue);
    bfs_data_wiping_paranoid_reverie_step(fullpath, data, data_size, fp, no_error, bfs_data_wiping_epilogue);

#undef bfs_data_wiping_bit_fliping_step
#undef bfs_data_wiping_paranoid_reverie_step

bfs_data_wiping_epilogue:

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    memset(fullpath, 0, sizeof(fullpath));

    return no_error;
}

static int unl_handle_encrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              bfs_file_status_t *f_st) {

    int no_error = unl_handle_meta_proc(rootpath, rootpath_size, path, path_size, protlayer, blackcat_encrypt_data);

    if (no_error) {
        *f_st = kBfsFileStatusLocked;
    }

    return no_error;
}

static int unl_handle_decrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              bfs_file_status_t *f_st) {

    int no_error = unl_handle_meta_proc(rootpath, rootpath_size, path, path_size, protlayer, blackcat_decrypt_data);

    if (no_error) {
        *f_st = kBfsFileStatusUnlocked;
    }

    return no_error;
}

static int unl_handle(bfs_catalog_ctx **catalog,
                      const char *rootpath, const size_t rootpath_size,
                      const char *pattern, const size_t pattern_size, unl_processor proc) {
    int proc_nr = 0;
    bfs_catalog_ctx *cp;
    bfs_catalog_relpath_ctx *files = NULL, *fp, *fpp;
    int rl = 0;

    if (catalog == NULL) {
        return 0;
    }

    cp = *catalog;

    if (pattern != NULL) {
        get_file_list(&files, NULL, rootpath, rootpath_size, pattern, pattern_size, &rl, BCREPO_RECUR_LEVEL_LIMIT);
    } else {
        files = cp->files;
    }

#define unl_fproc(file, p, protlayer, pstmt) {\
    if ((((p) == unl_handle_encrypt) && ((file) == NULL || (file)->status == kBfsFileStatusLocked   ||\
                                                           (file)->status == kBfsFileStatusPlain))  ||\
        (((p) == unl_handle_decrypt) && ((file) == NULL || (file)->status == kBfsFileStatusUnlocked ||\
                                                           (file)->status == kBfsFileStatusPlain))) {\
        continue;\
    }\
    if ((p) == unl_handle_encrypt) {\
        get_new_file_seed(&(file)->seed, &(file)->seed_size);\
    }\
    blackcat_xor_keychain_protkey(protlayer, (file)->seed, (file)->seed_size);\
    pstmt;\
    blackcat_xor_keychain_protkey(protlayer, (file)->seed, (file)->seed_size);\
}
    if (files != cp->files) {
        for (fp = files; fp != NULL; fp = fp->next) {
            fpp = get_entry_from_relpath_ctx(cp->files, fp->path);
            unl_fproc(fpp, proc, cp->protlayer, proc_nr += proc(rootpath,
                                                                rootpath_size,
                                                                fpp->path,
                                                                fpp->path_size,
                                                                cp->protlayer,
                                                                &fpp->status));
        }
    } else {
        for (fp = files; fp != NULL; fp = fp->next) {
            unl_fproc(fp, proc, cp->protlayer, proc_nr += proc(rootpath,
                                                               rootpath_size,
                                                               fp->path,
                                                               fp->path_size,
                                                               cp->protlayer,
                                                               &fp->status));
        }
    }

#undef unl_fproc

    if (files != NULL && files != cp->files) {
        del_bfs_catalog_relpath_ctx(files);
    }

    return proc_nr;
}

static size_t bcrepo_mkpath(char *path, const size_t path_size,
                          const char *root, const size_t root_size, const char *sub, const size_t sub_size) {
    char *p;
    const char *s, *t;
    size_t s_d = 0, subdir_size;
    char subdir[4096];
    if (path == NULL || root == NULL || sub == NULL) {
        return 0;
    }

    if ((root_size + sub_size + 1) >= path_size) {
        return 0;
    }

    memset(path, 0, path_size);

    p = path;

    memcpy(p, root, root_size);

    p += root_size;

    if (*(p - 1) != '/') {
        *(p) = '/';
        p += 1;
    }

    s = sub;

    if (*s == '/') {
        s++;
        s_d = 1;
    }

    // !-!--!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-+!
    // WARN(Rafael): This function take into consideration the possibility of having: 'a/b/c' and 'c/y.z' as parameters. |
    //               In this case, the resulting path will be 'a/b/c/y.z'. This function should not be used as a general !
    //               purpose 'path maker' function. Just use it inside this module.                                      |
    // !-!--!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-+!

    t = s + sub_size - s_d;

    while (t != s && *t != '/') {
        t--;
    }

    if (t > s) {
        memset(subdir, 0, sizeof(subdir));
        subdir_size = t - s;
        memcpy(subdir, s, subdir_size);
        if (subdir[subdir_size - 1] != '/') {
            subdir[subdir_size++] = '/';
        }
        t = strstr(path, subdir);
        if (t != NULL && *(t + subdir_size) == 0) {
            s += subdir_size;
            s_d += subdir_size;
        }
    }

    memcpy(p, s, sub_size - s_d);

    return strlen(path);
}

static void get_file_list(bfs_catalog_relpath_ctx **files, bfs_catalog_relpath_ctx *dest_files,
                          const char *rootpath, const size_t rootpath_size,
                          const char *pattern, const size_t pattern_size, int *recur_level, const int recur_max_level) {
    int matches;
    char *filepath = NULL, *fp = NULL, *fp_end = NULL, *glob = NULL, *filename;
    size_t filepath_size, glob_size, filename_size, cwd_size, tmp_size, filepath_delta_size;
    struct stat st;
    bfs_catalog_relpath_ctx *files_p;
    DIR *dirp = NULL;
    struct dirent *dt;
    char cwd[4096], tmp[4096];

    if (*recur_level > recur_max_level) {
        fprintf(stderr, "ERROR: get_file_list() recursiveness level limit hit.\n");
        goto get_file_list_epilogue;
    }

    if (files == NULL || rootpath == NULL || rootpath_size == 0 || pattern == NULL || pattern_size == 0) {
        goto get_file_list_epilogue;
    }

    memset(cwd, 0, sizeof(cwd));
    if (getcwd(cwd, sizeof(cwd) - 1) == NULL) {
        fprintf(stderr, "ERROR: Unable to get the current cwd.\n");
        goto get_file_list_epilogue;
    }

    if (strstr(cwd, rootpath) != &cwd[0]) {
        // INFO(Rafael): It should never happen in normal conditions.
        goto get_file_list_epilogue;
    }

    cwd_size = strlen(cwd);

    filepath_size = rootpath_size + cwd_size + pattern_size;
    filepath = (char *) kryptos_newseg(filepath_size + 4096);

    if (filepath == NULL) {
        fprintf(stderr, "ERROR: Unable to allocate memory!\n");
        goto get_file_list_epilogue;
    }

    tmp_size = bcrepo_mkpath(tmp, sizeof(tmp), rootpath, rootpath_size, cwd + rootpath_size, cwd_size - rootpath_size);
    filepath_size = bcrepo_mkpath(filepath, filepath_size + 2, tmp, tmp_size, pattern, pattern_size);

    if (strstr(filepath, "*") != NULL || strstr(filepath, "?") != NULL || strstr(filepath, "[") != NULL) {
        fp = filepath;
        fp_end = fp + filepath_size;

#ifndef _WIN32
        while (fp != fp_end && *fp_end != '/') {
            fp_end--;
        }

        *fp_end = 0;

        fp = fp_end + 1;
        fp_end = filepath + filepath_size;

        glob_size = fp_end - fp;
        glob = (char *) kryptos_newseg(glob_size + 1);

        if (glob == NULL) {
            fprintf(stderr, "ERROR: Unable to allocate memory!\n");
            goto get_file_list_epilogue;
        }

        memset(glob, 0, glob_size + 1);
        memcpy(glob, fp, glob_size);

        filepath = (char *) kryptos_realloc(filepath, 4096);

        if (filepath == NULL) {
            fprintf(stderr, "ERROR: Unable to allocate memory!\n");
            goto get_file_list_epilogue;
        }

        fp_end = filepath + 4095;

        for (fp = filepath; fp != fp_end && *fp != 0; fp++)
            ;
#else
# error Implement me... (__FILE__)
#endif
    }

    files_p = *files;

    if (stat(filepath, &st) == 0) {
        // INFO(Rafael): We are only interested in regular files and directories.
        if (st.st_mode & S_IFREG) {
            // INFO(Rafael): However, only regular files are really relevant for us.
            if (get_entry_from_relpath_ctx(dest_files, filepath + rootpath_size) == NULL) {
                files_p = add_file_to_relpath_ctx(files_p,
                                                  filepath + rootpath_size,
                                                  filepath_size - rootpath_size, kBfsFileStatusUnlocked, NULL);
            }
        } else if (st.st_mode & S_IFDIR) {
            if ((dirp = opendir(filepath)) == NULL) {
                fprintf(stderr, "ERROR: Unable to access '%s'.\n", filepath);
                goto get_file_list_epilogue;
            }

            memset(cwd, 0, sizeof(cwd));
            memcpy(cwd, filepath, filepath_size % sizeof(cwd));
            cwd_size = strlen(cwd);

            while ((dt = readdir(dirp)) != NULL) {
                filename = dt->d_name;

                if (strcmp(filename, ".") == 0 || strcmp(filename, BCREPO_HIDDEN_DIR) == 0 || strcmp(filename, "..") == 0) {
                    continue;
                }

                matches = (glob == NULL || *glob == 0 || strglob(filename, glob) == 1);

                if (!matches) {
                    continue;
                }

                filename_size = strlen(filename);

                //if ((fp + filename_size) >= fp_end) {
                //    fprintf(stderr, "WARN: The filename '%s' is too long. It was not added.\n", filename);
                //    continue;
                //}

                filepath_size = bcrepo_mkpath(filepath, 4096, cwd, cwd_size, filename, filename_size);

                *recur_level += 1;

                get_file_list(&files_p,
                              dest_files,
                              rootpath, rootpath_size,
                              filepath + rootpath_size, filepath_size - rootpath_size,
                              recur_level, recur_max_level);

                *recur_level -= 1;
            }
        }
    }

    (*files) = files_p;

get_file_list_epilogue:

    if (filepath != NULL) {
        kryptos_freeseg(filepath, strlen(filepath));
    }

    if (glob != NULL) {
        kryptos_freeseg(glob, 0);
    }

    if (dirp != NULL) {
        closedir(dirp);
    }
}

char *bcrepo_get_rootpath(void) {
    char oldcwd[4096], cwd[4096];
    DIR *dirp = NULL;
    char *rootpath = NULL;
    size_t rootpath_size;
    int recur_nr = 0;

    memset(oldcwd, 0, sizeof(oldcwd));
    getcwd(oldcwd, sizeof(oldcwd) - 1);

    memset(cwd, 0, sizeof(cwd));
    memcpy(cwd, oldcwd, sizeof(oldcwd) - 1);

    while ((dirp = opendir(BCREPO_HIDDEN_DIR)) == NULL && !root_dir_reached(cwd)) {
        chdir("..");
        recur_nr += 1;
        getcwd(cwd, sizeof(cwd));
    }

    if (recur_nr > 0) {
        chdir(oldcwd);
    }

    if (dirp != NULL) {
        rootpath_size = strlen(cwd);
        rootpath = (char *) kryptos_newseg(rootpath_size + 1);

        if (rootpath == NULL) {
            return NULL;
        }

        memset(rootpath, 0, rootpath_size + 1);
        memcpy(rootpath, cwd, rootpath_size);

        closedir(dirp);
    }

    return rootpath;
}

int bcrepo_validate_key(const bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size) {
    int is_valid = 0;
    kryptos_task_ctx t, *ktask = &t;

    if (catalog == NULL || key == NULL || key_size == 0 || catalog->key_hash_algo == NULL) {
        goto bcrepo_validate_key_epilogue;
    }

    kryptos_task_init_as_null(ktask);

    ktask->in = (kryptos_u8_t *)key;
    ktask->in_size = key_size;

    catalog->key_hash_algo(&ktask, 1);

    if (!kryptos_last_task_succeed(ktask)) {
        goto bcrepo_validate_key_epilogue;
    }

    is_valid = (ktask->out_size == catalog->key_hash_size &&
                    memcmp(ktask->out, catalog->key_hash, ktask->out_size) == 0);

bcrepo_validate_key_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return is_valid;
}

int bcrepo_write(const char *filepath, bfs_catalog_ctx *catalog, const kryptos_u8_t *key, const size_t key_size) {
    FILE *fp = NULL;
    int no_error = 1;
    size_t o_size;
    kryptos_u8_t *o = NULL;
    kryptos_u8_t *pem_buf = NULL;
    size_t pem_buf_size = 0;
    const char *key_hash_algo = NULL, *encoder = NULL;
    kryptos_u8_t *pfx = NULL, *sfx = NULL;
    size_t pfx_size, sfx_size;

    o_size = eval_catalog_buf_size(catalog);

    if (o_size == 0) {
        fprintf(stderr, "ERROR: Nothing to be written.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    pfx = random_printable_padding(&pfx_size);

    if (pfx == NULL || pfx_size == 0) {
        fprintf(stderr, "ERROR: Unable to generate the random bytes.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    sfx = random_printable_padding(&sfx_size);

    if (sfx == NULL || sfx_size == 0) {
        fprintf(stderr, "ERROR: Unable to generate the random bytes.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    o = (kryptos_u8_t *) kryptos_newseg(o_size + pfx_size + sfx_size);

    if (o == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    //memset(o, 0, o_size);
    dump_catalog_data(o + pfx_size, o_size, catalog);

    // INFO(Rafael): Mitigating chosen-plaintext attack by making its applying hard.

    memcpy(o, pfx, pfx_size);
    memcpy(o + pfx_size + o_size, sfx, sfx_size);

    o_size += pfx_size + sfx_size;

    if (encrypt_catalog_data(&o, &o_size, key, key_size, catalog) == kKryptosSuccess) {
        fprintf(stderr, "ERROR: Error while encrypting the catalog data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    key_hash_algo = get_hash_processor_name(catalog->catalog_key_hash_algo);

    if (key_hash_algo == NULL) {
        fprintf(stderr, "ERROR: Unknown catalog's key hash processor.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_KEY_HASH_ALGO_HDR,
                             key_hash_algo,
                             strlen(key_hash_algo)) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: Error while writing the catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_HMAC_HDR,
                             catalog->hmac_scheme->name,
                             strlen(catalog->hmac_scheme->name)) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: Error while writing the catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (catalog->encoder != NULL) {
        if ((encoder = get_encoder_name(catalog->encoder)) == NULL) {
            fprintf(stderr, "ERROR: Unknown encoder processor.\n");
            no_error = 0;
            encoder = NULL;
            goto bcrepo_write_epilogue;
        }

        if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                                 BCREPO_PEM_ENCODER_HDR,
                                 encoder, strlen(encoder)) != kKryptosSuccess) {
            fprintf(stderr, "ERROR: Error while writing the catalog PEM data.\n");
            no_error = 0;
            encoder = NULL;
            goto bcrepo_write_epilogue;
        }

        encoder = NULL;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_CATALOG_DATA_HDR,
                             o, o_size) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: Error while writing the catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    fp = fopen(filepath, "w");

    if (fp == NULL) {
        fprintf(stderr, "ERROR: Unable to write to file '%s'.\n", filepath);
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (fwrite(pem_buf, 1, pem_buf_size, fp) == -1) {
        fprintf(stderr, "ERROR: While writing the PEM data to disk.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

bcrepo_write_epilogue:

    if (pfx != NULL) {
        kryptos_freeseg(pfx, pfx_size);
        pfx_size = 0;
    }

    if (sfx != NULL) {
        kryptos_freeseg(sfx, sfx_size);
        sfx_size = 0;
    }

    if (fp != NULL) {
        fclose(fp);
    }

    if (o != NULL) {
        kryptos_freeseg(o, o_size);
        o_size = 0;
    }

    if (pem_buf != NULL) {
        kryptos_freeseg(pem_buf, pem_buf_size);
        pem_buf_size = 0;
    }

    if (key_hash_algo != NULL) {
        key_hash_algo = NULL;
    }

    return no_error;
}

kryptos_u8_t *bcrepo_read(const char *filepath, bfs_catalog_ctx *catalog, size_t *out_size) {
    kryptos_u8_t *o = NULL;
    FILE *fp = NULL;
    kryptos_u8_t *hmac_algo = NULL, *key_hash_algo = NULL, *encoder = NULL;
    size_t hmac_algo_size = 0, key_hash_algo_size = 0, encoder_size = 0;
    const struct blackcat_hmac_catalog_algorithms_ctx *hmac_scheme = NULL;
    blackcat_hash_processor catalog_key_hash_algo = NULL;

    if (filepath == NULL || catalog == NULL || out_size == NULL) {
        goto bcrepo_read_epilogue;
    }

    *out_size = 0;

    fp = fopen(filepath, "r");

    if (fp == NULL) {
        fprintf(stderr, "ERROR: Unable to read the catalog file '%s'.\n", filepath);
        goto bcrepo_read_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    *out_size = (size_t) ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    o = (kryptos_u8_t *) kryptos_newseg(*out_size);

    if (o == NULL) {
        fprintf(stderr, "ERROR: Not enough memory for reading the catalog file.\n");
        goto bcrepo_read_epilogue;
    }

    fread(o, 1, *out_size, fp);

    // INFO(Rafael): We will keep the catalog encrypted in memory, however, we need to know how to
    //               open it in the next catalog stat operation. So let's 'trigger' the correct
    //               hash algorithm (key crunching) and the HMAC processor.

    key_hash_algo = kryptos_pem_get_data(BCREPO_PEM_KEY_HASH_ALGO_HDR, o, *out_size, &key_hash_algo_size);

    if (key_hash_algo == NULL) {
        fprintf(stderr, "ERROR: Unable to get the catalog's hash algorithm.\n");
        kryptos_freeseg(o, *out_size);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    catalog_key_hash_algo = get_hash_processor(key_hash_algo);

    if (catalog_key_hash_algo == NULL) {
        // INFO(Rafael): Some idiot trying to screw up the program's flow.
        fprintf(stderr, "ERROR: Unknown catalog's hash algorithm.\n");
        kryptos_freeseg(o, *out_size);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    catalog->catalog_key_hash_algo = catalog_key_hash_algo;

    hmac_algo = kryptos_pem_get_data(BCREPO_PEM_HMAC_HDR, o, *out_size, &hmac_algo_size);

    if (hmac_algo == NULL) {
        fprintf(stderr, "ERROR: Unable to get the catalog's HMAC scheme.\n");
        kryptos_freeseg(o, *out_size);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    hmac_scheme = get_hmac_catalog_scheme(hmac_algo);

    if (hmac_scheme == NULL) {
        // INFO(Rafael): Some idiot trying to screw up the program's flow.
        fprintf(stderr, "ERROR: Unknown catalog's HMAC scheme.\n");
        kryptos_freeseg(o, *out_size);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    catalog->hmac_scheme = hmac_scheme;

    encoder = kryptos_pem_get_data(BCREPO_PEM_ENCODER_HDR, o, *out_size, &encoder_size);

    if (encoder != NULL) {
        if ((catalog->encoder = get_encoder(encoder)) == NULL) {
            fprintf(stderr, "ERROR: Unable to get the repo's encoder.\n");
            kryptos_freeseg(o, *out_size);
            o = NULL;
            *out_size = 0;
            goto bcrepo_read_epilogue;
        }
    }

bcrepo_read_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    if (key_hash_algo != NULL) {
        kryptos_freeseg(key_hash_algo, key_hash_algo_size);
        key_hash_algo_size = 0;
    }

    if (hmac_algo != NULL) {
        kryptos_freeseg(hmac_algo, hmac_algo_size);
        hmac_algo_size = 0;
    }

    if (encoder != NULL) {
        kryptos_freeseg(encoder, encoder_size);
        encoder_size = 0;
    }

    hmac_scheme = NULL;

    return o;
}

int bcrepo_stat(bfs_catalog_ctx **catalog,
                const kryptos_u8_t *key, const size_t key_size,
                kryptos_u8_t **data, size_t *data_size) {
    kryptos_task_result_t result = kKryptosProcessError;
    int no_error = 1;

    result = decrypt_catalog_data(data, data_size, key, key_size, *catalog);

    if (result != kKryptosSuccess) {
        no_error = 0;
        goto bcrepo_stat_epilogue;
    }

    if (!read_catalog_data(catalog, *data, *data_size)) {
        no_error = 0;
        goto bcrepo_stat_epilogue;
    }

bcrepo_stat_epilogue:

    if (result == kKryptosSuccess) {
        kryptos_freeseg(*data, *data_size);
        *data = NULL;
        *data_size = 0;
    }

    return no_error;
}

char *remove_go_ups_from_path(char *path, const size_t path_size) {
    char cwd[4096];
    int go_up_nr = 0;
    char *p, *p_end;
    size_t cwd_size;

    getcwd(cwd, sizeof(cwd) - 1);

    if (cwd == NULL) {
        return path;
    }

    // TODO(Rafael): When in Windows also test '..\\'.

    p = path;
    p_end = path + strlen(path);

    while (p < p_end && (p = strstr(p, "../")) != NULL) {
        go_up_nr++;
        p += 3;
    }

    if (go_up_nr == 0) {
        goto remove_go_ups_from_path_epilogue;
    }

    p = &cwd[strlen(cwd) - 1];

    while (p != &cwd[0] && go_up_nr > 0) {
        while (p != &cwd[0] && *p != '/') {
            p--;
        }
        go_up_nr -= 1;
        p -= (go_up_nr != 0);
    }

    *p = 0;

    cwd_size = strlen(cwd);

    if (cwd_size < path_size) {
        memset(path, 0, path_size);
        memcpy(path, cwd, cwd_size);
    }

remove_go_ups_from_path_epilogue:

    p = path;
    p_end = p + strlen(path);
    cwd_size = 0;

    while (p < p_end) {
        if ((p + 1) < p_end && p[0] == '.' && p[1] == '/') {
            p += 2;
            if (p == p_end) {
                continue;
            }
        } else if ((p + 2) < p_end && p[0] == '.' && p[1] == '.' && p[2] == '/') {
            p += 3;
            if (p == p_end) {
                continue;
            }
        }
        cwd[cwd_size++] = *p;
        p++;
    }

    memset(path, 0, path_size);
    memcpy(path, cwd, cwd_size);

    return path;
}

static int root_dir_reached(const char *cwd) {
#ifndef _WIN32
    return (strcmp(cwd, "/") == 0);
#else
    return 1;
#endif
}

static kryptos_task_result_t decrypt_catalog_data(kryptos_u8_t **data, size_t *data_size,
                                                  const kryptos_u8_t *key, const size_t key_size,
                                                  bfs_catalog_ctx *catalog) {
    blackcat_protlayer_chain_ctx p_layer;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_result_t result = kKryptosProcessError;

    if (!is_hmac_processor(catalog->hmac_scheme->processor) || catalog->catalog_key_hash_algo == NULL) {
        return kKryptosProcessError;
    }

    p_layer.key = NULL;

    kryptos_task_init_as_null(ktask);

    ktask->in = (kryptos_u8_t *) key;
    ktask->in_size = key_size;

    catalog->catalog_key_hash_algo(&ktask, 0);

    if (!kryptos_last_task_succeed(ktask)) {
        fprintf(stderr, "ERROR: Unable to process the catalog's key.\n");
        goto decrypt_catalog_data_epilogue;
    }

    p_layer.key = ktask->out;
    p_layer.key_size = ktask->out_size;
    p_layer.mode = catalog->hmac_scheme->mode;

    ktask->in = kryptos_pem_get_data(BCREPO_PEM_CATALOG_DATA_HDR, *data, *data_size, &ktask->in_size);

    if (ktask->in == NULL) {
        fprintf(stderr, "ERROR: While decrypting catalog's data.\n");
        goto decrypt_catalog_data_epilogue;
    }

    kryptos_task_set_decrypt_action(ktask);

    catalog->hmac_scheme->processor(&ktask, &p_layer);

    if (kryptos_last_task_succeed(ktask)) {
        kryptos_freeseg(*data, *data_size);
        *data = ktask->out;
        *data_size = ktask->out_size;
    }

    result = ktask->result;

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    p_layer.key_size = 0;
    p_layer.mode = kKryptosCipherModeNr;

decrypt_catalog_data_epilogue:

    if (p_layer.key != NULL) {
        kryptos_freeseg(p_layer.key, p_layer.key_size);
    }

    return result;
}

static kryptos_task_result_t encrypt_catalog_data(kryptos_u8_t **data, size_t *data_size,
                                                  const kryptos_u8_t *key, const size_t key_size,
                                                  bfs_catalog_ctx *catalog) {
    blackcat_protlayer_chain_ctx p_layer;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_result_t result = kKryptosProcessError;

    if (catalog->catalog_key_hash_algo == NULL) {
        return kKryptosProcessError;
    }

    p_layer.key = NULL;

    kryptos_task_init_as_null(ktask);

    catalog->hmac_scheme = get_random_hmac_catalog_scheme();

    ktask->in = (kryptos_u8_t *) key;
    ktask->in_size = key_size;

    catalog->catalog_key_hash_algo(&ktask, 0);

    if (!kryptos_last_task_succeed(ktask)) {
        fprintf(stderr, "ERROR: Unable to process the catalog's key.\n");
        goto encrypt_catalog_data_epilogue;
    }

    p_layer.key = ktask->out;
    p_layer.key_size = ktask->out_size;
    p_layer.mode = catalog->hmac_scheme->mode;

    kryptos_task_set_in(ktask, *data, *data_size);

    kryptos_task_set_encrypt_action(ktask);

    catalog->hmac_scheme->processor(&ktask, &p_layer);

    if (kryptos_last_task_succeed(ktask)) {
        *data = ktask->out;
        *data_size = ktask->out_size;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    p_layer.key_size = 0;
    p_layer.mode = kKryptosCipherModeNr;

    result = ktask->result;

encrypt_catalog_data_epilogue:

    if (p_layer.key != NULL) {
        kryptos_freeseg(p_layer.key, p_layer.key_size);
    }

    return result;
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
        size += f->path_size + strlen(f->timestamp) + 6 + (f->seed_size << 1);
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
    static struct bcrepo_dumper_ctx dumpers[] = {
        { BCREPO_CATALOG_BC_VERSION,              bc_version_w,              0 },
        { BCREPO_CATALOG_KEY_HASH_ALGO,           key_hash_algo_w,           0 },
        { BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO, protlayer_key_hash_algo_w, 0 },
        { BCREPO_CATALOG_KEY_HASH,                key_hash_w,                0 },
        { BCREPO_CATALOG_PROTECTION_LAYER,        protection_layer_w,        0 },
        { BCREPO_CATALOG_FILES,                   files_w,                   0 }
    };
    static size_t dumpers_nr = sizeof(dumpers) / sizeof(dumpers[0]), d;
    kryptos_u8_t *o;
#define all_dump_done(d) ( (d)[0].done && (d)[1].done && (d)[2].done && (d)[3].done && (d)[4].done && (d)[5].done )

    for (d = 0; d < dumpers_nr; d++) {
        dumpers[d].done = 0;
    }

    o = out;

    while (!all_dump_done(dumpers)) {
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
    char xseed[40];

    o = out;

    size = strlen(BCREPO_CATALOG_FILES);
    memcpy(o, BCREPO_CATALOG_FILES, size);
    o += size;
    *o = '\n';
    o += 1;

    for (f = catalog->files; f != NULL; f = f->next) {
        size = f->path_size;
        memcpy(o, f->path, size);
        o += size;

        *o = ',';
        o += 1;

        *o = (kryptos_u8_t)f->status;
        o += 1;

        *o = ',';
        o += 1;

        size = strlen(f->timestamp);
        memcpy(o, f->timestamp, size);
        o += size;

        *o = ',';
        o += 1;

        bcrepo_seed_to_hex(xseed, sizeof(xseed), f->seed, f->seed_size);
        size = strlen(xseed);
        memcpy(o, xseed, size);
        o += size;

        *o = '\n';
        o += 1;
    }

    *o = '\n';

    memset(xseed, 0, sizeof(xseed));

    return (o + 1);
}

static int read_catalog_data(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    static bcrepo_reader read[] = {
        bc_version_r,
        key_hash_algo_r,
        protlayer_key_hash_algo_r,
        key_hash_r,
        protection_layer_r,
        files_r
    };
    static size_t read_nr = sizeof(read) /  sizeof(read[0]), r;
    int no_error = 1;

    for (r = 0; r < read_nr && no_error; r++) {
        no_error = read[r](catalog, in, in_size);
    }

    return no_error;
}

static kryptos_u8_t *get_catalog_field(const char *field, const kryptos_u8_t *in, const size_t in_size) {
    const kryptos_u8_t *fp, *fp_end, *end;
    kryptos_u8_t *data = NULL;

    fp = strstr(in, field);
    end = in + in_size;

    if (fp == NULL) {
        goto get_catalog_field_epilogue;
    }

    if (*(fp - 1) == '-') {
        while (fp != NULL && *(fp - 1) == '-' && fp < end) {
            fp += 1;
            fp = strstr(fp, field);
        }
    }

    if (fp >= end || fp == NULL) {
        goto get_catalog_field_epilogue;
    }

    fp += strlen(field);

    while (fp != end && *fp == ' ') {
        fp++;
    }

    fp_end = fp;

    while (fp_end != end && *fp_end != '\n') {
        fp_end++;
    }

    data = (kryptos_u8_t *) kryptos_newseg(fp_end - fp + 1);
    memset(data, 0, fp_end - fp + 1);
    memcpy(data, fp, fp_end - fp);

get_catalog_field_epilogue:

    return data;
}

static int bc_version_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;
    cp->bc_version = get_catalog_field(BCREPO_CATALOG_BC_VERSION, in, in_size);
    return (cp->bc_version != NULL);
}

static int key_hash_algo_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    char *hash_algo = NULL;
    int done = 0;
    bfs_catalog_ctx *cp = *catalog;

    hash_algo = get_catalog_field(BCREPO_CATALOG_KEY_HASH_ALGO, in, in_size);

    if (hash_algo == NULL) {
        goto key_hash_algo_r_epilogue;
    }

    cp->key_hash_algo = get_hash_processor(hash_algo);
    cp->key_hash_algo_size = get_hash_size(hash_algo);

    done = (cp->key_hash_algo != NULL && cp->key_hash_algo_size != NULL);

key_hash_algo_r_epilogue:

    if (hash_algo != NULL) {
        kryptos_freeseg(hash_algo, strlen(hash_algo));
    }

    return done;
}

static int protlayer_key_hash_algo_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    char *hash_algo = NULL;
    int done = 0;
    bfs_catalog_ctx *cp = *catalog;

    hash_algo = get_catalog_field(BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO, in, in_size);

    if (hash_algo == NULL) {
        goto protlayer_key_hash_algo_r_epilogue;
    }

    cp->protlayer_key_hash_algo = get_hash_processor(hash_algo);
    cp->protlayer_key_hash_algo_size = get_hash_size(hash_algo);

    done = (cp->protlayer_key_hash_algo != NULL && cp->protlayer_key_hash_algo_size != NULL);

protlayer_key_hash_algo_r_epilogue:

    if (hash_algo != NULL) {
        kryptos_freeseg(hash_algo, strlen(hash_algo));
    }

    return done;
}

static int key_hash_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;

    if (cp->key_hash_algo_size == NULL) {
        return 0;
    }

    cp->key_hash = get_catalog_field(BCREPO_CATALOG_KEY_HASH, in, in_size);
    cp->key_hash_size = cp->key_hash_algo_size() << 1; // INFO(Rafael): Stored in hexadecimal format.

    return (cp->key_hash != NULL && cp->key_hash_size > 0);
}

static int protection_layer_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;
    cp->protection_layer = get_catalog_field(BCREPO_CATALOG_PROTECTION_LAYER, in, in_size);
    return (cp->protection_layer != NULL);
}

static int files_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    const kryptos_u8_t *ip, *ip_end, *cp, *cp_end;
    kryptos_u8_t *path = NULL;
    size_t path_size;
    bfs_file_status_t status;
    char *timestamp = NULL;
    size_t timestamp_size;
    bfs_catalog_ctx *cat_p = *catalog;
    int no_error = 1;

    ip = in;
    ip_end = ip + in_size;

    if ((kryptos_u8_t *)(ip = strstr(ip, BCREPO_CATALOG_FILES)) == NULL) {
        return 0;
    }

    ip += strlen(BCREPO_CATALOG_FILES);

    if (*ip != '\n') {
        return 0;
    }

    ip += 1;

    if (*ip == '\n') {
        // INFO(Rafael): Empty file list.
        goto files_r_epilogue;
    }

    while (ip < ip_end) {

        if (*ip != '\n') {
            cp = ip;
            cp_end = cp;

            // INFO(Rafael): Getting the path data.

            while (cp_end != ip_end && *cp_end != ',') {
                cp_end++;
            }

            if (*cp_end != ',') {
                // INFO(Rafael): It should never happen since it is protected by a HMAC function!
                fprintf(stderr, "ERROR: The catalog seems corrupted.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            path_size = cp_end - cp;
            path = (kryptos_u8_t *) kryptos_newseg(path_size + 1);

            if (path == NULL) {
                fprintf(stderr, "ERROR: Not enough memory to read the file list from catalog.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            memset(path, 0, path_size + 1);
            memcpy(path, cp, path_size);

            // INFO(Rafael): Getting the status data.

            cp = cp_end + 1;
            cp_end = cp;

            status = *cp_end;

            if (status != 'L' && status != 'U' && status != 'P') {
                fprintf(stderr, "ERROR: Invalid file status.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            cp_end += 1;

            if (*cp_end != ',') {
                // INFO(Rafael): It should never happen since it is protected by a HMAC function!
                fprintf(stderr, "ERROR: The catalog seems corrupted.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            // INFO(Rafael): Getting the timestamp data.

            cp = cp_end + 1;
            cp_end = cp;

            while (cp_end != ip_end && *cp_end != ',') {
                cp_end++;
            }

            if (*cp_end != ',') {
                // INFO(Rafael): It should never happen since it is protected by a HMAC function!
                fprintf(stderr, "ERROR: The catalog seems corrupted.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            timestamp_size = cp_end - cp;
            timestamp = (char *) kryptos_newseg(timestamp_size + 1);

            if (timestamp == NULL) {
                fprintf(stderr, "ERROR: Not enough memory to read the file list from catalog.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            memset(timestamp, 0, timestamp_size + 1);
            memcpy(timestamp, cp, timestamp_size);

            cat_p->files = add_file_to_relpath_ctx(cat_p->files, path, path_size, status, timestamp);

            // INFO(Rafael): Getting the file's seed.

            cp = cp_end + 1;
            cp_end = cp;

            while (cp_end != ip_end && *cp_end != '\n') {
                cp_end++;
            }

            if (*cp_end != '\n') {
                // INFO(Rafael): It should never happen since it is protected by a HMAC function!
                fprintf(stderr, "ERROR: The catalog seems corrupted.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            bcrepo_hex_to_seed(&cat_p->files->tail->seed, &cat_p->files->tail->seed_size, cp, cp_end - cp);

            kryptos_freeseg(path, path_size + 1);
            kryptos_freeseg(timestamp, timestamp_size + 1);
            path = timestamp = NULL;

            ip = cp_end - 1;
        } else if (*(ip + 1) == '\n') {
            break;
        }

        ip++;
    }

files_r_epilogue:

    if (no_error == 0) {
        del_bfs_catalog_relpath_ctx(cat_p->files);
        cat_p->files = NULL;
    }

    if (path != NULL) {
        kryptos_freeseg(path, path_size + 1);
    }

    if (timestamp != NULL) {
        kryptos_freeseg(timestamp, timestamp_size + 1);
    }

    return no_error;
}

static void bcrepo_seed_to_hex(char *buf, const size_t buf_size, const kryptos_u8_t *seed, const size_t seed_size) {
    char *bp, *bp_end;
    const kryptos_u8_t *sp, *sp_end;
    static char hex_digits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    size_t n1, n2;

    memset(buf, 0, buf_size);

    bp = buf;
    bp_end = bp + buf_size - 1;

    sp = seed;
    sp_end = sp + seed_size;

    while (sp != sp_end && bp != bp_end) {
#define get_nibble_value(n, n1, n2)  ( (n1) = ((n) >> 4), (n2) = ((n) & 0xF) )
        get_nibble_value(sp[0], n1, n2);
#undef get_nibble_value
        bp[0] = hex_digits[n1];
        bp[1] = hex_digits[n2];
        bp += 2;
        sp += 1;
    }

    sp = sp_end = NULL;
    bp = bp_end = NULL;
}

static void bcrepo_hex_to_seed(kryptos_u8_t **seed, size_t *seed_size, const char *buf, const size_t buf_size) {
    const char *bp, *bp_end;
    kryptos_u8_t *sp, *sp_end;

    if ((*seed) != NULL) {
        kryptos_freeseg(*seed, *seed_size);
        (*seed) = NULL;
    }

    *seed_size = buf_size >> 1;

    sp = (*seed) = (kryptos_u8_t *) kryptos_newseg(*seed_size);

    if (sp == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to get the file's seed.\n");
        *seed_size = 0;
        return;
    }

    bp = buf;
    bp_end = bp + buf_size;

    sp_end = sp + *seed_size;

    while (bp != bp_end && sp != sp_end) {
#define get_xnibble_value(n) ( isdigit((n)) ? ((n) - '0') : (toupper(n) - 55) )
        *sp = get_xnibble_value(bp[0]) << 4 | get_xnibble_value(bp[1]);
#undef get_xnibble_value
        sp += 1;
        bp += 2;
    }

    sp = sp_end = NULL;
    bp = bp_end = NULL;

}

static kryptos_u8_t *random_printable_padding(size_t *size) {
    // WARN(Rafael): This function only generates random blocks from 1b up to 1Kb. However,
    //               it is enough to make harder the building of an infrastructure to promote
    //               a chosen-plaintext attack over the catalog's data.
    kryptos_u8_t s1[62] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };
    kryptos_u8_t s2[62];
    size_t *rs, s;
    kryptos_u8_t *data, *dp, *dp_end;

    *size = 0;
    rs = (size_t *) kryptos_get_random_block(sizeof(size_t));

    if (rs == NULL) {
        goto random_printable_padding_epilogue;
    }

    *size = *rs % 1024;

    if (*size == 0) {
        *size = 1;
    }

    kryptos_freeseg(rs, sizeof(size_t));

    dp = data = (kryptos_u8_t *) kryptos_newseg(*size);

    if (dp == NULL) {
        *size = 0;
        goto random_printable_padding_epilogue;
    }

    dp_end = dp + *size;

    for (s = 0; s < 62; s++) {
        s2[s] = s1[kryptos_get_random_byte() % 62];
    }

    while (dp != dp_end) {
        *dp = s2[kryptos_get_random_byte() % 62];
        dp++;
    }

random_printable_padding_epilogue:

    memset(s2, 0, sizeof(s2));

    dp = dp_end = NULL;

    return data;
}

#undef BCREPO_CATALOG_BC_VERSION
#undef BCREPO_CATALOG_KEY_HASH_ALGO
#undef BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO
#undef BCREPO_CATALOG_KEY_HASH
#undef BCREPO_CATALOG_PROTECTION_LAYER
#undef BCREPO_CATALOG_FILES

#undef BCREPO_PEM_KEY_HASH_ALGO_HDR
#undef BCREPO_PEM_HMAC_HDR
#undef BCREPO_PEM_CATALOG_DATA_HDR
#undef BCREPO_PEM_ENCODER_HDR

#undef BCREPO_HIDDEN_DIR
#undef BCREPO_HIDDEN_DIR_SIZE
#undef BCREPO_CATALOG_FILE
#undef BCREPO_CATALOG_FILE_SIZE

#undef BCREPO_RECUR_LEVEL_LIMIT
