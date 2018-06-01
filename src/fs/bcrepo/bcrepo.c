/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <fs/bcrepo/bcrepo.h>
#include <keychain/ciphering_schemes.h>
#include <fs/ctx/fsctx.h>
#include <fs/strglob.h>
#include <kryptos.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BCREPO_CATALOG_BC_VERSION               "bc-version: "
#define BCREPO_CATALOG_KEY_HASH_ALGO            "key-hash-algo: "
#define BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO  "protlayer-key-hash-algo: "
#define BCREPO_CATALOG_KEY_HASH                 "key-hash: "
#define BCREPO_CATALOG_PROTECTION_LAYER         "protection-layer: "
#define BCREPO_CATALOG_FILES                    "files: "

#define BCREPO_PEM_HMAC_HDR "BCREPO HMAC SCHEME"
#define BCREPO_PEM_CATALOG_DATA_HDR "BCREPO CATALOG DATA"

#define BCREPO_HIDDEN_DIR ".bcrepo"
#define BCREPO_CATALOG_FILE "CATALOG"

#define BCREPO_RECUR_LEVEL_LIMIT 1024

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

static int unl_handle(bfs_catalog_ctx **catalog,
                      const char *rootpath, const size_t rootpath_size,
                      const char *pattern, const size_t pattern_size, int lock) {
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

#define unl_fproc(file, l, pstmt) {\
    if (((l) && !((file) != NULL && (file)->status == kBfsFileStatusUnlocked)) ||\
        (!(l) && !((file) != NULL && (file)->status == kBfsFileStatusLocked))) {\
        continue;\
    }\
    pstmt;\
}
    if (files != cp->files) {
        for (fp = files; fp != NULL; fp = files->next) {
            fpp = get_entry_from_relpath_ctx(cp->files, fp->path);
            // TODO(Rafael): Process the file and increment the processing counter.
            unl_fproc(fpp, lock, {});
        }
    } else {
        for (fp = files; fp != NULL; fp = files->next) {
            // TODO(Rafael): Process the file and increment the processing counter.
            unl_fproc(fp, lock, NULL);
        }
    }

#undef unl_fproc

    if (files != NULL && files != cp->files) {
        del_bfs_catalog_relpath_ctx(files);
    }

    return proc_nr;
}

int bcrepo_lock(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return unl_handle(catalog, rootpath, rootpath_size, pattern, pattern_size, 1);
}


int bcrepo_unlock(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return unl_handle(catalog, rootpath, rootpath_size, pattern, pattern_size, 0);
}

int bcrepo_rm(bfs_catalog_ctx **catalog,
              const char *rootpath, const size_t rootpath_size,
              const char *pattern, const size_t pattern_size) {
    int rm_nr = 0;
    bfs_catalog_relpath_ctx *files = NULL, *fp;
    bfs_catalog_ctx *cp;
    int rl = 0;

    if (catalog == NULL) {
        goto bcrepo_rm_epilogue;
    }

    cp = *catalog;

    get_file_list(&files, cp->files, rootpath, rootpath_size, pattern, pattern_size, &rl, BCREPO_RECUR_LEVEL_LIMIT);

    for (fp = files; fp != NULL; fp = fp->next) {
        // TODO(Rafael): If the file is currently encrypted, decrypt it before deleting from catalog.
        cp->files = del_file_from_relpath_ctx(cp->files, fp->path);
        rm_nr++;
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

static void get_file_list(bfs_catalog_relpath_ctx **files, bfs_catalog_relpath_ctx *dest_files,
                          const char *rootpath, const size_t rootpath_size,
                          const char *pattern, const size_t pattern_size, int *recur_level, const int recur_max_level) {
    int matches;
    char *filepath = NULL, *fp = NULL, *fp_end = NULL, *glob = NULL, *filename;
    size_t filepath_size, glob_size, filename_size;
    struct stat st;
    bfs_catalog_relpath_ctx *files_p;
    DIR *dirp = NULL;
    struct dirent *dt;
    char cwd[4096];

    if (*recur_level > recur_max_level) {
        printf("ERROR: get_file_list() recursiveness level limit hit.\n");
        goto get_file_list_epilogue;
    }

    if (files == NULL || rootpath == NULL || rootpath_size == 0 || pattern == NULL || pattern_size == 0) {
        goto get_file_list_epilogue;
    }

    filepath_size = rootpath_size + pattern_size;
    filepath = (char *) kryptos_newseg(filepath_size + 1);

    if (filepath == NULL) {
        printf("ERROR: Unable to allocate memory!\n");
        goto get_file_list_epilogue;
    }

    memset(filepath, 0, filepath_size + 1);
    memcpy(filepath, rootpath, rootpath_size);
    memcpy(filepath + rootpath_size, pattern, pattern_size);

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
            printf("ERROR: Unable to allocate memory!\n");
            goto get_file_list_epilogue;
        }

        memset(glob, 0, glob_size + 1);
        memcpy(glob, fp, glob_size);

        filepath = (char *) kryptos_realloc(filepath, 4096);

        if (filepath == NULL) {
            printf("ERROR: Unable to allocate memory!\n");
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
                printf("ERROR: Unable to access '%s'.\n", filepath);
                goto get_file_list_epilogue;
            }

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

                if ((fp + filename_size) >= fp_end) {
                    printf("WARN: The filename '%s' is too long. It was not added.\n", filename);
                    continue;
                }

                memcpy(fp, filename, filename_size);
                *(fp + filename_size) = 0;
                filepath_size = (fp - filepath) + filename_size;

                *recur_level += 1;

                get_file_list(files,
                              dest_files,
                              rootpath, rootpath_size,
                              filepath + rootpath_size, filepath_size - rootpath_size,
                              recur_level, recur_max_level);

                *recur_level -= 1;
            }
        }
    } else {
        // INFO(Rafael): It is about a glob to be tested over the current directory files.
        //               Let's perform a new call to bcrepo_add() passing '<cwd>/<pattern>'.
        memset(cwd, 0, sizeof(cwd));
        if (getcwd(cwd, sizeof(cwd) - 1) == NULL) {
            printf("ERROR: Unable to get the current cwd.\n");
            goto get_file_list_epilogue;
        }

        fp = &cwd[0];
        fp_end = fp + strlen(cwd);

        if (*(fp_end - 1) != '/') {
            *(fp_end) = '/';
            fp_end++;
        }

        if ((fp_end + pattern_size) >= (fp + sizeof(cwd))) {
            printf("ERROR: The passed file pattern is too long.\n");
            goto get_file_list_epilogue;
        }

        memcpy(fp_end, pattern, pattern_size);

        *recur_level += 1;

        get_file_list(files, dest_files, rootpath, rootpath_size, cwd, strlen(cwd), recur_level, recur_max_level);

        *recur_level -= 1;
    }

get_file_list_epilogue:

    if (filepath != NULL) {
        kryptos_freeseg(filepath);
    }

    if (glob != NULL) {
        kryptos_freeseg(glob);
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

    if (encrypt_catalog_data(&o, &o_size, key, key_size, catalog) == kKryptosSuccess) {
        printf("ERROR: Error while encrypting the catalog data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_HMAC_HDR,
                             catalog->hmac_scheme->name,
                             strlen(catalog->hmac_scheme->name)) != kKryptosSuccess) {
        printf("ERROR: Error while writing the catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_CATALOG_DATA_HDR,
                             o, o_size) != kKryptosSuccess) {
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

    return no_error;
}

kryptos_u8_t *bcrepo_read(const char *filepath, bfs_catalog_ctx *catalog, size_t *out_size) {
    kryptos_u8_t *o = NULL;
    FILE *fp = NULL;
    kryptos_u8_t *hmac_algo = NULL;
    size_t hmac_algo_size = 0;
    const struct blackcat_hmac_catalog_algorithms_ctx *hmac_scheme = NULL;

    if (filepath == NULL || catalog == NULL || out_size == NULL) {
        goto bcrepo_read_epilogue;
    }

    *out_size = 0;

    fp = fopen(filepath, "r");

    if (fp == NULL) {
        printf("ERROR: Unable to read the catalog file '%s'.\n", filepath);
        goto bcrepo_read_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    *out_size = (size_t) ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    o = (kryptos_u8_t *) kryptos_newseg(*out_size);

    if (o == NULL) {
        printf("ERROR: Not enough memory for reading the catalog file.\n");
        goto bcrepo_read_epilogue;
    }

    fread(o, 1, *out_size, fp);

    // INFO(Rafael): We will keep the catalog encrypted in memory, however, we need to know how to
    //               open it in the next catalog stat operation. So let's 'trigger' the correct
    //               HMAC processor.

    hmac_algo = kryptos_pem_get_data(BCREPO_PEM_HMAC_HDR, o, *out_size, &hmac_algo_size);

    if (hmac_algo == NULL) {
        printf("ERROR: Unable to get the catalog's HMAC scheme.\n");
        kryptos_freeseg(o);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    hmac_scheme = get_hmac_catalog_scheme(hmac_algo);

    if (hmac_scheme == NULL) {
        // INFO(Rafael): Some idiot trying to screw up the program's flow.
        printf("ERROR: Unknown catalog's HMAC scheme.\n");
        kryptos_freeseg(o);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    catalog->hmac_scheme = hmac_scheme;

bcrepo_read_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    if (hmac_algo != NULL) {
        kryptos_freeseg(hmac_algo);
        hmac_algo_size = 0;
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
        kryptos_freeseg(*data);
        *data = NULL;
        *data_size = 0;
    }

    return no_error;
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

    if (!is_hmac_processor(catalog->hmac_scheme->processor)) {
        return kKryptosProcessError;
    }

    kryptos_task_init_as_null(ktask);

    p_layer.key = (kryptos_u8_t *) key;
    p_layer.key_size = key_size;
    p_layer.mode = catalog->hmac_scheme->mode;

    ktask->in = kryptos_pem_get_data(BCREPO_PEM_CATALOG_DATA_HDR, *data, *data_size, &ktask->in_size);

    if (ktask->in == NULL) {
        printf("ERROR: While decrypting catalog's data.\n");
        goto decrypt_catalog_data_epilogue;
    }

    kryptos_task_set_decrypt_action(ktask);

    catalog->hmac_scheme->processor(&ktask, &p_layer);

    if (kryptos_last_task_succeed(ktask)) {
        kryptos_freeseg(*data);
        *data = ktask->out;
        *data_size = ktask->out_size;
    }

    result = ktask->result;

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    p_layer.key = NULL;
    p_layer.key_size = 0;
    p_layer.mode = kKryptosCipherModeNr;

decrypt_catalog_data_epilogue:

    return result;
}

static kryptos_task_result_t encrypt_catalog_data(kryptos_u8_t **data, size_t *data_size,
                                                  const kryptos_u8_t *key, const size_t key_size,
                                                  bfs_catalog_ctx *catalog) {
    blackcat_protlayer_chain_ctx p_layer;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_result_t result = kKryptosProcessError;

    kryptos_task_init_as_null(ktask);

    catalog->hmac_scheme = get_random_hmac_catalog_scheme();

    p_layer.key = (kryptos_u8_t *) key;
    p_layer.key_size = key_size;
    p_layer.mode = catalog->hmac_scheme->mode;

    kryptos_task_set_in(ktask, *data, *data_size);

    kryptos_task_set_encrypt_action(ktask);

    catalog->hmac_scheme->processor(&ktask, &p_layer);

    if (kryptos_last_task_succeed(ktask)) {
        *data = ktask->out;
        *data_size = ktask->out_size;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    p_layer.key = NULL;
    p_layer.key_size = 0;
    p_layer.mode = kKryptosCipherModeNr;

    result = ktask->result;

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
        size += f->path_size + strlen(f->timestamp) + 4;
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

        *o = '\n';
        o += 1;
    }

    *o = '\n';

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

    if (fp > in && *(fp - 1) != '\n') {
        while (*(fp - 1) != '\n' && fp < end) {
            fp += 1;
            fp = strstr(fp, field);
        }
    }

    if (fp >= end) {
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
        kryptos_freeseg(hash_algo);
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
        kryptos_freeseg(hash_algo);
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
                printf("ERROR: The catalog seems corrupted.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            path_size = cp_end - cp;
            path = (kryptos_u8_t *) kryptos_newseg(path_size + 1);

            if (path == NULL) {
                printf("ERROR: Not enough memory to read the file list from catalog.\n");
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
                printf("ERROR: Invalid file status.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            cp_end += 1;

            if (*cp_end != ',') {
                // INFO(Rafael): It should never happen since it is protected by a HMAC function!
                printf("ERROR: The catalog seems corrupted.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            // INFO(Rafael): Getting the timestamp data.

            cp = cp_end + 1;
            cp_end = cp;

            while (cp_end != ip_end && *cp_end != '\n') {
                cp_end++;
            }

            if (*cp_end != '\n') {
                // INFO(Rafael): It should never happen since it is protected by a HMAC function!
                printf("ERROR: The catalog seems corrupted.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            timestamp_size = cp_end - cp;
            timestamp = (char *) kryptos_newseg(timestamp_size + 1);

            if (timestamp == NULL) {
                printf("ERROR: Not enough memory to read the file list from catalog.\n");
                no_error = 0;
                goto files_r_epilogue;
            }

            memset(timestamp, 0, timestamp_size + 1);
            memcpy(timestamp, cp, timestamp_size);

            cat_p->files = add_file_to_relpath_ctx(cat_p->files, path, path_size, status, timestamp);

            kryptos_freeseg(path);
            kryptos_freeseg(timestamp);
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
        kryptos_freeseg(path);
    }

    if (timestamp != NULL) {
        kryptos_freeseg(timestamp);
    }

    return no_error;
}

#undef BCREPO_CATALOG_BC_VERSION
#undef BCREPO_CATALOG_KEY_HASH_ALGO
#undef BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO
#undef BCREPO_CATALOG_KEY_HASH
#undef BCREPO_CATALOG_PROTECTION_LAYER
#undef BCREPO_CATALOG_FILES

#undef BCREPO_PEM_HMAC_HDR
#undef BCREPO_PEM_CATALOG_DATA_HDR

#undef BCREPO_HIDDEN_DIR
#undef BCREPO_CATALOG_FILE
