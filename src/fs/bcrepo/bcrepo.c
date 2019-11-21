/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <fs/bcrepo/bcrepo.h>
#include <fs/bcrepo/config.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/processor.h>
#include <keychain/keychain.h>
#include <keychain/kdf/kdf_utils.h>
#include <ctx/ctx.h>
#include <fs/ctx/fsctx.h>
#include <fs/strglob.h>
#include <util/random.h>
#include <dev/defs/io.h>
#include <dev/defs/types.h>
#include <kryptos.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(__unix__)
# include <sys/ioctl.h>
#elif defined(_WIN32)
# include <windows.h>
#endif
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>

#define BCREPO_CATALOG_BC_VERSION               "bc-version: "
#define BCREPO_CATALOG_KEY_HASH_ALGO            "key-hash-algo: "
#define BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO  "protlayer-key-hash-algo: "
#define BCREPO_CATALOG_KEY_HASH                 "key-hash: "
#define BCREPO_CATALOG_PROTECTION_LAYER         "protection-layer: "
#define BCREPO_CATALOG_FILES                    "files: "
#define BCREPO_CATALOG_OTP                      "otp: "
#define BCREPO_CATALOG_CONFIG_HASH              "config-hash: "
#define BCREPO_CATALOG_KDF_PARAMS               "kdf-params: "

#define BCREPO_PEM_KEY_HASH_ALGO_HDR "BCREPO KEY HASH ALGO"
#define BCREPO_PEM_HMAC_HDR "BCREPO HMAC SCHEME"
#define BCREPO_PEM_CATALOG_DATA_HDR "BCREPO CATALOG DATA"
#define BCREPO_PEM_ENCODER_HDR "BCREPO ENCODER"
#define BCREPO_PEM_SALT_DATA_HDR "BCREPO SALT DATA"

#define BCREPO_CATALOG_FILE "CATALOG"
#define BCREPO_CATALOG_FILE_SIZE 7
#define BCREPO_RESCUE_FILE "rescue"
#define BCREPO_RESCUE_FILE_SIZE 6

#define BCREPO_RECUR_LEVEL_LIMIT 1024

#define BLACKCAT_DEVPATH "/dev/" CDEVNAME

#if defined(__unix__)
# define BLACKCAT_EPOCH 26705100
#elif defined(_WIN32)
# define BLACKCAT_EPOCH_L 0xAB905E00
# define BLACKCAT_EPOCH_H 0x019EA46C
#endif

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

static kryptos_u8_t *otp_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *config_hash_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

static kryptos_u8_t *kdf_params_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog);

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

static int otp_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int config_hash_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int kdf_params_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static int read_catalog_data(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size);

static kryptos_u8_t *get_catalog_field(const char *field, const kryptos_u8_t *in, const size_t in_size);

static int root_dir_reached(const char *cwd);

static void get_file_list(bfs_catalog_relpath_ctx **files, bfs_catalog_relpath_ctx *dest_files,
                          const char *rootpath, const size_t rootpath_size,
                          const char *pattern, const size_t pattern_size, int *recur_level, const int recur_max_level);

static int unl_handle_encrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              blackcat_data_processor dproc,
                              bfs_file_status_t *f_st,
                              bfs_checkpoint_func ckpt,
                              void *ckpt_args);

static int unl_handle_decrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              blackcat_data_processor dproc,
                              bfs_file_status_t *f_st,
                              bfs_checkpoint_func ckpt,
                              void *ckpt_args);

typedef int (*unl_processor)(const char *rootpath, const size_t rootpath_size,
                             const char *path, const size_t path_size,
                             const blackcat_protlayer_chain_ctx *protlayer,
                             blackcat_data_processor dproc,
                             bfs_file_status_t *f_st,
                             bfs_checkpoint_func ckpt,
                             void *ckpt_args);

static int unl_handle_meta_proc(const char *rootpath, const size_t rootpath_size,
                                const char *path, const size_t path_size,
                                const blackcat_protlayer_chain_ctx *protlayer, blackcat_data_processor dproc);

static int unl_handle(bfs_catalog_ctx **catalog,
                      const char *rootpath, const size_t rootpath_size,
                      const char *pattern, const size_t pattern_size, unl_processor proc,
                      bfs_checkpoint_func ckpt,
                      void *ckpt_args);

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

static int bcrepo_mkdtree(const char *dirtree);

#if defined(__unix__)
static int do_ioctl(unsigned long cmd, const unsigned char *path, const size_t path_size);
#elif defined(_WIN32)
static int do_ioctl(unsigned long cmd, const unsigned char *path, const size_t path_size);
#endif

static int bdup_handle(unsigned long cmd,
                 bfs_catalog_ctx **catalog,
                 const char *rootpath, const size_t rootpath_size,
                 const char *pattern, const size_t pattern_size);

static int bstat(const char *pathname, struct stat *buf);

static kryptos_u8_t *bckdf(const kryptos_u8_t *key, const size_t key_size,
                           blackcat_hash_processor hash, blackcat_hash_size_func hash_size,
                           const ssize_t size, const kryptos_u8_t *salt, const size_t salt_size);

static int create_rescue_file(const char *rootpath, const size_t rootpath_size, const char *path, const size_t path_size,
                              const kryptos_u8_t *data, const size_t data_size);

static int is_metadata_compatible(const char *version);

#if defined(__unix__)
static int setfilectime(const char *path);
#elif defined(_WIN32)
static int setfiletime(const char *path, const int hard);
#endif

static void bcrepo_info_print_ext_ascii_data(const void *data, const size_t data_size);

static void bcrepo_info_kdf_params(const char *kdf_params, const size_t kdf_params_size);

static kryptos_u8_t *get_random_catalog_salt(size_t *out_size);

static int bcrepo_untouch_directories(const char *rootpath, const size_t rootpath_size);

const char *bcrepo_metadata_version(void) {
    return BCREPO_METADATA_VERSION;
}

int bcrepo_check_config_integrity(bfs_catalog_ctx *catalog, const char *rootpath, const size_t rootpath_size) {
    kryptos_u8_t *config_data = NULL;
    size_t config_data_size;
    FILE *fp = NULL;
    int clean = 0;
    char temp[4096];
    kryptos_u8_t *salt = NULL;
    size_t salt_size;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    if (catalog == NULL || rootpath == NULL || rootpath_size == 0 ||
        catalog->config_hash == NULL || catalog->config_hash_size == 0) {
        goto bcrepo_check_config_integrity_epilogue;
    }

    bcrepo_hex_to_seed(&salt, &salt_size,
                       (char *)(catalog->config_hash + (catalog->config_hash_size >> 1)),
                       catalog->config_hash_size - (catalog->config_hash_size >> 1));

    bcrepo_mkpath(temp, sizeof(temp) - 1, rootpath, rootpath_size,
                  BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE, BCREPO_HIDDEN_DIR_SIZE + BCREPO_CONFIG_FILE_SIZE + 1);

    if ((fp = fopen(temp, "rb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to open the config file for this repo.\n");
        goto bcrepo_check_config_integrity_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    config_data_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    if ((config_data = (kryptos_u8_t *) kryptos_newseg(config_data_size)) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto bcrepo_check_config_integrity_epilogue;
    }

    if (fread(config_data, 1, config_data_size, fp) != config_data_size) {
        fprintf(stderr, "ERROR: Unable to perform a full reading from config file.\n");
        goto bcrepo_check_config_integrity_epilogue;
    }

    fclose(fp);
    fp = NULL;

    ktask->in_size = salt_size + config_data_size;
    ktask->in = (kryptos_u8_t *) kryptos_newseg(ktask->in_size);

    if (ktask->in == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto bcrepo_check_config_integrity_epilogue;
    }

    memcpy(ktask->in, config_data, config_data_size);
    memcpy(ktask->in + config_data_size, salt, salt_size);

    catalog->catalog_key_hash_algo(&ktask, 1);

    if (kryptos_last_task_succeed(ktask) == 0) {
        fprintf(stderr, "ERROR: During hash computation.\n");
        goto bcrepo_check_config_integrity_epilogue;
    }

    clean = (memcmp(catalog->config_hash, ktask->out, ktask->out_size) == 0);

bcrepo_check_config_integrity_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    if (fp != NULL) {
        fclose(fp);
    }

    if (config_data != NULL) {
        kryptos_freeseg(config_data, config_data_size);
    }

    if (salt != NULL) {
        kryptos_freeseg(salt, salt_size);
    }

    return clean;
}

int bcrepo_config_update(bfs_catalog_ctx **catalog, const char *rootpath, const size_t rootpath_size,
                         bfs_checkpoint_func ckpt, void *ckpt_args) {
    kryptos_u8_t *salt = NULL, *config_data = NULL;
    kryptos_task_ctx t, *ktask = &t;
    size_t salt_size, config_data_size;
    bfs_catalog_ctx *cp;
    int no_error = 0;
    FILE *fp = NULL;
    char temp[4096];

    kryptos_task_init_as_null(ktask);

    if (catalog == NULL || rootpath == NULL || rootpath == 0 || ckpt == NULL) {
        goto bcrepo_config_update_epilogue;
    }

    cp = *catalog;

    salt_size = cp->catalog_key_hash_algo_size();
    if ((salt = kryptos_get_random_block(salt_size)) == NULL) {
        fprintf(stderr, "ERROR: Unable to get a random block.\n");
        goto bcrepo_config_update_epilogue;
    }

    bcrepo_mkpath(temp, sizeof(temp) - 1, rootpath, rootpath_size,
              BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE, BCREPO_HIDDEN_DIR_SIZE + BCREPO_CONFIG_FILE_SIZE + 1);

    if ((fp = fopen(temp, "rb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to open the config file.\n");
        goto bcrepo_config_update_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    config_data_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    if ((config_data = (kryptos_u8_t *) kryptos_newseg(config_data_size)) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto bcrepo_config_update_epilogue;
    }

    if (fread(config_data, 1, config_data_size, fp) != config_data_size) {
        fprintf(stderr, "ERROR: Unable to perform a full reading from config file.\n");
        goto bcrepo_config_update_epilogue;
    }

    fclose(fp);
    fp = NULL;

    ktask->in_size = salt_size + config_data_size;
    ktask->in = (kryptos_u8_t *) kryptos_newseg(ktask->in_size);
    if (ktask->in == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto bcrepo_config_update_epilogue;
    }

    memcpy(ktask->in, config_data, config_data_size);
    memcpy(ktask->in + config_data_size, salt, salt_size);

    cp->catalog_key_hash_algo(&ktask, 1);

    if (kryptos_last_task_succeed(ktask) == 0) {
        fprintf(stderr, "ERROR: During hash computation.\n");
        goto bcrepo_config_update_epilogue;
    }

    if (cp->config_hash != NULL) {
        kryptos_freeseg(cp->config_hash, cp->config_hash_size);
    }

    cp->config_hash_size = ktask->out_size + (salt_size << 1);
    cp->config_hash = (kryptos_u8_t *) kryptos_newseg(cp->config_hash_size + 1);
    if (cp->config_hash == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto bcrepo_config_update_epilogue;
    }

    bcrepo_seed_to_hex(temp, sizeof(temp) - 1, salt, salt_size);

    memset(cp->config_hash, 0, cp->config_hash_size + 1);
    memcpy(cp->config_hash, ktask->out, ktask->out_size);
    memcpy(cp->config_hash + ktask->out_size, temp, salt_size << 1);

    no_error = ckpt(ckpt_args);

bcrepo_config_update_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    if (salt != NULL) {
        kryptos_freeseg(salt, salt_size);
    }

    if (config_data != NULL) {
        kryptos_freeseg(config_data, config_data_size);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    cp = NULL;

    return no_error;
}

int bcrepo_config_remove(bfs_catalog_ctx **catalog, const char *rootpath, const size_t rootpath_size,
                         bfs_checkpoint_func ckpt, void *ckpt_args) {
    int no_error = 0;
    bfs_catalog_ctx *cp;
    char temp[4096];

    if (catalog == NULL || rootpath == NULL || rootpath_size == 0 || ckpt == NULL || ckpt_args == NULL) {
        goto bcrepo_config_remove_epilogue;
    }

    bcrepo_mkpath(temp, sizeof(temp) - 1, rootpath, rootpath_size,
                  BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE, BCREPO_HIDDEN_DIR_SIZE + BCREPO_CONFIG_FILE_SIZE + 1);

#if defined(__unix__)
    if (remove(temp) != 0) {
        fprintf(stderr, "ERROR: Unable to remove the config file.\n");
        goto bcrepo_config_remove_epilogue;
    }
#elif defined(_WIN32)
    if (DeleteFile(temp) == 0) {
        fprintf(stderr, "ERROR: Unable to remove the config file.\n");
        goto bcrepo_config_remove_epilogue;
    }
#else
# error Some code wanted.
#endif

    cp = *catalog;

    if (cp->config_hash != NULL) {
        kryptos_freeseg(cp->config_hash, cp->config_hash_size);
        cp->config_hash = NULL;
        cp->config_hash_size = 0;
    }

    no_error = ckpt(ckpt_args);

bcrepo_config_remove_epilogue:

    return no_error;
}

#if defined(__unix__)

static int bcrepo_untouch_directories(const char *rootpath, const size_t rootpath_size) {
    char cwd[4096], *cwd_p;
    int err = EFAULT;
    DIR *dir = NULL;
    struct dirent *dt;
    char *filename = NULL;
    char fullpath[4096];
    struct stat st;
    size_t fullpath_size;
    struct utimbuf tmb;

    if ((cwd_p = getcwd(cwd, sizeof(cwd) - 1)) == NULL) {
        goto bcrepo_untouch_directories_epilogue;
    }

    if (chdir(rootpath) == -1) {
        goto bcrepo_untouch_directories_epilogue;
    }

    if ((dir = opendir(rootpath)) == NULL) {
        goto bcrepo_untouch_directories_epilogue;
    }

    err = 0;

    tmb.actime = BLACKCAT_EPOCH;
    tmb.modtime = BLACKCAT_EPOCH;

    while (err == 0 && (dt = readdir(dir)) != NULL) {
        filename = dt->d_name;

        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
            continue;
        }

        fullpath_size = bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, filename, strlen(filename));

        if (bstat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                err = bcrepo_untouch_directories(fullpath, fullpath_size);
                if (err == 0) {
                    err = utime(fullpath, &tmb);
                }
            }
        }
    }

    if (err == 0) {
        err = utime(rootpath, &tmb);
    }

bcrepo_untouch_directories_epilogue:

    if (cwd_p != NULL) {
        chdir(cwd_p);
    }

    if (dir != NULL) {
        closedir(dir);
    }

    filename = NULL;

    memset(fullpath, 0, sizeof(fullpath));

    memset(&st, 0, sizeof(st));

    dt = NULL;

    return err;
}

int bcrepo_untouch(bfs_catalog_ctx *catalog,
                   const char *rootpath, const size_t rootpath_size,
                   const char *pattern, const size_t pattern_size, const int hard) {
    int touch_nr = 0, done;
    struct utimbuf tmb;
    char fullpath[4096];
    bfs_catalog_relpath_ctx *fp;
    struct stat st;

    if (catalog == NULL) {
        goto bcrepo_untouch_epilogue;
    }

    tmb.actime = BLACKCAT_EPOCH;
    tmb.modtime = BLACKCAT_EPOCH;

    for (fp = catalog->files; fp != NULL; fp = fp->next) {
        if (pattern == NULL || strglob((char *)fp->path, pattern)) {
            bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, (char *)fp->path, fp->path_size);
            done = (hard) ? (utime(fullpath, &tmb) == 0 && setfilectime(fullpath) == 0) : (utime(fullpath, &tmb) == 0);
            if (done) {
                touch_nr++;
            } else {
                fprintf(stderr, "WARN: Unable to set file time attributes for '%s'.\n", fullpath);
            }
        }
    }

    if (touch_nr > 0) {
        // INFO(Rafael): It is important untouch '.bcrepo/CATALOG' and '.bcrepo/CONFIG'.
        //               Otherwise the deniable encryption attempt could be harmed by
        //               leaking file times of those two files.
        bcrepo_catalog_file(fullpath, sizeof(fullpath), rootpath);
        done = (hard) ? (utime(fullpath, &tmb) == 0 && setfilectime(fullpath) == 0) : (utime(fullpath, &tmb) == 0);
        if (!done) {
            fprintf(stderr, "ERROR: When untouching catalog file.\n");
            touch_nr = 0;
            goto bcrepo_untouch_epilogue;
        }
        bcrepo_mkpath(fullpath, sizeof(fullpath) - 1, rootpath, rootpath_size,
                      BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE, BCREPO_HIDDEN_DIR_SIZE + BCREPO_CONFIG_FILE_SIZE + 1);
        if (bstat(fullpath, &st) == 0) {
            done = (hard) ? (utime(fullpath, &tmb) == 0 && setfilectime(fullpath) == 0) : (utime(fullpath, &tmb) == 0);
            if (!done) {
                fprintf(stderr, "ERROR: When untouching config file.\n");
                touch_nr = 0;
                goto bcrepo_untouch_epilogue;
            }
            memset(&st, 0, sizeof(st));
        }
    }

    if (touch_nr > 0 && hard) {
        if (bcrepo_untouch_directories(rootpath, rootpath_size) != 0) {
            touch_nr = 0;
        }
    }

bcrepo_untouch_epilogue:

    return touch_nr;
}

#elif defined(_WIN32)

static int bcrepo_untouch_directories(const char *rootpath, const size_t rootpath_size) {
    char cwd[4096], *cwd_p;
    int err = EFAULT;
    DIR *dir = NULL;
    struct dirent *dt;
    char *filename = NULL;
    char fullpath[4096], *fp;
    struct stat st;
    size_t fullpath_size;

    if ((cwd_p = getcwd(cwd, sizeof(cwd) - 1)) == NULL) {
        goto bcrepo_untouch_directories_epilogue;
    }

    if (chdir(rootpath) == -1) {
        goto bcrepo_untouch_directories_epilogue;
    }

    if ((dir = opendir(rootpath)) == NULL) {
        goto bcrepo_untouch_directories_epilogue;
    }

    err = 0;

    while (err == 0 && (dt = readdir(dir)) != NULL) {
        filename = dt->d_name;

        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
            continue;
        }

        fullpath_size = bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, filename, strlen(filename));

        // INFO(Rafael): I prefer replacing '/' by '\\'. It will no hurt.
        while ((fp = strstr(fullpath, "/")) != NULL) {
            *fp = '\\';
        }

        if (bstat(fullpath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                err = bcrepo_untouch_directories(fullpath, fullpath_size);
                if (err == 0) {
                    // INFO(Rafael): Not hard because the feature behavior must be equal among different platforms.
                    err = setfiletime(fullpath, 0);
                }
            }
        }
    }

    if (err == 0) {
        // INFO(Rafael): Not hard because the feature behavior must be equal among different platforms.
        err = setfiletime(rootpath, 0);
    }

bcrepo_untouch_directories_epilogue:

    if (cwd_p != NULL) {
        chdir(cwd_p);
    }

    if (dir != NULL) {
        closedir(dir);
    }

    filename = NULL;

    memset(fullpath, 0, sizeof(fullpath));

    memset(&st, 0, sizeof(st));

    dt = NULL;

    return err;
}

int bcrepo_untouch(bfs_catalog_ctx *catalog,
                   const char *rootpath, const size_t rootpath_size,
                   const char *pattern, const size_t pattern_size, const int hard) {
    int touch_nr = 0;
    char fullpath[4096];
    bfs_catalog_relpath_ctx *fp;
    struct stat st;

    if (catalog == NULL) {
        goto bcrepo_untouch_epilogue;
    }

    for (fp = catalog->files; fp != NULL; fp = fp->next) {
        if (pattern == NULL || strglob(fp->path, pattern)) {
            bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, fp->path, fp->path_size);
            if (setfiletime(fullpath, hard) == 0) {
                touch_nr++;
            } else {
                fprintf(stderr, "WARN: Unable to set file time attributes for '%s'.\n", fullpath);
            }
        }
    }

    if (touch_nr > 0) {
        // INFO(Rafael): It is important untouch '.bcrepo/CATALOG' and '.bcrepo/CONFIG'.
        //               Otherwise the deniable encryption attempt could be harmed by
        //               leaking file times of those two files.
        bcrepo_catalog_file(fullpath, sizeof(fullpath), rootpath);
        if (setfiletime(fullpath, hard) != 0) {
            fprintf(stderr, "ERROR: When untouching catalog file.\n");
            touch_nr = 0;
            goto bcrepo_untouch_epilogue;
        }
        bcrepo_mkpath(fullpath, sizeof(fullpath) - 1, rootpath, rootpath_size,
                      BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE, BCREPO_HIDDEN_DIR_SIZE + BCREPO_CONFIG_FILE_SIZE + 1);
        if (bstat(fullpath, &st) == 0) {
            if (setfiletime(fullpath, hard) != 0) {
                fprintf(stderr, "ERROR: When untouching config file.\n");
                touch_nr = 0;
                goto bcrepo_untouch_epilogue;
            }
            memset(&st, 0, sizeof(st));
        }
    }

    if (touch_nr > 0 && hard) {
        if (bcrepo_untouch_directories(rootpath, rootpath_size) != 0) {
            touch_nr = 0;
        }
    }

bcrepo_untouch_epilogue:

    return touch_nr;
}

#endif

int bcrepo_detach_metainfo(const char *dest, const size_t dest_size) {
    int no_error = 0;
    char temp[8192];
    kryptos_u8_t *data = NULL;
    size_t data_size;
    FILE *fp = NULL;
    struct stat st;
     char *rootpath = NULL;
    size_t rootpath_size;

    if (dest == NULL ||  dest_size == 0) {
        goto bcrepo_detach_metainfo_epilogue;
    }

    if ((rootpath = bcrepo_get_rootpath()) == NULL) {
        fprintf(stderr, "ERROR: This is not a blackcat repo.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }

    rootpath_size = strlen(rootpath);

#if defined(__unix__)
    snprintf(temp, sizeof(temp) - 1, "%s/" BCREPO_HIDDEN_DIR "/" BCREPO_RESCUE_FILE, rootpath);
#elif defined(_WIN32)
    snprintf(temp, sizeof(temp) - 1, "%s\\" BCREPO_HIDDEN_DIR "\\" BCREPO_RESCUE_FILE, rootpath);
#else
# error Some code wanted.
#endif

    if (bstat(temp, &st) == 0) {
        fprintf(stderr, "ERROR: This repo is locked due to a rescue file. You must handle this issue before detaching.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }

#if defined(__unix__)
    snprintf(temp, sizeof(temp) - 1, "%s/" BCREPO_HIDDEN_DIR "/" BCREPO_CATALOG_FILE, rootpath);
#elif defined(_WIN32)
    snprintf(temp, sizeof(temp) - 1, "%s\\" BCREPO_HIDDEN_DIR "\\" BCREPO_CATALOG_FILE, rootpath);
#else
# error Some code wanted.
#endif

    if ((fp = fopen(temp, "rb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to read from file '%s'.\n", temp);
        goto bcrepo_detach_metainfo_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    data_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    if ((data = kryptos_newseg(data_size)) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }

#if defined(__unix__)
    if (fread(data, 1, data_size, fp) != data_size) {
        fprintf(stderr, "ERROR: While reading catalog's data. '%s'\n", data);
        goto bcrepo_detach_metainfo_epilogue;
    }
#elif defined(_WIN32)
    fread(data, 1, data_size, fp);
    if (ferror(fp) != 0) {
        fprintf(stderr, "ERROR: While reading catalog's data. '%s'\n", data);
        goto bcrepo_detach_metainfo_epilogue;
    }
#else
# error Some code wanted.
#endif

    fclose(fp);

    if ((fp = fopen(dest, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to write to file '%s'.\n", dest);
        goto bcrepo_detach_metainfo_epilogue;
    }

#if defined(__unix__)
    if (fwrite(data, 1, data_size, fp) != data_size) {
        fprintf(stderr, "ERROR: While writing catalog's data.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#elif defined(_WIN32)
    fwrite(data, 1, data_size, fp);
    if (ferror(fp) != 0) {
        fprintf(stderr, "ERROR: While writing catalog's data.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#else
# error Some code wanted.
#endif

    fclose(fp);
    fp = NULL;

#if defined(__unix__)
    if (bfs_data_wiping(rootpath, rootpath_size,
                        BCREPO_HIDDEN_DIR "/" BCREPO_CATALOG_FILE, strlen(BCREPO_HIDDEN_DIR "/" BCREPO_CATALOG_FILE),
                        data_size) == 0) {
        fprintf(stderr, "ERROR: Unable to erase the repo metatinfo.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#elif defined(_WIN32)
    if (bfs_data_wiping(rootpath, rootpath_size,
                        BCREPO_HIDDEN_DIR "\\" BCREPO_CATALOG_FILE, strlen(BCREPO_HIDDEN_DIR "\\" BCREPO_CATALOG_FILE),
                        data_size) == 0) {
        fprintf(stderr, "ERROR: Unable to erase the repo metatinfo.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#else
# error Some code wanted.
#endif

#if defined(__unix__)
    if (remove(temp) != 0) {
        fprintf(stderr, "ERROR: Unable to erase the repo metatinfo.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#elif defined(_WIN32)
    if (DeleteFile(temp) == 0) {
        fprintf(stderr, "ERROR: Unable to erase the repo metainfo.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#else
# error Some code wanted.
#endif

#if defined(__unix__)
    snprintf(temp, sizeof(temp) - 1, "%s/" BCREPO_HIDDEN_DIR, rootpath);
#elif defined(_WIN32)
    snprintf(temp, sizeof(temp) - 1, "%s\\", BCREPO_HIDDEN_DIR, rootpath);
#else
# error Some code wanted.
#endif

#if defined(__unix__)
    if (remove(temp) != 0) {
        fprintf(stderr, "ERROR: Unable to erase the repo metatinfo.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#elif defined(_WIN32)
    if (RemoveDirectory(temp) == 0) {
        fprintf(stderr, "ERROR: Unable to erase the repo metainfo.\n");
        goto bcrepo_detach_metainfo_epilogue;
    }
#else
# error Some code wanted.
#endif

    no_error = 1;

bcrepo_detach_metainfo_epilogue:

    if (no_error == 0) {
        remove(dest);
    }

    memset(temp, 0, sizeof(temp));

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
    }

    if (rootpath != NULL) {
        kryptos_freeseg(rootpath, rootpath_size);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    return no_error;
}

int bcrepo_attach_metainfo(const char *src, const size_t src_size) {
    int no_error = 0;
    struct stat st;
    char temp[8192], cwd[8192];
    char *rootpath = NULL;
    FILE *fp = NULL;
    kryptos_u8_t *data = NULL;
    size_t data_size;

    if (src == NULL ||  src_size == 0) {
        goto bcrepo_attach_metainfo_epilogue;
    }

    if ((rootpath = bcrepo_get_rootpath()) != NULL) {
        fprintf(stderr, "ERROR: It does not seem to be a detached repo.\n");
        goto bcrepo_attach_metainfo_epilogue;
    }

    if (getcwd(cwd, sizeof(cwd) - 1) == NULL) {
        fprintf(stderr, "ERROR: Unable to get the cwd path.\n");
        goto bcrepo_attach_metainfo_epilogue;
    }

#if defined(__unix__)
    snprintf(temp, sizeof(temp) - 1, "%s/" BCREPO_HIDDEN_DIR "/" BCREPO_CATALOG_FILE, cwd);
#elif defined(_WIN32)
    snprintf(temp, sizeof(temp) - 1, "%s\\" BCREPO_HIDDEN_DIR "\\" BCREPO_CATALOG_FILE, cwd);
#else
# error Some code wanted.
#endif

    if (bcrepo_mkdtree(BCREPO_HIDDEN_DIR) != 0) {
        fprintf(stderr, "ERROR: Unable to create the .bcrepo metainfo directory.\n");
        goto bcrepo_attach_metainfo_epilogue;
    }

    if ((fp = fopen(src, "rb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to read from file '%s'.\n", src);
        goto bcrepo_attach_metainfo_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    data_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    if ((data = kryptos_newseg(data_size)) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto bcrepo_attach_metainfo_epilogue;
    }

#if defined(__unix__)
    if (fread(data, 1, data_size, fp) != data_size) {
        fprintf(stderr, "ERROR: While reading metainfo data from '%s'.\n", src);
        goto bcrepo_attach_metainfo_epilogue;
    }
#elif defined(_WIN32)
    fread(data, 1, data_size, fp);
    if (ferror(fp) != 0) {
        fprintf(stderr, "ERROR: While reading metainfo data from '%s'.\n", src);
        goto bcrepo_attach_metainfo_epilogue;
    }
#else
# error Some code wanted.
#endif

    fclose(fp);

    if ((fp = fopen(temp, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to write to file '%s'.\n", temp);
        goto bcrepo_attach_metainfo_epilogue;
    }

#if defined(__unix__)
    if (fwrite(data, 1, data_size, fp) != data_size) {
        fprintf(stderr, "ERROR: While writing catalog's data.\n");
        goto bcrepo_attach_metainfo_epilogue;
    }
#elif defined(_WIN32)
    fwrite(data, 1, data_size, fp);
    if (ferror(fp) != 0) {
        fprintf(stderr, "ERROR: While writing catalog's data.\n");
        goto bcrepo_attach_metainfo_epilogue;
    }
#else
# error Some code wanted.
#endif

    fclose(fp);
    fp = NULL;

    no_error = 1;

bcrepo_attach_metainfo_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
    }

    return no_error;
}

int bcrepo_info(bfs_catalog_ctx *catalog) {
    int no_error = 0;

    if (catalog == NULL) {
        goto bcrepo_info_epilogue;
    }

    fprintf(stdout, " .bcrepo\n");
    fprintf(stdout, " |_ bc-version: %s\n", catalog->bc_version);
    fprintf(stdout, " |_ catalog-hash: %s\n", get_hash_processor_name(catalog->catalog_key_hash_algo));
    fprintf(stdout, " |_ key-hash: %s", get_hash_processor_name(catalog->key_hash_algo));
    if (catalog->key_hash_algo == blackcat_bcrypt) {
        fprintf(stdout, " (cost=%d)", (catalog->key_hash[4] - '0') * 10 + (catalog->key_hash[5] - '0'));
    }
    if (catalog->kdf_params != NULL) {
        fprintf(stdout, "\n");
        bcrepo_info_kdf_params(catalog->kdf_params, catalog->kdf_params_size);
    }
    fprintf(stdout, "\n");
    fprintf(stdout, " |_ protection-layer-hash: %s\n", get_hash_processor_name(catalog->protlayer_key_hash_algo));
    fprintf(stdout, " |_ protection-layer: %s");
    bcrepo_info_print_ext_ascii_data(catalog->protection_layer, catalog->protection_layer_size);
    fprintf(stdout, "\n");
    fprintf(stdout, " |_ cascade type: %s\n", (catalog->otp) ? "one-time pad" : "single flow");
    fprintf(stdout, " |_ encoder: %s\n", get_encoder_name(catalog->encoder));

    no_error = 1;

bcrepo_info_epilogue:

    return no_error;
}

int bcrepo_decoy(const char *filepath, const size_t chaff_size, blackcat_encoder encoder, const int otp, const int overwrite) {
    FILE *fp = NULL;
    kryptos_u8_t *chaff = NULL, *pem = NULL;
    int no_error = 0;
    kryptos_task_ctx t, *ktask = &t;
    size_t temp_size, pem_size;
    struct stat st;
    int del_file = 1;

    kryptos_task_init_as_null(ktask);

    if (filepath == NULL || chaff_size == 0) {
        goto bcrepo_decoy_epilogue;
    }

    if (!overwrite && bstat(filepath, &st) == 0) {
        fprintf(stderr, "ERROR: The file '%s' already exists. Retry using the overwrite flag to go ahead.\n", filepath);
        del_file = 0;
        goto bcrepo_decoy_epilogue;
    }

    if ((fp = fopen(filepath, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to create the file '%s'.\n", filepath);
        goto bcrepo_decoy_epilogue;
    }

    if ((chaff = kryptos_get_random_block(chaff_size)) == NULL) {
        fprintf(stderr, "ERROR: Unable to get random data.\n");
        goto bcrepo_decoy_epilogue;
    }

    if (otp) {
        if (kryptos_pem_put_data(&pem, &pem_size, BLACKCAT_OTP_D, chaff, chaff_size) != kKryptosSuccess) {
            fprintf(stderr, "ERROR: Unable to encode into a PEM buffer.\n");
            goto bcrepo_decoy_epilogue;
        }
        kryptos_freeseg(chaff, chaff_size);
        chaff = pem;
        temp_size = pem_size;
        pem = NULL;
        pem_size = 0;
    } else if (encoder == NULL) {
        temp_size = chaff_size;
    }

    if (encoder != NULL) {
        kryptos_task_set_encode_action(ktask);
        kryptos_task_set_in(ktask, chaff, chaff_size);

        encoder(&ktask);

        if (!kryptos_last_task_succeed(ktask)) {
            fprintf(stderr, "ERROR: While encoding the random data.\n");
            goto bcrepo_decoy_epilogue;
        }

        chaff = ktask->out;
        temp_size = ktask->out_size;
    }

    if (fwrite(chaff, 1, temp_size, fp) != temp_size) {
        fprintf(stderr, "ERROR: Unable to write to '%s'.\n", filepath);
        goto bcrepo_decoy_epilogue;
    }

    no_error = 1;

bcrepo_decoy_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    if (no_error == 0 && del_file && filepath != NULL) {
#if defined(__unix__)
        remove(filepath);
#elif defined(_WIN32)
        DeleteFile(filepath);
#else
# error Some code wanted.
#endif
    }

    if (encoder != NULL) {
        kryptos_task_free(ktask, KRYPTOS_TASK_IN);
    }

    if (chaff != NULL) {
        kryptos_freeseg(chaff, temp_size);
        chaff = NULL;
        temp_size = 0;
    }

    if (pem != NULL) {
        kryptos_freeseg(pem, pem_size);
    }

    return no_error;
}

int bcrepo_restore(const bfs_catalog_ctx *catalog, const char *rootpath, const size_t rootpath_size) {
    FILE *fp = NULL;
    int no_error = 0;
    char rescue_file_hdr[8192], rescue_filepath[4096];
    char filepath[4096], *rp, *rp_end;
    bfs_catalog_relpath_ctx *file;
    size_t data_size, filepath_size;
    kryptos_u8_t *data = NULL;

    bcrepo_rescue_file(rescue_filepath, sizeof(rescue_filepath), rootpath);

    if ((fp = fopen(rescue_filepath, "rb")) == NULL) {
        fprintf(stderr, "ERROR: The repo seems clean, there is nothing to restore here.\n");
        goto bcrepo_restore_epilogue;
    }

    memset(rescue_file_hdr, 0, sizeof(rescue_file_hdr));
    fgets(rescue_file_hdr, sizeof(rescue_file_hdr) - 1, fp);

    rp = &rescue_file_hdr[0];
    rp_end = rp + strlen(rescue_file_hdr);
    rp_end -= 1;
    *rp_end = 0;

    while (rp != rp_end && *rp != ',') {
        rp++;
    }

    if (*rp != ',') {
        fprintf(stderr, "ERROR: The rescue file seems corrupted.\n");
        goto bcrepo_restore_epilogue;
    }

    filepath_size = (rp - &rescue_file_hdr[0]);

    if (filepath_size > sizeof(filepath)) {
        fprintf(stderr, "ERROR: The file path is too long to be restored.\n");
        goto bcrepo_restore_epilogue;
    }

    memset(filepath, 0, sizeof(filepath));
    memcpy(filepath, rescue_file_hdr, filepath_size);

    data_size = strtoul(rp + 1, NULL, 10);

    rp = &filepath[0] + rootpath_size;

    if ((file = get_entry_from_relpath_ctx(catalog->files, (kryptos_u8_t *)rp)) == NULL) {
        fprintf(stderr, "ERROR: There is nothing to restore.\n");
        fclose(fp);
        fp = NULL;
        bcrepo_remove_rescue_file(rootpath, rootpath_size); // INFO(Rafael): MUaAhauahuahauhauah!
        goto bcrepo_restore_epilogue;
    }

    if ((data = (kryptos_u8_t *) kryptos_newseg(data_size)) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to perform a restore.\n");
        goto bcrepo_restore_epilogue;
    }

    if (fread(data, 1, data_size, fp) != data_size) {
        fprintf(stderr, "ERROR: Unable to get the exact previous amount of bytes to restore.\n"
                        "TIP: If the rescue file was edited, give up and remove it on your own otherwise "
                        "your repo will remain locked.\n");
        goto bcrepo_restore_epilogue;
    }

    fclose(fp);

    if ((fp = fopen(filepath, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to re-create the file '%s'.\n", filepath);
        goto bcrepo_restore_epilogue;
    }

    if ((fwrite(data, 1, data_size, fp)) != data_size) {
        fprintf(stderr, "ERROR: Unable to write the exact previous amount of bytes to conclude the restore process.\n"
                        "TIP: If the file is really important restore it by hand, otherwise give up and remove the rescue "
                        "file because your repo will remain locked.\n");
        goto bcrepo_restore_epilogue;
    }

    fclose(fp);

    fp = NULL;

    no_error = 1;

bcrepo_restore_epilogue:

    if (fp != NULL) {
        fclose(fp);
    }

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
        data_size = 0;
        data = NULL;
    }

    if (no_error) {
        no_error = bcrepo_remove_rescue_file(rootpath, rootpath_size);
        if (no_error == 0) {
            fprintf(stderr, "WARN: Remove the rescue file on your own. Btw, if it is plain, you should apply some data wiping,"
                            " just saying.\n");
        }
    }

    return no_error;
}

int bcrepo_bury(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return bdup_handle(BLACKCAT_BURY, catalog, rootpath, rootpath_size, pattern, pattern_size);
}

int bcrepo_dig_up(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size) {
    return bdup_handle(BLACKCAT_DIG_UP, catalog, rootpath, rootpath_size, pattern, pattern_size);
}

int bcrepo_reset_repo_settings(bfs_catalog_ctx **catalog,
                               const char *rootpath, const size_t rootpath_size,
                               kryptos_u8_t *catalog_key, const size_t catalog_key_size,
                               kryptos_u8_t **protlayer_key, size_t *protlayer_key_size,
                               const char *protection_layer,
                               char *kdf_params, size_t kdf_params_size,
                               blackcat_hash_processor catalog_hash_proc,
                               blackcat_hash_processor key_hash_proc,
                               void *key_hash_proc_args,
                               blackcat_hash_processor protlayer_hash_proc,
                               blackcat_encoder encoder,
                               bfs_checkpoint_func ckpt,
                               void *ckpt_args) {
    bfs_catalog_ctx *cp = *catalog;
    char filepath[4096];
    int no_error = 1;
    size_t temp_size, temp_size2;
    int inv_cascade_type;
    struct blackcat_keychain_handle_ctx handle;
    char *temp = NULL;

    inv_cascade_type = (cp->otp && cp->encrypt_data != blackcat_otp_encrypt_data) ||
                       (!cp->otp && cp->encrypt_data != blackcat_encrypt_data);

    if (inv_cascade_type) {
        cp->otp = !cp->otp;
    }

    bcrepo_unlock(catalog, rootpath, rootpath_size, "*", 1, ckpt, ckpt_args);

    if (inv_cascade_type) {
        cp->otp = !cp->otp;
    }

    if ((temp_size = strlen(cp->bc_version)) < (temp_size2 = strlen(BCREPO_METADATA_VERSION))) {
        temp = cp->bc_version;
        cp->bc_version = (char *) kryptos_newseg(temp_size2 + 1);
        if (cp->bc_version == NULL) {
            temp = NULL;
        }
    }

    memset(cp->bc_version, 0, temp_size2 + 1);
    memcpy(cp->bc_version, BCREPO_METADATA_VERSION, temp_size2);

    if (temp != NULL) {
        kryptos_freeseg(temp, temp_size);
        temp = NULL;
    }

    cp->catalog_key_hash_algo = catalog_hash_proc;
    cp->catalog_key_hash_algo_size = get_hash_size(get_hash_processor_name(catalog_hash_proc));
    cp->key_hash_algo = key_hash_proc;
    cp->key_hash_algo_size = get_hash_size(get_hash_processor_name(key_hash_proc));

    kryptos_freeseg(cp->key_hash, cp->key_hash_size);

    cp->key_hash = bcrepo_hash_key(*protlayer_key, *protlayer_key_size,
                                   cp->key_hash_algo, key_hash_proc_args, &cp->key_hash_size);

    if (cp->key_hash == NULL) {
        fprintf(stderr, "ERROR: While trying to hash the user key.\n");
        no_error = 0;
        goto bcrepo_reset_repo_settings_epilogue;
    }

    cp->protlayer_key_hash_algo = protlayer_hash_proc;
    cp->protlayer_key_hash_algo_size = get_hash_size(get_hash_processor_name(protlayer_hash_proc));

    cp->encoder = encoder;

    if (protection_layer != NULL) {
        cp->protection_layer_size = strlen(protection_layer);
        cp->protection_layer = (char *)kryptos_newseg(cp->protection_layer_size + 1);

        if (cp->protection_layer == NULL) {
            no_error = 0;
            fprintf(stderr, "ERROR: Not enough memory.\n");
            goto bcrepo_reset_repo_settings_epilogue;
        }

        memset(cp->protection_layer, 0, cp->protection_layer_size + 1);
        memcpy(cp->protection_layer, protection_layer, cp->protection_layer_size);

        if (cp->protlayer != NULL) {
            del_protlayer_chain_ctx(cp->protlayer);
            cp->protlayer = NULL;
        }

        if (cp->kdf_params != NULL && kdf_params != cp->kdf_params) {
            kryptos_freeseg(cp->kdf_params, cp->kdf_params_size);
            cp->kdf_params = kdf_params;
            cp->kdf_params_size = kdf_params_size;
        }

        handle.hash = protlayer_hash_proc;
        handle.kdf_clockwork = (cp->kdf_params != NULL) ? get_kdf_clockwork(cp->kdf_params, cp->kdf_params_size, NULL) : NULL;

        if (cp->kdf_params != NULL && handle.kdf_clockwork == NULL) {
            handle.hash = NULL;
            no_error = 0;
            fprintf(stderr, "ERROR: Unable to create KDF clockwork.\n");
            goto bcrepo_reset_repo_settings_epilogue;
        }

        cp->protlayer = add_composite_protlayer_to_chain(cp->protlayer, cp->protection_layer, cp->protection_layer_size,
                                                         protlayer_key, protlayer_key_size,
                                                         &handle, cp->encoder);

        handle.hash = NULL;

        if (handle.kdf_clockwork != NULL) {
            del_blackcat_kdf_clockwork_ctx(handle.kdf_clockwork);
            handle.kdf_clockwork = NULL;
        }

        if (cp->protlayer == NULL) {
            fprintf(stderr, "ERROR: While reconstructing the protection layer.\n");
            no_error = 0;
            goto bcrepo_reset_repo_settings_epilogue;
        }
    }

    if (cp->otp) {
        cp->encrypt_data = blackcat_otp_encrypt_data;
        cp->decrypt_data = blackcat_otp_decrypt_data;
    } else {
        cp->encrypt_data = blackcat_encrypt_data;
        cp->decrypt_data = blackcat_decrypt_data;
    }

    bcrepo_lock(catalog, rootpath, rootpath_size, "*", 1, ckpt, ckpt_args);

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
        bcrepo_lock(catalog, rootpath, rootpath_size, "*", 1, ckpt, ckpt_args);
    }

    memset(catalog_key, 0, catalog_key_size);

    return no_error;
}

int bcrepo_pack(bfs_catalog_ctx **catalog, const char *rootpath, const size_t rootpath_size,
                             const char *wpath, bfs_checkpoint_func ckpt, void *ckpt_args) {
    bfs_catalog_relpath_ctx *fp = NULL;
    bfs_catalog_ctx *cp = *catalog;
    FILE *wp = NULL, *wpp = NULL;
    int no_error = 1;
    char filepath[4096];
    kryptos_u8_t *data = NULL;
    size_t data_size = 0;
    struct stat st;

    bcrepo_lock(catalog, rootpath, rootpath_size, "*", 1, ckpt, ckpt_args);

    if ((wp = fopen(wpath, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to create the file '%s'.\n", wpath);
        no_error = 0;
        goto bcrepo_pack_epilogue;
    }

#define roll_data(filepath, curr_path, wp, wpp, data, data_size, no_error) {\
    if ((wpp = fopen(filepath, "rb")) == NULL) {\
        fprintf(stderr, "ERROR: Unable to read the file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_pack_epilogue;\
    }\
    fseek(wpp, 0L, SEEK_END);\
    data_size = (size_t) ftell(wpp);\
    fseek(wpp, 0L, SEEK_SET);\
    if ((data = (kryptos_u8_t *) kryptos_newseg(data_size)) == NULL) {\
        fprintf(stderr, "ERROR: Not enough memory.\n");\
        no_error = 0;\
        goto bcrepo_pack_epilogue;\
    }\
    if (fread(data, 1, data_size, wpp) == -1) {\
        fprintf(stderr, "ERROR: Unable to read data from file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_pack_epilogue;\
    }\
    fclose(wpp);\
    wpp = NULL;\
    fprintf(wp, "%s,%d\n", curr_path, data_size);\
    if (fwrite(data, 1, data_size, wp) == -1) {\
        fprintf(stderr, "ERROR: Unable to write data to file '%s'.\n", wpath);\
        no_error = 0;\
        goto bcrepo_pack_epilogue;\
    }\
    kryptos_freeseg(data, data_size);\
    data = NULL;\
}

    bcrepo_catalog_file(filepath, sizeof(filepath) - 1, rootpath);

    roll_data(filepath, BCREPO_HIDDEN_DIR "/" BCREPO_CATALOG_FILE, wp, wpp, data, data_size, no_error)

    bcrepo_mkpath(filepath, sizeof(filepath) - 1, rootpath, rootpath_size,
                  BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE,
                  BCREPO_HIDDEN_DIR_SIZE + BCREPO_CONFIG_FILE_SIZE + 1);

    if (bstat(filepath, &st) == 0) {
        roll_data(filepath, BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE, wp, wpp, data, data_size, no_error)
    }

    for (fp = cp->files; fp != NULL; fp = fp->next) {
        bcrepo_mkpath(filepath, sizeof(filepath) - 1, rootpath, rootpath_size, (char *)fp->path, fp->path_size);
        roll_data(filepath, fp->path, wp, wpp, data, data_size, no_error)
    }

#undef roll_data

    fclose(wp);
    wp = NULL;

bcrepo_pack_epilogue:

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
        data_size = 0;
    }

    if (wpp != NULL) {
        fclose(wpp);
    }

    if (wp != NULL) {
        fclose(wp);
#if defined(__unix__)
        remove(wpath);
#elif defined(_WIN32)
        DeleteFile(wpath);
#else
# error Some code wanted.
#endif
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
        fprintf(stderr, "ERROR: You are inside a previously initialized repo.\n");
        no_error = 0;
        goto bcrepo_unpack_epilogue;
    }

    if ((wool = fopen(wpath, "rb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to read the file '%s'.\n", wpath);
        no_error = 0;
        goto bcrepo_unpack_epilogue;
    }

    fseek(wool, 0L, SEEK_END);
    wp_data_size = ftell(wool);
    fseek(wool, 0L, SEEK_SET);

    if ((wp_data = (kryptos_u8_t *) kryptos_newseg(wp_data_size)) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        no_error = 0;
        wp_data_size = 0;
        goto bcrepo_unpack_epilogue;
    }

    if (fread(wp_data, 1, wp_data_size, wool) == -1) {
        fprintf(stderr, "ERROR: Unable to read data from file '%s'.\n", wpath);
        no_error = 0;
        goto bcrepo_unpack_epilogue;
    }

    fclose(wool);
    wool = NULL;

    if (rootpath != NULL) {
        if (bcrepo_mkdtree(rootpath) != 0) { 
            fprintf(stderr, "ERROR: Unable to create the directory path '%s'.\n", rootpath);
            no_error = 0;
            goto bcrepo_unpack_epilogue;
        }
        getcwd(oldcwd, sizeof(oldcwd) - 1);
        if (chdir(rootpath) != 0) {
            fprintf(stderr, "ERROR: Unable to change the current work directory.");\
            no_error = 0;
            goto bcrepo_unpack_epilogue;
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
        goto bcrepo_unpack_epilogue;\
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
        goto bcrepo_unpack_epilogue;\
    }\
    memcpy(data, wp, data_size);\
    wp += data_size;\
    off = (kryptos_u8_t *)&filepath[strlen((char *)filepath) - 1];\
    while (off != (kryptos_u8_t *)&filepath[0] && *off != '/') {\
        off--;\
    }\
    if ((off - (kryptos_u8_t *)&filepath[0]) > 0) {\
        memset(temp, 0, temp_size);\
        memcpy(temp, filepath, off - (kryptos_u8_t *)&filepath[0]);\
        if (bcrepo_mkdtree(temp) != 0) {\
            fprintf(stderr, "ERROR: Unable to create the directory path '%s'.\n", temp);\
            no_error = 0;\
            goto bcrepo_unpack_epilogue;\
        }\
    }\
    if ((fp = fopen(filepath, "wb")) == NULL) {\
        fprintf(stderr, "ERROR: Unable to create the file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_unpack_epilogue;\
    }\
    if (fwrite(data, 1, data_size, fp) == -1) {\
        fprintf(stderr, "ERROR: Unable to dump data to file '%s'.\n", filepath);\
        no_error = 0;\
        goto bcrepo_unpack_epilogue;\
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

bcrepo_unpack_epilogue:

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

static void bcrepo_info_kdf_params(const char *kdf_params, const size_t kdf_params_size) {
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = get_kdf_clockwork(kdf_params, kdf_params_size, NULL);

    if (kdf_clockwork == NULL) {
        // INFO(Rafael): In normal conditions it should never happen.
        fprintf(stderr, "ERROR: Unable to get KDF clockwork.\n");
        return;
    }

    fprintf(stdout, " |_ kdf-params: .%s\n", get_kdf_name(kdf_clockwork->kdf));

    if (kdf_clockwork->kdf == blackcat_hkdf) {
        fprintf(stdout, " |              |_ hkdf-hash: %s\n",
                get_hash_processor_name((blackcat_hash_processor)kdf_clockwork->arg_data[0]));
        fprintf(stdout, " |              |_ hkdf-salt: ");
        bcrepo_info_print_ext_ascii_data(kdf_clockwork->arg_data[3], kdf_clockwork->arg_size[3]);
        fprintf(stdout, "\n");
        fprintf(stdout, " |              |_ hkdf-info: ");
        bcrepo_info_print_ext_ascii_data(kdf_clockwork->arg_data[5], kdf_clockwork->arg_size[5]);
        fprintf(stdout, "\n");
    } else if (kdf_clockwork->kdf == blackcat_pbkdf2) {
        fprintf(stdout, " |              |_ pbkdf2-hash: %s\n",
                get_hash_processor_name((blackcat_hash_processor)kdf_clockwork->arg_data[0]));
        fprintf(stdout, " |              |_ pbkdf2-salt: ");
        bcrepo_info_print_ext_ascii_data(kdf_clockwork->arg_data[3], kdf_clockwork->arg_size[3]);
        fprintf(stdout, "\n");
        fprintf(stdout, " |              |_ pbkdf2-count: %d\n", *((size_t *)kdf_clockwork->arg_data[5]));
    } else if (kdf_clockwork->kdf == blackcat_argon2i) {
        fprintf(stdout, " |              |_ argon2i-salt: ");
        bcrepo_info_print_ext_ascii_data(kdf_clockwork->arg_data[0], kdf_clockwork->arg_size[0]);
        fprintf(stdout, "\n");
        fprintf(stdout, " |              |_ argon2i-memory: %d\n", *((kryptos_u32_t *)kdf_clockwork->arg_data[2]));
        fprintf(stdout, " |              |_ argon2i-iterations: %d\n", *((kryptos_u32_t *)kdf_clockwork->arg_data[3]));
        fprintf(stdout, " |              |_ argon2i-key: ");
        bcrepo_info_print_ext_ascii_data(kdf_clockwork->arg_data[4], kdf_clockwork->arg_size[4]);
        fprintf(stdout, "\n");
        fprintf(stdout, " |              |_ argon2i-aad: ");
        bcrepo_info_print_ext_ascii_data(kdf_clockwork->arg_data[6], kdf_clockwork->arg_size[6]);
        fprintf(stdout, "\n");
    }

    fprintf(stdout, " |");

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
}

static void bcrepo_info_print_ext_ascii_data(const void *data, const size_t data_size) {
    const kryptos_u8_t *d, *d_end;

    if (data == NULL || data_size == 0) {
        fprintf(stdout, "(null)");
        return;
    }

    d = (const kryptos_u8_t *)data;
    d_end = (const kryptos_u8_t *)d + data_size;

    while (d != d_end) {
        if (!isprint(*d)) {
            fprintf(stdout, "\\x%.2X", *d);
        } else {
            fprintf(stdout, "%c", *d);
        }
        d++;
    }
}

#if defined(__unix__)
static int setfilectime(const char *path) {
    // WARN(Rafael): As you should know, in Unix by default (Yo!), we cannot set the creation time (ctime) of a file
    //               by using any Posix function. Functions such as utime(), utimes() are capable of only set
    //               the access time and/or the modification time of a file.
    //
    //               However, the creation time can be indirectly set when the file is created (sorry, obvious) and also when
    //               its attributes are changed. Taking into consideration this system behavior, setfilectime() will:
    //
    //                          - get the current system time;
    //                          - change the system time to BLACKCAT_EPOCH (11/05/1970 16:05:00);
    //                          - will the the original file permissions;
    //                          - change the file permissions (0777);
    //                          - change it back to the original ones;
    //                          - re-adjust the system time to the current time (considering the elapsed time);
    //
    //               A noisy but effective function.
    //
    struct timeval tv_old, bc_epch, tv_curr;
    struct timezone tz_old;
    int err, tset = 0;
    struct stat st_old;
    mode_t temp_mode;

    if ((err = gettimeofday(&tv_old, &tz_old)) != 0) {
        goto setfilectime_epilogue;
    }

    tset = 1;

    bc_epch.tv_sec = BLACKCAT_EPOCH;
    bc_epch.tv_usec = 0;

    if ((err = settimeofday(&bc_epch, &tz_old)) != 0) {
        goto setfilectime_epilogue;
    }

    if ((err = bstat(path, &st_old)) != 0) {
        goto setfilectime_epilogue;
    }

    tset |= 2;

    temp_mode = S_IRUSR | S_IWUSR | S_IXUSR |
                S_IRGRP | S_IWGRP | S_IXGRP |
                S_IROTH | S_IWOTH | S_IXOTH;

    if ((err = chmod(path, temp_mode)) != 0) {
        goto setfilectime_epilogue;
    }

setfilectime_epilogue:

    if (tset & 2) {
        chmod(path, st_old.st_mode);
    }

    if (tset & 1) {
        gettimeofday(&tv_curr, &tz_old);
        tv_old.tv_sec += (tv_curr.tv_sec - bc_epch.tv_sec);
        settimeofday(&tv_old, &tz_old);
    }

    return err;
}
#elif defined(_WIN32)
static int setfiletime(const char *path, const int hard) {
    // INFO(Rafael): It sets the creation date time to "BLACKCAT_EPOCH" (11/05/1970 16:05:00)
    FILETIME ftime;
    HANDLE h;
    int err;

    // INFO(Rafael): We will try anyway, even it failing.

    if ((h = CreateFile(path,
                        GENERIC_WRITE,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_BACKUP_SEMANTICS, NULL)) == INVALID_HANDLE_VALUE) {
        return ENOENT;
    }

    ftime.dwLowDateTime = BLACKCAT_EPOCH_L;
    ftime.dwHighDateTime = BLACKCAT_EPOCH_H;

    err = (SetFileTime(h, (hard) ? &ftime : NULL, &ftime, &ftime) != 0) ? 0 : EFAULT;

    CloseHandle(h);

    return err;
}
#endif

static int create_rescue_file(const char *rootpath, const size_t rootpath_size, const char *path, const size_t path_size,
                              const kryptos_u8_t *data, const size_t data_size) {
    char rescue_filepath[4096], fullpath[4096];
    FILE *rp;
    struct stat st;

    if (bcrepo_mkpath(fullpath, sizeof(fullpath), rootpath, rootpath_size, path, path_size) == 0) {
        fprintf(stderr, "ERROR: The rescue file path is too long.\n");
        return 0;
    }

    bcrepo_rescue_file(rescue_filepath, sizeof(rescue_filepath), rootpath);

    if (bstat(rescue_filepath, &st) == 0) {
        fprintf(stderr, "ERROR: Error while creating a rescue file. You must remove the file '%s' manually.\n",
                         rescue_filepath);
        return 0;
    }

    if ((rp = fopen(rescue_filepath, "wb")) == NULL) {
        fprintf(stderr, "ERROR: Unable to create the rescue file.\n");
        return 0;
    }

    fprintf(rp, "%s,%zu\n", fullpath, data_size);
    fwrite(data, 1, data_size, rp);
    fclose(rp);

    return 1;
}

static int bstat(const char *pathname, struct stat *buf) {
    int err = -1, fd;

    if ((err = stat(pathname, buf)) != 0) {
        if ((fd = open(pathname, O_RDONLY)) > -1) {
            err = fstat(fd, buf);
            close(fd);
        }
    }

    return err;
}

static int bdup_handle(unsigned long cmd,
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
        if (pattern == NULL || strglob((char *)fp->path, pattern) == 1) {
            if (do_ioctl(cmd, fp->path, fp->path_size) == 0) {
                count += 1;
            } else {
                perror("do_ioctl()");
            }
        }
    }

    return count;
}

#if defined(__unix__)
static int do_ioctl(unsigned long cmd, const unsigned char *path, const size_t path_size) {
    int dev;
    int err = 0;
    const unsigned char *rp, *rp_end;
    struct blackcat_devio_ctx devio;

    if ((dev = open(BLACKCAT_DEVPATH, O_WRONLY)) == -1) {
        return ENODEV;
    }

    rp = path;
    rp_end = path + path_size;

    while (rp_end != rp && *rp_end != '/') {
        rp_end--;
    }

    devio.data = (unsigned char *)rp_end + (*rp_end == '/');
    devio.data_size = strlen((char *)devio.data);

    err = ioctl(dev, cmd, &devio);

    devio.data = NULL;
    devio.data_size = 0;

    close(dev);

    return err;
}
#elif defined(_WIN32)
static int do_ioctl(unsigned long cmd, const unsigned char *path, const size_t path_size) {
    return 1;
}
#endif

static int bcrepo_mkdtree(const char *dirtree) {
    mode_t oldmask;
    const char *d, *d_end, *s;
    char dir[4096];
    char oldcwd[4096];
    int exit_code = 0;
    struct stat st;

    if (bstat(dirtree, &st) == 0) {
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

#if defined(__unix__)
        exit_code = mkdir(dir, 0644);
#else
        exit_code = mkdir(dir);
#endif

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
#if defined(__unix__)
    snprintf(buf, buf_size - 1, "%s/%s/%s", rootpath, BCREPO_HIDDEN_DIR, BCREPO_CATALOG_FILE);
#elif defined(_WIN32)
    snprintf(buf, buf_size - 1, "%s\\%s\\%s", rootpath, BCREPO_HIDDEN_DIR, BCREPO_CATALOG_FILE);
#else
# error Some code wanted.
#endif
    return buf;
}

char *bcrepo_rescue_file(char *buf, const size_t buf_size, const char *rootpath) {
    if (rootpath == NULL || buf == NULL || buf_size == 0) {
        return buf;
    }
    memset(buf, 0, buf_size);
    if ((strlen(rootpath) + BCREPO_HIDDEN_DIR_SIZE + BCREPO_RESCUE_FILE_SIZE) >= buf_size - 1) {
        return buf;
    }
#if defined(__unix__)
    snprintf(buf, buf_size - 1, "%s/%s/%s", rootpath, BCREPO_HIDDEN_DIR, BCREPO_RESCUE_FILE);
#elif defined(_WIN32)
    snprintf(buf, buf_size - 1, "%s\\%s\\%s", rootpath, BCREPO_HIDDEN_DIR, BCREPO_RESCUE_FILE);
#else
# error Some code wanted.
#endif
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

#if defined(__unix__)
    if (mkdir(BCREPO_HIDDEN_DIR, 0644) != 0) {
        no_error = 0;
        fprintf(stderr, "ERROR: Unable to initialize the current working directory as a blackcat repo.\n");
        goto bcrepo_init_epilogue;
    }
#else
    if (mkdir(BCREPO_HIDDEN_DIR) != 0) {
        no_error = 0;
        fprintf(stderr, "ERROR: Unable to initialize the current working directory as a blackcat repo.\n");
        goto bcrepo_init_epilogue;
    }
#endif

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
    struct stat st;

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

#if defined(__unix__)
    if (remove(filepath) != 0) {
        no_error = 0;
        fprintf(stderr, "ERROR: Unable to remove the file '%s'.\n", filepath);
        goto bcrepo_deinit_epilogue;
    }
#elif defined(_WIN32)
    if (DeleteFile(filepath) == 0) {
        no_error = 0;
        fprintf(stderr, "ERROR: Unable to remove the file '%s'.\n", filepath);
        goto bcrepo_deinit_epilogue;
    }
#else
# error Some code wanted.
#endif

    temp_size = bcrepo_mkpath(filepath, sizeof(filepath), rootpath, rootpath_size,
                              BCREPO_HIDDEN_DIR "/" BCREPO_CONFIG_FILE,
                              BCREPO_HIDDEN_DIR_SIZE + BCREPO_CONFIG_FILE_SIZE + 1);

    if (bstat(filepath, &st) == 0) {
        if (bfs_data_wiping(rootpath, rootpath_size,
                            filepath + rootpath_size + 1, filepath_size - rootpath_size + 1, temp_size) == 0) {
            fprintf(stderr, "WARN: Unable to perform data wiping over the file '%s'\n", filepath);
            fprintf(stderr, "      If you are paranoid enough you should run a data wiping software"
                            " over your entire storage device.\n");
        }

#if defined(__unix__)
        if (remove(filepath) != 0) {
            no_error = 0;
            fprintf(stderr, "ERROR: Unable to remove the file '%s'.\n", filepath);
            goto bcrepo_deinit_epilogue;
        }
#elif defined(_WIN32)
        if (DeleteFile(filepath) == 0) {
            no_error = 0;
            fprintf(stderr, "ERROR: Unable to remove the file '%s'.\n", filepath);
            goto bcrepo_deinit_epilogue;
        }
#else
# error Some code wanted.
#endif
    }

    temp_size = 0;

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
                  const char *pattern, const size_t pattern_size,
                  bfs_checkpoint_func ckpt,
                  void *ckpt_args) {
    return unl_handle(catalog, rootpath, rootpath_size, pattern, pattern_size, unl_handle_encrypt, ckpt, ckpt_args);
}

int bcrepo_unlock(bfs_catalog_ctx **catalog,
                  const char *rootpath, const size_t rootpath_size,
                  const char *pattern, const size_t pattern_size,
                  bfs_checkpoint_func ckpt,
                  void *ckpt_args) {
    return unl_handle(catalog, rootpath, rootpath_size, pattern, pattern_size, unl_handle_decrypt, ckpt, ckpt_args);
}

int bcrepo_rm(bfs_catalog_ctx **catalog,
              const char *rootpath, const size_t rootpath_size,
              const char *pattern, const size_t pattern_size, const int force) {
    int rm_nr = 0;
    bfs_catalog_relpath_ctx *files = NULL, *fp, *fpp;
    bfs_catalog_ctx *cp;
    int rl = 0, again;

    if (catalog == NULL) {
        goto bcrepo_rm_epilogue;
    }

    cp = *catalog;

    get_file_list(&files, NULL, rootpath, rootpath_size, pattern, pattern_size, &rl, BCREPO_RECUR_LEVEL_LIMIT);

    again = 1;

    while (again) {
        again = 0;
        for (fp = files; fp != NULL && !again; fp = fp->next) {
            if ((fpp = get_entry_from_relpath_ctx(cp->files, fp->path)) == NULL) {
                continue;
            }

            if (fpp->status == kBfsFileStatusLocked &&
                bcrepo_unlock(catalog, rootpath, rootpath_size, (char *)fpp->path, fpp->path_size, NULL, NULL) != 1) {
                fprintf(stderr, "WARN: Unable to unlock the file '%s'.\n", fpp->path);
            }

            cp->files = del_file_from_relpath_ctx(cp->files, fpp->path);

            rm_nr++;
            again = 1;
        }
    }

    if (force) {
        again = 1;
        while (again) {
            fp = cp->files;
            again = 0;
            while (fp != NULL && !again) {
                if (strglob((char *)fp->path, pattern) == 1) {
                    cp->files = del_file_from_relpath_ctx(cp->files, fp->path);
                    rm_nr++;
                    again = 1;
                } else {
                    fp = fp->next;
                }
            }
        }
    }

bcrepo_rm_epilogue:

    if (files != NULL) {
        del_bfs_catalog_relpath_ctx(files);
    }

    again = 0;

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

    if ((no_error = create_rescue_file(rootpath, rootpath_size, path, path_size, in, in_size)) == 0) {
        goto unl_handle_meta_proc_epilogue;
    }

    if (dproc == blackcat_encrypt_data || dproc == blackcat_otp_encrypt_data) {
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

    // INFO(Rafael): This step of the implemented data wiping is based on the suggestions given by Bruce Schneier
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

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// INFO(Rafael): Even having almost same body the functions unl_handle_encrypt and unl_handle_decrypt cannot be merged. !!
//               The addresses of those functions are used as identifiers in order to know what basic operation is      !!
//               being done: encrypt or decrypt.                                                                        !!
//                                                                                                                      !!
//               Moreover, creating one more level of indirection would be useless because after hitting the encrypt or !!
//               decrypt handle no additional stuff will be done. It encripts or decrypts, period. I have decided avoid !!
//               increasing the execution cost with one more function call that shows useless for practical reasons.    !!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

static int unl_handle_encrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              blackcat_data_processor dproc,
                              bfs_file_status_t *f_st,
                              bfs_checkpoint_func ckpt,
                              void *ckpt_args) {

    int no_error = unl_handle_meta_proc(rootpath, rootpath_size, path, path_size, protlayer, dproc);

    if (no_error) {
        *f_st = kBfsFileStatusLocked;
        if (ckpt != NULL) {
            no_error = ckpt(ckpt_args);
        }

        if (no_error) {
            no_error = bcrepo_remove_rescue_file(rootpath, rootpath_size);
        }
    }

    return no_error;
}

static int unl_handle_decrypt(const char *rootpath, const size_t rootpath_size,
                              const char *path, const size_t path_size,
                              const blackcat_protlayer_chain_ctx *protlayer,
                              blackcat_data_processor dproc,
                              bfs_file_status_t *f_st,
                              bfs_checkpoint_func ckpt,
                              void *ckpt_args) {

    int no_error = unl_handle_meta_proc(rootpath, rootpath_size, path, path_size, protlayer, dproc);

    if (no_error) {
        *f_st = kBfsFileStatusUnlocked;
        if (ckpt != NULL) {
            no_error = ckpt(ckpt_args);
        }

        if (no_error) {
            no_error = bcrepo_remove_rescue_file(rootpath, rootpath_size);
        }
    }

    return no_error;
}

static int unl_handle(bfs_catalog_ctx **catalog,
                      const char *rootpath, const size_t rootpath_size,
                      const char *pattern, const size_t pattern_size, unl_processor proc,
                      bfs_checkpoint_func ckpt,
                      void *ckpt_args) {
    int proc_nr = 0;
    bfs_catalog_ctx *cp;
    bfs_catalog_relpath_ctx *files = NULL, *fp, *fpp;
    int rl = 0;
    blackcat_data_processor dproc;

    if (catalog == NULL) {
        return 0;
    }

    cp = *catalog;

    if (pattern != NULL) {
        get_file_list(&files, NULL, rootpath, rootpath_size, pattern, pattern_size, &rl, BCREPO_RECUR_LEVEL_LIMIT);
    } else {
        files = cp->files;
    }

    if (proc == unl_handle_encrypt) {
        dproc = cp->encrypt_data;
    } else if (proc == unl_handle_decrypt) {
        dproc = cp->decrypt_data;
    } else {
        dproc = NULL;
    }

    if (dproc == NULL) {
        fprintf(stderr, "ERROR: Data processor cannot be NULL.\n");
        goto unl_handle_epilogue;
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
                                                                (char *)fpp->path,
                                                                fpp->path_size,
                                                                cp->protlayer,
                                                                dproc,
                                                                &fpp->status,
                                                                ckpt,
                                                                ckpt_args));
        }
    } else {
        for (fp = files; fp != NULL; fp = fp->next) {
            unl_fproc(fp, proc, cp->protlayer, proc_nr += proc(rootpath,
                                                               rootpath_size,
                                                               (char *)fp->path,
                                                               fp->path_size,
                                                               cp->protlayer,
                                                               dproc,
                                                               &fp->status,
                                                               ckpt,
                                                               ckpt_args));
        }
    }

#undef unl_fproc

unl_handle_epilogue:

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

#if defined(__unix__)
    p = path;
#elif defined(_WIN32)
    if ((p = strstr(path, ":\\")) != NULL ||
        (p = strstr(path, ":/")) != NULL)  {
        p += 1;
    } else {
        p = path;
    }
#else
# error Some code wanted.
#endif

    memcpy(p, root, root_size);

    p += root_size;

#if defined(__unix__)
    if (*(p - 1) != '/') {
        *(p) = '/';
        p += 1;
    }
#elif defined(_WIN32)
    if (*(p - 1) != '/' && *(p - 1) != '\\') {
        *(p) = '/';
        p += 1;
    }
#else
# error Some code wanted.
#endif

    s = sub;

#if defined(__unix__)
    if (*s == '/') {
        s++;
        s_d = 1;
    }
#elif defined(_WIN32)
    if (*s == '/' || *s == '\\') {
        s++;
        s_d = 1;
    }
#else
# error Some code wanted.
#endif

    // !-!--!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-+!
    // WARN(Rafael): This function take into consideration the possibility of having: 'a/b/c' and 'c/y.z' as parameters. |
    //               In this case, the resulting path will be 'a/b/c/y.z'. This function should not be used as a general !
    //               purpose 'path maker' function. Just use it inside this module.                                      |
    // !-!--!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-!-+!

    t = s + sub_size - s_d;

#if defined(__unix__)
    while (t != s && *t != '/') {
        t--;
    }
#elif defined(_WIN32)
    while (t != s && *t != '/' && *t != '\\') {
        t--;
    }
#else
# error Some code wanted.
#endif

    if (t > s) {
        memset(subdir, 0, sizeof(subdir));
        subdir_size = t - s;
        memcpy(subdir, s, subdir_size);
#if defined(__unix__)
        if (subdir[subdir_size - 1] != '/') {
            subdir[subdir_size++] = '/';
        }
#elif defined(_WIN32)
        if (subdir[subdir_size - 1] != '/' && subdir[subdir_size - 1] != '\\') {
            subdir[subdir_size++] = '/';
        }
#else
# error Some code wanted.
#endif
        t = strstr(path, subdir);
        if (t != NULL && *(t + subdir_size) == 0) {
            s += subdir_size;
            s_d += subdir_size;
        }
    }

    memcpy(p, s, sub_size - s_d);

    return strlen(path);
}

#if defined(__unix__)
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
    }

    files_p = *files;

    if (bstat(filepath, &st) == 0) {
        // INFO(Rafael): We are only interested in regular files and directories.
        if (st.st_mode & S_IFREG) {
            // INFO(Rafael): However, only regular files are really relevant for us.
            if (get_entry_from_relpath_ctx(dest_files, (kryptos_u8_t *)(filepath + rootpath_size)) == NULL) {
                files_p = add_file_to_relpath_ctx(files_p,
                                                  (kryptos_u8_t *)(filepath + rootpath_size),
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
#elif defined(_WIN32)
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

        while (fp != fp_end && *fp_end != '/' && *fp_end != '\\') {
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
    }

    files_p = *files;

    if (bstat(filepath, &st) == 0) {
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
#else
# error get_file_list() must be implemented.
#endif

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
    size_t salt_size = 0;
    kryptos_u8_t *salt = NULL;
    blackcat_hash_size_func hash_size;

    kryptos_task_init_as_null(ktask);

    if (catalog == NULL || key == NULL || key_size == 0 || catalog->key_hash_algo == NULL) {
        goto bcrepo_validate_key_epilogue;
    }

    if (!is_pht(catalog->key_hash_algo)) {
        if ((hash_size = get_hash_size(get_hash_processor_name(catalog->key_hash_algo))) == NULL) {
            goto bcrepo_validate_key_epilogue;
        }

        salt_size = hash_size();

        bcrepo_hex_to_seed(&salt, &salt_size, (char *)catalog->key_hash, catalog->key_hash_size >> 1);

        ktask->in_size = salt_size + key_size;

        if ((ktask->in = kryptos_newseg(ktask->in_size + 1)) == NULL) {
            goto bcrepo_validate_key_epilogue;
        }

        memset(ktask->in, 0, ktask->in_size + 1);
        memcpy(ktask->in, salt, salt_size);
        memcpy(ktask->in + salt_size, key, key_size);

        catalog->key_hash_algo(&ktask, 1);

        if (!kryptos_last_task_succeed(ktask)) {
            goto bcrepo_validate_key_epilogue;
        }

        is_valid = (ktask->out_size == (catalog->key_hash_size >> 1) &&
                    memcmp(ktask->out, catalog->key_hash + ktask->out_size, ktask->out_size) == 0);
    } else if (catalog->key_hash_algo == blackcat_bcrypt) {
        ktask->in = catalog->key_hash;
        ktask->in_size = catalog->key_hash_size;
        ktask->arg[0] = (void *) key;
        ktask->arg[1] = (void *) &key_size;
        blackcat_bcrypt(&ktask, 1);
        is_valid = (ktask->result == kKryptosSuccess);
        ktask->arg[0] = ktask->arg[1] = NULL;
        ktask->in = NULL;
    }

bcrepo_validate_key_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    if (salt != NULL) {
        kryptos_freeseg(salt, salt_size);
        salt_size = 0;
    }

    return is_valid;
}

kryptos_u8_t *bcrepo_hash_key(const kryptos_u8_t *key,
                              const size_t key_size, blackcat_hash_processor h, void *h_args, size_t *hsize) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *salt = NULL, *hash = NULL;
    size_t salt_size;
    blackcat_hash_size_func hash_size;
    int cost;
    kryptos_u8_t xsalt[8192];

    kryptos_task_init_as_null(ktask);

    if (hsize == NULL) {
        goto bcrepo_hash_key_epilogue;
    }

    if (!is_pht(h)) {
        if ((hash_size = get_hash_size(get_hash_processor_name(h))) == NULL) {
            goto bcrepo_hash_key_epilogue;
        }

        salt_size = hash_size();
        hash_size = NULL;

        if ((salt = kryptos_get_random_block(salt_size)) == NULL) {
            goto bcrepo_hash_key_epilogue;
        }

        ktask->in_size = key_size + salt_size;
        if ((ktask->in = kryptos_newseg(ktask->in_size)) == NULL) {
            goto bcrepo_hash_key_epilogue;
        }

        memcpy(ktask->in, salt, salt_size);
        memcpy(ktask->in + salt_size, key, key_size);

        // WARN(Rafael): It does not hash with binary output, it must be hexadecimal.
        h(&ktask, 1);

        bcrepo_seed_to_hex((char *)xsalt, sizeof(xsalt) - 1, salt, salt_size);

        *hsize = (salt_size << 1) + ktask->out_size;

        if ((hash = kryptos_newseg(*hsize + 1)) == NULL) {
            goto bcrepo_hash_key_epilogue;
        }

        memset(hash, 0, *hsize + 1);
        memcpy(hash, xsalt, salt_size << 1);
        memcpy(hash + (salt_size << 1), ktask->out, ktask->out_size);
    } else if (h == blackcat_bcrypt) {
        if (h_args == NULL) {
            goto bcrepo_hash_key_epilogue;
        }

        ktask->in = (kryptos_u8_t *)key;
        ktask->in_size = key_size;
        ktask->arg[0] = h_args;

        h(&ktask, 0);

        hash = ktask->out;
        *hsize = ktask->out_size;
        ktask->out = NULL;
    }

    if (!kryptos_last_task_succeed(ktask)) {
        goto bcrepo_hash_key_epilogue;
    }

bcrepo_hash_key_epilogue:

    if (ktask->in != NULL && ktask->in != key) {
        kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
    }

    if (salt != NULL) {
        kryptos_freeseg(salt, salt_size);
        salt_size = 0;
    }

    return hash;
}

int bcrepo_remove_rescue_file(const char *rootpath, const size_t rootpath_size) {
    char rescue_filepath[4096];
    int no_error = 0;
    FILE *fp;
    size_t rescue_file_size, temp_size;
    char temp[4096];

    // INFO(Rafael): Erasing the current rescue file.

    bcrepo_rescue_file(rescue_filepath, sizeof(rescue_filepath), rootpath);

    if ((fp = fopen(rescue_filepath, "rb")) != NULL) {
        fseek(fp, 0L, SEEK_END);
        rescue_file_size = ftell(fp);
        fclose(fp);
        snprintf(temp, sizeof(temp) - 1, "%s/%s", rootpath, BCREPO_HIDDEN_DIR);
        temp_size = strlen(temp);
        bfs_data_wiping(temp, temp_size, BCREPO_RESCUE_FILE, BCREPO_RESCUE_FILE_SIZE, rescue_file_size);
        rescue_file_size = 0;
#if defined(__unix__)
        no_error = (remove(rescue_filepath) == 0);
#elif defined(_WIN32)
        no_error = (DeleteFile(rescue_filepath) != 0);
#else
# error Some code wanted.
#endif
    }

    return no_error;
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

    dump_catalog_data(o + pfx_size, o_size, catalog);

    // INFO(Rafael): Mitigating chosen-plaintext attack by making its applying hard.

    memcpy(o, pfx, pfx_size);
    memcpy(o + pfx_size + o_size, sfx, sfx_size);

    o_size += pfx_size + sfx_size;

    if (encrypt_catalog_data(&o, &o_size, key, key_size, catalog) == kKryptosSuccess) {
        fprintf(stderr, "ERROR: While encrypting catalog data.\n");
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
                             (kryptos_u8_t *)key_hash_algo,
                             strlen(key_hash_algo)) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: While writing catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    // INFO(Rafael): From v1.2.0 first-layer key is salted by default. Anyway if old data has arrived here,
    //               it must not break things.

    if (catalog->salt != NULL && catalog->salt_size > 0 && kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                                                                                BCREPO_PEM_SALT_DATA_HDR,
                                                                                catalog->salt,
                                                                                catalog->salt_size) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: While writing catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_HMAC_HDR,
                             (kryptos_u8_t *)catalog->hmac_scheme->name,
                             strlen(catalog->hmac_scheme->name)) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: While writing catalog PEM data.\n");
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
                                 (kryptos_u8_t *)encoder, strlen(encoder)) != kKryptosSuccess) {
            fprintf(stderr, "ERROR: While writing catalog PEM data.\n");
            no_error = 0;
            encoder = NULL;
            goto bcrepo_write_epilogue;
        }

        encoder = NULL;
    }

    if (kryptos_pem_put_data(&pem_buf, &pem_buf_size,
                             BCREPO_PEM_CATALOG_DATA_HDR,
                             o, o_size) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: While writing catalog PEM data.\n");
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    // INFO(Rafael): Making the binary mode explicit because we must avoid '\r\n' from Windows, otherwise it will mess up
    //               with catalog reading in other platforms. The 'b' is useless in Unix but meaningful in Windows.
    //               Let it be...
    fp = fopen(filepath, "wb");

    if (fp == NULL) {
        fprintf(stderr, "ERROR: Unable to write to file '%s'.\n", filepath);
        no_error = 0;
        goto bcrepo_write_epilogue;
    }

    if (fwrite(pem_buf, 1, pem_buf_size, fp) == -1) {
        fprintf(stderr, "ERROR: While writing PEM data to disk.\n");
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

    fp = fopen(filepath, "rb");

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
    //               open it at the next catalog stat operation. So let's 'trigger' the correct
    //               hash algorithm (key crunching) and the HMAC processor.

    key_hash_algo = kryptos_pem_get_data(BCREPO_PEM_KEY_HASH_ALGO_HDR, o, *out_size, &key_hash_algo_size);

    if (key_hash_algo == NULL) {
        fprintf(stderr, "ERROR: Unable to get the catalog's hash algorithm.\n");
        kryptos_freeseg(o, *out_size);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    catalog_key_hash_algo = get_hash_processor((char *)key_hash_algo);

    if (catalog_key_hash_algo == NULL) {
        // INFO(Rafael): Some idiot trying to screw up the program's flow.
        fprintf(stderr, "ERROR: Unknown catalog's hash algorithm.\n");
        kryptos_freeseg(o, *out_size);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    catalog->catalog_key_hash_algo = catalog_key_hash_algo;
    catalog->catalog_key_hash_algo_size = get_hash_size((char *)key_hash_algo);

    hmac_algo = kryptos_pem_get_data(BCREPO_PEM_HMAC_HDR, o, *out_size, &hmac_algo_size);

    if (hmac_algo == NULL) {
        fprintf(stderr, "ERROR: Unable to get the catalog's HMAC scheme.\n");
        kryptos_freeseg(o, *out_size);
        o = NULL;
        *out_size = 0;
        goto bcrepo_read_epilogue;
    }

    catalog->salt = kryptos_pem_get_data(BCREPO_PEM_SALT_DATA_HDR, o, *out_size, &catalog->salt_size);

    hmac_scheme = get_hmac_catalog_scheme((char *)hmac_algo);

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
        if ((catalog->encoder = get_encoder((char *)encoder)) == NULL) {
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
#if defined(_WIN32)
    char *rp;
#endif
    size_t cwd_size;

    if (getcwd(cwd, sizeof(cwd) - 1) == NULL) {
        return path;
    }

    p = path;
    p_end = path + strlen(path);

#if defined(__unix__)
    while (p < p_end && (p = strstr(p, "../")) != NULL) {
        go_up_nr++;
        p += 3;
    }
#elif defined(_WIN32)
    while (p < p_end && ((rp = strstr(p, "../")) != NULL || (rp = strstr(p, "..\\")) != NULL)) {
        p = rp;
        go_up_nr++;
        p += 3;
    }
#else
# error Some code wanted.
#endif

    if (go_up_nr == 0) {
        goto remove_go_ups_from_path_epilogue;
    }

    p = &cwd[strlen(cwd) - 1];

    while (p != &cwd[0] && go_up_nr > 0) {
#if defined(__unix__)
        while (p != &cwd[0] && *p != '/') {
            p--;
        }
#elif defined(_WIN32)
        while (p != &cwd[0] && *p != '/' && *p != '\\') {
            p--;
        }
#else
# error Some code wanted.
#endif
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
#if defined(__unix__)
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
#elif defined(_WIN32)
        if ((p + 1) < p_end && p[0] == '.' && (p[1] == '/' || p[1] == '\\')) {
            p += 2;
            if (p == p_end) {
                continue;
            }
        } else if ((p + 2) < p_end && p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\\')) {
            p += 3;
            if (p == p_end) {
                continue;
            }
        }
#else
# error Some code wanted.
#endif
        cwd[cwd_size++] = *p;
        p++;
    }

    memset(path, 0, path_size);
    memcpy(path, cwd, cwd_size);

    return path;
}

static int root_dir_reached(const char *cwd) {
#if defined(__unix__)
    return (cwd != NULL && (strcmp(cwd, "/") == 0));
#elif defined(_WIN32)
    char *p;

    if (cwd == NULL) {
        return 0;
    }

    if (strcmp(cwd, "/") == 0) {
        return 1;
    }

    if ((p = strstr(cwd, ":\\")) == NULL) {
        if ((p = strstr(cwd, ":/")) == NULL) {
            return (strcmp(cwd, "\\") == 0);
        }
    }

    return (p != NULL && p[2] == 0);
#else
# error Some code wanted.
#endif
}

static kryptos_u8_t *bckdf(const kryptos_u8_t *key, const size_t key_size,
                           blackcat_hash_processor hash, blackcat_hash_size_func hash_size,
                           const ssize_t size, const kryptos_u8_t *salt, const size_t salt_size) {
    size_t k, hs, key_hash_size;
    kryptos_u8_t *kp = NULL, *kp_end, *key_hash = NULL;
    kryptos_task_ctx t, *ktask = &t;

    if (hash == NULL || hash_size == NULL || size <= 0 ||
            (hs = hash_size()) == 0 || (kp = kryptos_newseg(size)) == NULL) {
        goto bckdf_epilogue;
    }

    kp_end = kp + size;

    k = 0;

    kryptos_task_init_as_null(ktask);


    if (salt == NULL || salt_size == 0) {
        ktask->in = (kryptos_u8_t *)key;
        ktask->in_size = key_size;
    } else {
        ktask->in_size = key_size + salt_size;
        if ((ktask->in = (kryptos_u8_t *)kryptos_newseg(ktask->in_size)) == NULL) {
            fprintf(stderr, "ERROR: Unable to allocate memory for key and salt data.\n");
            goto bckdf_epilogue;
        }
        memcpy(ktask->in, key, key_size);
        memcpy(ktask->in + key_size, salt, salt_size);
    }

    hash(&ktask, 0);

    if (!kryptos_last_task_succeed(ktask)) {
        kryptos_freeseg(kp, size);
        kp = NULL;
        goto bckdf_epilogue;
    }

    if (ktask->in != key) {
        kryptos_task_free(ktask, KRYPTOS_TASK_IN);
    }

    ktask->in_size = ktask->out_size + key_size;
    ktask->in = (kryptos_u8_t *) kryptos_newseg(ktask->in_size);

    if (ktask->in == NULL) {
        kryptos_freeseg(ktask->out, ktask->out_size);
        kryptos_freeseg(kp, size);
        kp = NULL;
        goto bckdf_epilogue;
    }

    memcpy(ktask->in, ktask->out, ktask->out_size >> 1);
    memcpy(ktask->in + (ktask->out_size >> 1), key, key_size);
    memcpy(ktask->in + (ktask->out_size >> 1) + key_size, ktask->out + (ktask->out_size >> 1), ktask->out_size >> 1);

    kryptos_freeseg(ktask->out, ktask->out_size);

    hash(&ktask, 0);

    kryptos_freeseg(ktask->in, ktask->in_size);
    ktask->in = NULL;

    if (!kryptos_last_task_succeed(ktask)) {
        kryptos_freeseg(kp, size);
        kp = NULL;
        goto bckdf_epilogue;
    }

    key_hash = ktask->out;
    key_hash_size = ktask->out_size;

    ktask->in = ktask->out;
    ktask->in_size = ktask->out_size;

    while (kp < kp_end) {
        hash(&ktask, 0);

        if (!kryptos_last_task_succeed(ktask)) {
            kryptos_freeseg(kp, size);
            kp = NULL;
            goto bckdf_epilogue;
        }

        *kp = ktask->out[key_hash[k] % hs];

        if (ktask->in != key_hash) {
            kryptos_task_free(ktask, KRYPTOS_TASK_IN);
        }

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;

        k = (k + 1) % key_hash_size;
        kp += 1;
    }

    kp -= size;

bckdf_epilogue:

    kp_end = NULL;
    k = hs = 0;

    if (ktask->in != key_hash) {
        kryptos_task_free(ktask, KRYPTOS_TASK_IN);
    }

    if (key_hash != NULL) {
        kryptos_freeseg(key_hash, key_hash_size);
        key_hash_size = 0;
    }

    kryptos_task_init_as_null(ktask);

    return kp;
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

    p_layer.key_size = get_hmac_key_size(catalog->hmac_scheme->processor);
    p_layer.key = bckdf(key, key_size,
                        catalog->catalog_key_hash_algo, catalog->catalog_key_hash_algo_size,
                        p_layer.key_size, catalog->salt, catalog->salt_size);
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

        if (catalog->salt == NULL) {
            // INFO(Rafael): If it came from an older writer, we will refresh it and start applying salt from now on.
            catalog->salt = get_random_catalog_salt(&catalog->salt_size);
        }
    }

    result = ktask->result;

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

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

    if (catalog->salt != NULL) {
        kryptos_freeseg(catalog->salt, catalog->salt_size);
        // INFO(Rafael): It is a little freak paranoid since salt once would efficiently difficult a dictionary attack.
        //               Anyway, using a new salt will not hurt.
        if ((catalog->salt = get_random_catalog_salt(&catalog->salt_size)) == NULL) {
            // INFO(Rafael): From v1.2.0 first-layer key salting is mandatory.
            fprintf(stderr, "ERROR: Unable to get a random first-layer key salt.\n");
            result = kKryptosProcessError;
            goto encrypt_catalog_data_epilogue;
        }
    }

    p_layer.key_size = get_hmac_key_size(catalog->hmac_scheme->processor);
    p_layer.key = bckdf(key, key_size,
                        catalog->catalog_key_hash_algo, catalog->catalog_key_hash_algo_size,
                        p_layer.key_size, catalog->salt, catalog->salt_size);
    p_layer.mode = catalog->hmac_scheme->mode;

    kryptos_task_set_in(ktask, *data, *data_size);

    kryptos_task_set_encrypt_action(ktask);

    catalog->hmac_scheme->processor(&ktask, &p_layer);

    if (kryptos_last_task_succeed(ktask)) {
        *data = ktask->out;
        *data_size = ktask->out_size;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

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
    kryptos_task_ctx t, *ktask = &t;

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

    kryptos_task_init_as_null(ktask);

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, catalog->protection_layer, catalog->protection_layer_size);

    if (!kryptos_last_task_succeed(ktask)) {
        // WARN(Rafael): In normal conditions it should never happen.
        return 0;
    }

    size += strlen(catalog->bc_version) + ktask->out_size + catalog->key_hash_size + strlen(hash_name) +
            catalog->config_hash_size +
            catalog->kdf_params_size +
            strlen(BCREPO_CATALOG_BC_VERSION) + 1 +
            strlen(BCREPO_CATALOG_KEY_HASH_ALGO) + 1 +
            strlen(BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO) + 1 +
            strlen(BCREPO_CATALOG_KEY_HASH) + 1 +
            strlen(BCREPO_CATALOG_PROTECTION_LAYER) + 1 +
            strlen(BCREPO_CATALOG_FILES) + 1 +
            strlen(BCREPO_CATALOG_OTP) + 1 +
            strlen(BCREPO_CATALOG_CONFIG_HASH) + 1 +
            strlen(BCREPO_CATALOG_KDF_PARAMS) + 2;

    hash_name = NULL;

    for (f = catalog->files; f != NULL; f = f->next) {
        size += f->path_size + strlen(f->timestamp) + 6 + (f->seed_size << 1);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

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
        { BCREPO_CATALOG_FILES,                   files_w,                   0 },
        { BCREPO_CATALOG_OTP,                     otp_w,                     0 },
        { BCREPO_CATALOG_CONFIG_HASH,             config_hash_w,             0 },
        { BCREPO_CATALOG_KDF_PARAMS,              kdf_params_w,              0 }
    };
    static size_t dumpers_nr = sizeof(dumpers) / sizeof(dumpers[0]), d;
    kryptos_u8_t *o;
    // WARN(Rafael): All dumpers must be included during this check. If you have added a new one in dumpers[] add its
    //               writing verification here.
#define all_dump_done(d) ( (d)[0].done && (d)[1].done && (d)[2].done &&\
                           (d)[3].done && (d)[4].done && (d)[5].done &&\
                           (d)[6].done && (d)[7].done && (d)[8].done )

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
    kryptos_task_ctx t, *ktask = &t;
    size = strlen(BCREPO_CATALOG_PROTECTION_LAYER);
    memcpy(out, BCREPO_CATALOG_PROTECTION_LAYER, size);
    out += size;
    kryptos_task_init_as_null(ktask);
    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, (kryptos_u8_t *)catalog->protection_layer, catalog->protection_layer_size);
    if (!kryptos_last_task_succeed(ktask)) {
        // INFO(Rafael): It should never happen in normal conditions.
        fprintf(stderr, "ERROR: Unable to encode protection layer. Aborting.\n");
        exit(EFAULT);
    }
    memcpy(out, ktask->out, ktask->out_size);
    out += ktask->out_size;
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    *out = '\n';
    return (out + 1);
}

static kryptos_u8_t *otp_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    size = strlen(BCREPO_CATALOG_OTP);
    memcpy(out, BCREPO_CATALOG_OTP, size);
    out += size;
    *out = (catalog->otp) ? '1' : '0';
    out += 1;
    *out = '\n';
    return (out + 1);
}

static kryptos_u8_t *config_hash_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    kryptos_u8_t *o = out;
    if (catalog->config_hash != NULL) {
        size = strlen(BCREPO_CATALOG_CONFIG_HASH);
        memcpy(o, BCREPO_CATALOG_CONFIG_HASH, size);
        o += size;
        memcpy(o, catalog->config_hash, catalog->config_hash_size);
        o += catalog->config_hash_size;
        *o = '\n';
        o += 1;
    }
    return o;
}

static kryptos_u8_t *kdf_params_w(kryptos_u8_t *out, const size_t out_size, const bfs_catalog_ctx *catalog) {
    size_t size;
    kryptos_u8_t *o = out;
    if (catalog->kdf_params != NULL) {
        size = strlen(BCREPO_CATALOG_KDF_PARAMS);
        memcpy(o, BCREPO_CATALOG_KDF_PARAMS, size);
        o += size;
        memcpy(o, catalog->kdf_params, catalog->kdf_params_size);
        o += catalog->kdf_params_size;
        *o = '\n';
        o += 1;
    }
    return o;
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
        files_r,
        otp_r,
        config_hash_r,
        kdf_params_r
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

    fp = (kryptos_u8_t *)strstr((const char *)in, field);
    end = in + in_size;

    if (fp == NULL) {
        goto get_catalog_field_epilogue;
    }

    if (*(fp - 1) == '-') {
        while (fp != NULL && *(fp - 1) == '-' && fp < end) {
            fp += 1;
            fp = (kryptos_u8_t *)strstr((char *)fp, field);
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

    if (data == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto get_catalog_field_epilogue;
    }

    memset(data, 0, fp_end - fp + 1);
    memcpy(data, fp, fp_end - fp);

get_catalog_field_epilogue:

    return data;
}

static int is_metadata_compatible(const char *version) {
    // INFO(Rafael): If you are changing something here and it will not break compatibility with the current
    //               cmd tool's version, include its version here, otherwise erase this version entry.
    static const char *compatible_versions[] = {
        BCREPO_METADATA_VERSION,
        "1.2.0", // INFO(Rafael): Metadata version 1.3.0 has introduced encoded protection layers as a security
                 // mesurement. Since from 1.3.0 became possible to pass extended ascii as escaped chars in cipher's
                 // parameters. With a raw protection layer dumped directly to the catalog, a malicious user could
                 // be able to cause buffer overflows. Once a protection layer saved by using a prior bcrepo metadata
                 // version read by routine from a newer bcrepo, it will be encoded accordingly and the repository's
                 // bc-version will be refreshed by the current newer version.
        "1.1.0", // INFO(Rafael): Metadata version 1.2.0 has introduced the kdf-params during key crunching
                 // besides new algorithms and modes. Anyway is still possible to read 1.1.0 metadata and
                 // handle it accordingly. If a setkey is done over 1.1.0 stuff it will overwrite the repo's
                 // metadata version making it incompatible for prior blackcat versions. So everything will
                 // be fine and sane as we like.
        "1.0.0"
    };
    static const size_t compatible_versions_nr = sizeof(compatible_versions) / sizeof(compatible_versions[0]);
    size_t c;
    int is = 0;
    for (c = 0; c < compatible_versions_nr && !is; c++) {
         is = (strcmp(compatible_versions[c], version) == 0);
    }

    if (!is) {
        fprintf(stderr, "ERROR: Your repository was created with an incompatible version (%s).\n"
                        "       Try to use that old version or rebase your repo with this version (%s).\n",
                        version, BCREPO_METADATA_VERSION);
    }

    return is;
}

static int bc_version_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;
    cp->bc_version = (char *)get_catalog_field(BCREPO_CATALOG_BC_VERSION, in, in_size);
    // INFO(Rafael): In case of incompatibility we will abort the reading here.
    return is_metadata_compatible(cp->bc_version);
}

static int otp_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;
    char *otp_data = (char *)get_catalog_field(BCREPO_CATALOG_OTP, in, in_size);
    cp->otp = (otp_data != NULL && *otp_data == '1');
    if (otp_data != NULL) {
        kryptos_freeseg(otp_data, 1);
    }
    if (cp->otp) {
        cp->encrypt_data = blackcat_otp_encrypt_data;
        cp->decrypt_data = blackcat_otp_decrypt_data;
    } else {
        cp->encrypt_data = blackcat_encrypt_data;
        cp->decrypt_data = blackcat_decrypt_data;
    }
    return 1;
}

static int key_hash_algo_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    char *hash_algo = NULL;
    int done = 0;
    bfs_catalog_ctx *cp = *catalog;

    hash_algo = (char *)get_catalog_field(BCREPO_CATALOG_KEY_HASH_ALGO, in, in_size);

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

    hash_algo = (char *)get_catalog_field(BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO, in, in_size);

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
    cp->key_hash_size = strlen((char *)cp->key_hash);

    return (cp->key_hash != NULL && cp->key_hash_size > 0);
}

static int protection_layer_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *data;
    if (strcmp(cp->bc_version, "1.0.0") == 0 ||
        strcmp(cp->bc_version, "1.1.0") == 0 ||
        strcmp(cp->bc_version, "1.2.0") == 0) {
        // INFO(Rafael): Backward compatibility. Once read it will be re-written in radix-64 and
        //               bc_version will be increased for the newer version.
        cp->protection_layer = get_catalog_field(BCREPO_CATALOG_PROTECTION_LAYER, in, in_size);
        cp->protection_layer_size = strlen(cp->protection_layer);
    } else {
        kryptos_task_init_as_null(ktask);
        data = get_catalog_field(BCREPO_CATALOG_PROTECTION_LAYER, in, in_size);
        kryptos_task_set_decode_action(ktask);
        kryptos_run_encoder(base64, ktask, data, strlen(data));
        cp->protection_layer = ktask->out;
        cp->protection_layer_size = ktask->out_size;
        kryptos_task_free(ktask, KRYPTOS_TASK_IN);
    }
    return (cp->protection_layer != NULL);
}

static int config_hash_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;

    cp->config_hash = get_catalog_field(BCREPO_CATALOG_CONFIG_HASH, in, in_size);
    cp->config_hash_size =  (cp->config_hash != NULL) ? strlen((char *)cp->config_hash) : 0;

    return 1; // INFO(Rafael): This catalog field is optional so always its reading will return true.
}

static int kdf_params_r(bfs_catalog_ctx **catalog, const kryptos_u8_t *in, const size_t in_size) {
    bfs_catalog_ctx *cp = *catalog;

    cp->kdf_params = (char *)get_catalog_field(BCREPO_CATALOG_KDF_PARAMS, in, in_size);
    cp->kdf_params_size = (cp->kdf_params != NULL) ? strlen((char *)cp->kdf_params) : 0;

    return 1; // INFO(Rafael): This catalog field is also optional.
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

    if ((kryptos_u8_t *)(ip = (kryptos_u8_t *)strstr((const char *)ip, BCREPO_CATALOG_FILES)) == NULL) {
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

            bcrepo_hex_to_seed(&cat_p->files->tail->seed, &cat_p->files->tail->seed_size, (char *)cp, cp_end - cp);

            kryptos_freeseg(path, path_size + 1);
            kryptos_freeseg(timestamp, timestamp_size + 1);
            path = NULL;
            timestamp = NULL;

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

static kryptos_u8_t *get_random_catalog_salt(size_t *out_size) {
    // INFO(Rafael): Salts for first-layer key; 32, 64, 96, 128, 160, 192, 224 and 256 bits respectivelly.
    static size_t salt_size[] = { 4, 8, 12, 16, 20, 24, 28, 32 };
    static size_t salt_size_nr = sizeof(salt_size) / sizeof(salt_size[0]);
    kryptos_u8_t *out = NULL;

    if (out_size == NULL) {
        goto get_random_catalog_salt_epilogue;
    }

    *out_size = salt_size[kryptos_get_random_byte() % salt_size_nr];
    if ((out = (kryptos_u8_t *)kryptos_get_random_block(*out_size)) == NULL) {
        *out_size = 0;
    }

get_random_catalog_salt_epilogue:

    return out;
}

#undef BCREPO_CATALOG_BC_VERSION
#undef BCREPO_CATALOG_KEY_HASH_ALGO
#undef BCREPO_CATALOG_PROTLAYER_KEY_HASH_ALGO
#undef BCREPO_CATALOG_KEY_HASH
#undef BCREPO_CATALOG_PROTECTION_LAYER
#undef BCREPO_CATALOG_FILES
#undef BCREPO_CATALOG_OTP
#undef BCREPO_CATALOG_KDF_PARAMS

#undef BCREPO_PEM_KEY_HASH_ALGO_HDR
#undef BCREPO_PEM_HMAC_HDR
#undef BCREPO_PEM_CATALOG_DATA_HDR
#undef BCREPO_PEM_ENCODER_HDR
#undef BCREPO_PEM_SALT_DATA_HDR

#undef BCREPO_CATALOG_FILE
#undef BCREPO_CATALOG_FILE_SIZE
#undef BCREPO_RESCUE_FILE
#undef BCREPO_RESCUE_FILE_SIZE

#undef BCREPO_RECUR_LEVEL_LIMIT

#undef BLACKCAT_DEVPATH

#if defined(__unix__)
# undef BLACKCAT_EPOCH
#elif defined(_WIN32)
# undef BLACKCAT_EPOCH_L
# undef BLACKCAT_EPOCH_H
#endif
