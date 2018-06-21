/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/rm.h>
#include <cmd/options.h>
#include <fs/ctx/fsctx.h>
#include <fs/bcrepo/bcrepo.h>
#include <kryptos_memory.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_rm(void) {
    char *rootpath = NULL;
    int exit_code = EINVAL;
    char *rm_param = NULL;
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key[2] = { NULL, NULL };
    size_t key_size[2], rootpath_size;
    int rm_nr;
    kryptos_u8_t *catalog_data = NULL;
    size_t catalog_data_size;
    char temp[4096];

    rootpath = bcrepo_get_rootpath();

    if (rootpath == NULL) {
        fprintf(stderr, "ERROR: You are out of a blackcat repo.\n");
        goto blackcat_cmd_rm_epilogue;
    }

    rootpath_size = strlen(rootpath);

    rm_param = blackcat_get_argv(0);

    if (rm_param == NULL) {
        fprintf(stderr, "ERROR: A relative file path or a glob pattern is missing.\n");
        exit_code = ENOTSUP;
        goto blackcat_cmd_rm_epilogue;
    }

    catalog = new_bfs_catalog_ctx();

    if (catalog == NULL) {
        fprintf(stderr, "ERROR: Unable to allocate memory for the repo's catalog.\n");
        exit_code = ENOMEM;
        goto blackcat_cmd_rm_epilogue;
    }

    catalog_data = bcrepo_read(bcrepo_catalog_file(temp, sizeof(temp), rootpath), catalog, &catalog_data_size);

    if (catalog_data == NULL) {
        fprintf(stderr, "ERROR: Unable to read the repo's catalog file.\n");
        exit_code = EFAULT;
        goto blackcat_cmd_rm_epilogue;
    }

    fprintf(stdout, "Password: ");
    key[0] = blackcat_getuserkey(&key_size[0]);

    if (key[0] == NULL) {
        fprintf(stderr, "ERROR: Null key.\n");
        goto blackcat_cmd_rm_epilogue;
    }

    if (bcrepo_stat(&catalog, key[0], key_size[0], &catalog_data, &catalog_data_size) == 0) {
        fprintf(stderr, "ERROR: While trying to access the catalog data.\n");
        exit_code = EACCES;
        goto blackcat_cmd_rm_epilogue;
    }

    if (bcrepo_validate_key(catalog, key[0], key_size[0]) == 0) {
        fprintf(stdout, "Second password: ");
        key[1] = blackcat_getuserkey(&key_size[1]);
    } else {
        key[1] = key[0];
        key_size[1] = key_size[0];
    }

    rm_nr = bcrepo_rm(&catalog, rootpath, rootpath_size, rm_param, strlen(rm_param));

    if (rm_nr > 0) {
        fprintf(stdout, "%d file(s) removed from repo's catalog.\n", rm_nr);
        exit_code = 0;
    } else {
        fprintf(stderr, "File(s) not found.\n");
        exit_code = ENOENT;
    }

blackcat_cmd_rm_epilogue:

    if (key[1] != key[0]) {
        kryptos_freeseg(key[0], key_size[0]);
        key_size[0] = 0;
        kryptos_freeseg(key[1], key_size[1]);
        key_size[1] = 0;
    } else {
        kryptos_freeseg(key[0], key_size[0]);
        key_size[0] = key_size[1] = 0;
    }

    if (catalog != NULL) {
        del_bfs_catalog_ctx(catalog);
    }

    if (catalog_data != NULL) {
        kryptos_freeseg(catalog_data, catalog_data_size);
        catalog_data_size = 0;
    }

    if (rootpath != NULL) {
        kryptos_freeseg(rootpath, rootpath_size);
        rootpath_size = 0;
    }

    return exit_code;
}

int blackcat_cmd_rm_help(void) {
    fprintf(stderr, "use: blackcat rm <relative file name | glob pattern>\n");
    return 0;
}
