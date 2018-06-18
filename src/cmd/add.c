/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/add.h>
#include <cmd/options.h>
#include <fs/ctx/fsctx.h>
#include <fs/bcrepo/bcrepo.h>
#include <kryptos_memory.h>
#include <errno.h>
#include <stdio.h>

int blackcat_cmd_add(void) {
    char *rootpath = NULL;
    kryptos_u8_t *key = NULL;
    size_t key_size;
    int exit_code = EINVAL;
    char *add_param;
    int add_nr;
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *catalog_data = NULL;
    size_t catalog_data_size;
    char temp[4096];

    rootpath = bcrepo_get_rootpath();

    if (rootpath == NULL) {
        fprintf(stderr, "ERROR: You are out of a blackcat repo.\n");
        goto blackcat_cmd_add_epilogue;
    }

    add_param = blackcat_get_argv(0);

    if (add_param == NULL) {
        fprintf(stderr, "ERROR: A relative file path or a glob pattern is missing.\n");
        exit_code = ENOTSUP;
        goto blackcat_cmd_add_epilogue;
    }

    catalog = new_bfs_catalog_ctx();

    if (catalog == NULL) {
        fprintf(stderr, "ERROR: Unable to allocate memory for the repo's catalog.\n");
        exit_code = ENOMEM;
        goto blackcat_cmd_add_epilogue;
    }

    catalog_data = bcrepo_read(bcrepo_catalog_file(temp, sizeof(temp), rootpath), catalog, &catalog_data_size);

    if (catalog_data == NULL) {
        fprintf(stderr, "ERROR: Unable to read the repo's catalog file.\n");
        exit_code = EFAULT;
        goto blackcat_cmd_add_epilogue;
    }

    key = blackcat_getuserkey(&key_size);

    if (key == NULL) {
        fprintf(stderr, "ERROR: Null key.\n");
        goto blackcat_cmd_add_epilogue;
    }

    if (bcrepo_stat(&catalog, key, key_size, &catalog_data, &catalog_data_size) == 0) {
        fprintf(stderr, "ERROR: While trying to access the catalog data.\n");
        exit_code = EACCES;
        goto blackcat_cmd_add_epilogue;
    }

    add_nr = bcrepo_add(&catalog,
                        rootpath, strlen(rootpath),
                        add_param, strlen(add_param),
                        blackcat_get_bool_option("plain", 0));

    if (add_nr > 0) {
        fprintf(stderr, "%d file(s) added.\n", add_nr);
        exit_code = 0;
    } else {
        fprintf(stderr, "Files not found.\n");
        exit_code = ENOENT;
    }

blackcat_cmd_add_epilogue:

    if (key != NULL) {
        kryptos_freeseg(key);
        key_size = 0;
    }

    if (catalog != NULL) {
        del_bfs_catalog_ctx(catalog);
    }

    if (catalog_data != NULL) {
        kryptos_freeseg(catalog_data);
        catalog_data_size = 0;
    }

    if (rootpath != NULL) {
        kryptos_freeseg(rootpath);
    }

    return exit_code;
}

int blackcat_cmd_add_help(void) {
    fprintf(stderr, "use: blackcat add <relative file path | glob pattern> [--plain]\n");
    return 0;
}

