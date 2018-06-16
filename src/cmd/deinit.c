/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/deinit.h>
#include <cmd/options.h>
#include <kryptos.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int blackcat_cmd_deinit(void) {
    int exit_code = EINVAL;
    char *rootpath = NULL;
    kryptos_u8_t *key;
    size_t key_size;

    rootpath = bcrepo_get_rootpath();

    if (rootpath == NULL) {
        fprintf(stderr, "ERROR: You are out of a blackcat repo.\n");
        goto blackcat_cmd_deinit_epilogue;
    }

    // INFO(Rafael): During a deinit we only need the first key or master key.
    //               No encrypted files will be decrypted.

    key = blackcat_getuserkey(&key_size);

    if (key == NULL) {
        fprintf(stderr, "ERROR: Null key.\n");
        goto blackcat_cmd_deinit_epilogue;
    }


    if (bcrepo_deinit(rootpath, strlen(rootpath), key, key_size)) {
        exit_code = 0;
    }

blackcat_cmd_deinit_epilogue:

    if (rootpath != NULL) {
        kryptos_freeseg(rootpath);
    }

    if (key != NULL) {
        kryptos_freeseg(key);
        key_size = 0;
    }

    return exit_code;
}

int blackcat_cmd_deinit_help(void) {
    fprintf(stderr, "use: blackcat deinit\n");
    return 0;
}
