/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/unpack.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_unpack(void) {
    int exit_code = EINVAL;
    char *filepath;
    char *dirpath;

    filepath = blackcat_get_argv(0);

    if (filepath == NULL) {
        fprintf(stdout, "ERROR: file path is missing.\n");
        goto blackcat_cmd_unpack_epilogue;
    }

    dirpath = blackcat_get_argv(1);

    if (bcrepo_unpack(filepath, dirpath) != 1) {
        exit_code = EFAULT;
        goto blackcat_cmd_unpack_epilogue;
    }

    exit_code = 0;

blackcat_cmd_unpack_epilogue:

    return exit_code;
}

int blackcat_cmd_unpack_help(void) {
    fprintf(stdout, "use: blackcat unpack\n"
                    "              <file path>\n"
                    "              [<dir path>]\n");
    return 0;
}
