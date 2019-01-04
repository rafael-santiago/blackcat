/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/attach.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_attach(void) {
    char *src;
    int exit_code = EINVAL;

    BLACKCAT_GET_OPTION_OR_DIE(src, "src", blackcat_cmd_attach_epilogue);

    if (bcrepo_attach_metainfo(src, strlen(src))) {
        exit_code = 0;
    }

blackcat_cmd_attach_epilogue:

    return exit_code;
}

int blackcat_cmd_attach_help(void) {
    fprintf(stdout, "use: blackcat attach --src=<metainfo file path>\n");
    return 0;
}
