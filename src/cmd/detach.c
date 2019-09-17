/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/detach.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_detach(void) {
    char *dest;
    int exit_code = EINVAL;

    BLACKCAT_GET_OPTION_OR_DIE(dest, "dest", blackcat_cmd_detach_epilogue);

    if (bcrepo_detach_metainfo(dest, strlen(dest))) {
        exit_code = 0;
    }

blackcat_cmd_detach_epilogue:

    return exit_code;
}

int blackcat_cmd_detach_help(void) {
    fprintf(stdout, "use: blackcat detach\n"
                    "              --dest=<metainfo file path>\n");
    return 0;
}
