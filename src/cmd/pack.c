/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/pack.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <cmd/checkpoint.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_pack(void) {
    int exit_code = EINVAL;
    blackcat_exec_session_ctx *session = NULL;
    char *pack_param;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 1)) != 0) {
        exit_code = EACCES;
        goto blackcat_cmd_pack_epilogue;
    }

    exit_code = EINVAL;

    pack_param = blackcat_get_argv(0);

    if (pack_param == NULL) {
        fprintf(stderr, "ERROR: file path is missing.\n");
        goto blackcat_cmd_pack_epilogue;
    }

    if (bcrepo_pack(&session->catalog, session->rootpath, session->rootpath_size, pack_param,
                    blackcat_checkpoint, session) != 1) {
        exit_code = EFAULT;
        goto blackcat_cmd_pack_epilogue;
    }

    exit_code = 0;

blackcat_cmd_pack_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_pack_help(void) {
    fprintf(stdout, "use: blackcat pack <file path>\n");
    return 0;
}
