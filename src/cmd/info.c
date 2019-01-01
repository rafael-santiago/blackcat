/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/info.h>
#include <cmd/session.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_info(void) {
    int exit_code = EINVAL;
    blackcat_exec_session_ctx *session = NULL;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_info_epilogue;
    }

    if (bcrepo_info(session->catalog) == 0) {
        fprintf(stderr, "ERROR: When extracting bcrepo info.\n");
        exit_code = EFAULT;
    }

    exit_code = 0;

blackcat_cmd_info_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_info_help(void) {
    fprintf(stdout, "use: blackcat info\n");
    return 0;
}
