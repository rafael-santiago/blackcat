/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/undo.h>
#include <cmd/session.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_undo(void) {
    int exit_code = EFAULT;
    blackcat_exec_session_ctx *session = NULL;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_undo_epilogue;
    }

    if (bcrepo_restore(session->catalog, session->rootpath, session->rootpath_size)) {
        exit_code = 0;
    } else {
        exit_code = EFAULT;
    }

blackcat_cmd_undo_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_undo_help(void) {
    fprintf(stdout, "use: blackcat undo\n");
    return 0;
}
