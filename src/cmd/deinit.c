/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/deinit.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <kryptos.h>
#include <fs/bcrepo/bcrepo.h>
#include <accacia.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int blackcat_cmd_deinit(void) {
    int exit_code = EINVAL;
    blackcat_exec_session_ctx *session = NULL;

    // INFO(Rafael): During a deinit we only need the first key or master key.
    //               No encrypted files will be decrypted.

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_deinit_epilogue;
    }

    if (bcrepo_deinit(session->rootpath, session->rootpath_size, session->key[0], session->key_size[0])) {
        exit_code = 0;
    } else {
        fprintf(stderr, "ERROR: While accessing the catalog.\n");
        exit_code = EACCES;
    }

blackcat_cmd_deinit_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_deinit_help(void) {
    fprintf(stdout, "use: blackcat deinit\n");
    return 0;
}
