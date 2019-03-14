/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/untouch.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <cmd/checkpoint.h>
#include <fs/bcrepo/bcrepo.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_untouch(void) {
    int exit_code = EINVAL;
    char *untouch_param = NULL;
    blackcat_exec_session_ctx *session = NULL;
    int untouch_nr = 0;
    char cwd[4096];
    int a, hard;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_untouch_epilogue;
    }

    if ((untouch_param = blackcat_get_argv(0)) != NULL) {
        untouch_param = remove_go_ups_from_path(untouch_param, strlen(untouch_param) + 1);
    }

    if (untouch_param == NULL) {
        if (getcwd(cwd, sizeof(cwd) - 1) != NULL) {
            chdir(session->rootpath);
        }
    }

    hard = blackcat_get_bool_option("hard", 0);

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  untouch_param,
                                  {
                                    untouch_nr += bcrepo_untouch(session->catalog, session->rootpath, session->rootpath_size,
                                                                 (untouch_param != NULL) ? untouch_param : "*",
                                                                 (untouch_param != NULL) ? strlen(untouch_param) : 1, hard);
                                  })

    if (untouch_param == NULL) {
        chdir(cwd);
        memset(cwd, 0, sizeof(cwd));
    }

    if (untouch_nr > 0) {
        fprintf(stdout, "%d file(s) untouched.\n", untouch_nr);
        exit_code = 0;
    } else {
        fprintf(stdout, "File(s) not found.\n");
        exit_code = ENOENT;
    }

blackcat_cmd_untouch_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_untouch_help(void) {
    fprintf(stdout, "use: blackcat untouch [<glob pattern>, <relative path list> --hard]\n");
    return 0;
}
