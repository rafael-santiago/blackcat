/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/unlock.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <cmd/checkpoint.h>
#include <fs/bcrepo/bcrepo.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_unlock(void) {
    int exit_code = EINVAL;
    char *unlock_param = NULL;
    blackcat_exec_session_ctx *session = NULL;
    int unlock_nr = 0;
    char temp[4096], cwd[4096];
    int a;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 1)) != 0) {
        goto blackcat_cmd_unlock_epilogue;
    }

    if ((unlock_param = blackcat_get_argv(0)) != NULL) {
        unlock_param = remove_go_ups_from_path(unlock_param, strlen(unlock_param) + 1);
    }

    if (unlock_param == NULL) {
        if (getcwd(cwd, sizeof(cwd) - 1) != NULL) {
            chdir(session->rootpath);
        }
    }

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  unlock_param,
                                  {
                                    unlock_nr += bcrepo_unlock(&session->catalog,
                                                               session->rootpath, session->rootpath_size,
                                                               unlock_param,
                                                               (unlock_param != NULL) ? strlen(unlock_param) : 0,
                                                               blackcat_checkpoint, session);
                                  }, 1, 0)

    if (unlock_param == NULL) {
        chdir(cwd);
        memset(cwd, 0, sizeof(cwd));
    }

    if (unlock_nr > 0) {
        fprintf(stdout, "%d file(s) decrypted.\n", unlock_nr);
        exit_code = 0;
    } else {
        fprintf(stdout, "File(s) not found.\n");
        exit_code = ENOENT;
    }

blackcat_cmd_unlock_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_unlock_help(void) {
    fprintf(stdout, "use: blackcat unlock\n"
                    "              [<relative file path | glob pattern>]\n");
    return 0;
}
