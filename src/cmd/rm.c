/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/rm.h>
#include <cmd/options.h>
#include <cmd/session.h>
#include <fs/bcrepo/bcrepo.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_rm(void) {
    int exit_code = EINVAL;
    char *rm_param = NULL;
    int rm_nr;
    blackcat_exec_session_ctx *session = NULL;
    char temp[4096];

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 1)) != 0) {
        goto blackcat_cmd_rm_epilogue;
    }

    rm_param = blackcat_get_argv(0);

    if (rm_param == NULL) {
        fprintf(stderr, "ERROR: A relative file path or a glob pattern is missing.\n");
        exit_code = ENOTSUP;
        goto blackcat_cmd_rm_epilogue;
    }

    rm_param = remove_go_ups_from_path(rm_param, strlen(rm_param) + 1);

    rm_nr = bcrepo_rm(&session->catalog, session->rootpath, session->rootpath_size, rm_param, strlen(rm_param));

    if (rm_nr > 0) {
        if (bcrepo_write(bcrepo_catalog_file(temp, sizeof(temp), session->rootpath),
                         session->catalog, session->key[0], session->key_size[0])) {
            fprintf(stdout, "%d file(s) removed from repo's catalog.\n", rm_nr);
            exit_code = 0;
        } else {
            fprintf(stderr, "ERROR: Unable to update the catalog file.\n");
            exit_code = EFAULT;
        }
    } else {
        fprintf(stderr, "File(s) not found.\n");
        exit_code = ENOENT;
    }

blackcat_cmd_rm_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_rm_help(void) {
    fprintf(stdout, "use: blackcat rm <relative file name | glob pattern>\n");
    return 0;
}
