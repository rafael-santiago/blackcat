/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/lock.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_lock(void) {
    int exit_code = EINVAL;
    char *lock_param = NULL;
    blackcat_exec_session_ctx *session = NULL;
    int lock_nr;
    char temp[4096];

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 1)) != 0) {
        goto blackcat_cmd_lock_epilogue;
    }

    if ((lock_param = blackcat_get_argv(0)) != NULL) {
        lock_param = remove_go_ups_from_path(lock_param, strlen(lock_param) + 1);
    }

    lock_nr = bcrepo_lock(&session->catalog, session->rootpath, session->rootpath_size,
                          (lock_param != NULL) ? lock_param : "*", (lock_param != NULL) ? strlen(lock_param) : 1);

    if (lock_nr > 0) {
        if (bcrepo_write(bcrepo_catalog_file(temp, sizeof(temp), session->rootpath),
                         session->catalog, session->key[0], session->key_size[0])) {
            fprintf(stdout, "%d file(s) encrypted.\n", lock_nr);
            exit_code = 0;
        } else {
            fprintf(stderr, "ERROR: Unable to update the catalog file.\n");
            exit_code = EFAULT;
        }
    } else {
        fprintf(stdout, "File(s) not found.\n");
        exit_code = ENOENT;
    }

blackcat_cmd_lock_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_lock_help(void) {
    fprintf(stdout, "use: blackcat lock [<relative file path | glob pattern>]\n");
    return 0;
}
