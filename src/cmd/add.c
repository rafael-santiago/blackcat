/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/add.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_add(void) {
    int exit_code = EINVAL;
    char *add_param;
    int add_nr = 0;
    blackcat_exec_session_ctx *session = NULL;
    char temp[4096];
    int a;
    int lock = 0;

    lock = blackcat_get_bool_option("lock", 0);

    if ((exit_code = new_blackcat_exec_session_ctx(&session, lock)) != 0) {
        goto blackcat_cmd_add_epilogue;
    }

    add_param = blackcat_get_argv(0);

    if (add_param == NULL) {
        fprintf(stderr, "ERROR: A relative file path or a glob pattern is missing.\n");
        exit_code = ENOTSUP;
        goto blackcat_cmd_add_epilogue;
    }

    add_param = remove_go_ups_from_path(add_param, strlen(add_param) + 1);

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  add_param,
                                  {
                                    add_nr += bcrepo_add(&session->catalog,
                                                         session->rootpath, session->rootpath_size,
                                                         add_param, strlen(add_param),
                                                         blackcat_get_bool_option("plain", 0));
                                  })

    if (add_nr > 0) {
        if (bcrepo_write(bcrepo_catalog_file(temp, sizeof(temp), session->rootpath),
                         session->catalog, session->key[0], session->key_size[0])) {
            fprintf(stdout, "%d file(s) added.\n", add_nr);
            exit_code = 0;
            if (lock) {
                add_nr = 0;

                add_param = blackcat_get_argv(0);
                add_param = remove_go_ups_from_path(add_param, strlen(add_param) + 1);

                BLACKCAT_CONSUME_USER_OPTIONS(a,
                                              add_param,
                                              {
                                                add_nr += bcrepo_lock(&session->catalog, session->rootpath,
                                                                      session->rootpath_size,
                                                                      (add_param != NULL) ? add_param : "*",
                                                                      (add_param != NULL) ? strlen(add_param) : 1);
                                              })

                if (bcrepo_write(bcrepo_catalog_file(temp, sizeof(temp), session->rootpath),
                                                     session->catalog, session->key[0], session->key_size[0])) {
                    fprintf(stdout, "%d file(s) encrypted.\n", add_nr);
                } else {
                    fprintf(stderr, "WARN: File(s) added but no encrypted. Try to execute a lock by yourself.\n");
                }
            }
        } else {
            fprintf(stderr, "ERROR: Unable to update the catalog file.\n");
            exit_code = EFAULT;
        }
    } else {
        fprintf(stderr, "File(s) not found.\n");
        exit_code = ENOENT;
    }

blackcat_cmd_add_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_add_help(void) {
    fprintf(stdout, "use: blackcat add <relative file path | glob pattern> [--plain | --lock]\n");
    return 0;
}

