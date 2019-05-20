/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/config.h>
#include <cmd/defs.h>
#include <cmd/session.h>
#include <cmd/checkpoint.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int config_update(void);

static int config_remove(void);

static int check_integrity(void);

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_config_commands)
    { "--update",          config_update   },
    { "--remove",          config_remove   },
    { "--check-integrity", check_integrity }
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_config_commands)

static int arg;

int blackcat_cmd_config(void) {
    int exit_code = 0;
    char *sub_command;
    size_t c;

    arg = 0;
    exit_code = 0;
    sub_command = blackcat_get_argv(arg++);

    if (sub_command == NULL) {
        fprintf(stderr, "ERROR: No command supplied.\n");
        exit_code = EINVAL;
        goto blackcat_cmd_config_epilogue;
    }

    while (exit_code == 0 && sub_command != NULL) {
        exit_code = EINVAL;
        for (c = 0; c < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_config_commands); c++) {
            if (strcmp(sub_command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_config_commands, c)) == 0) {
                exit_code = GET_BLACKCAT_COMMAND_TEXT(g_blackcat_config_commands, c)();
            }
        }
        sub_command = blackcat_get_argv(arg++);
    }

blackcat_cmd_config_epilogue:

    return exit_code;
}

int blackcat_cmd_config_help(void) {
    fprintf(stdout, "use: blackcat config [--update | --remove | --check-integrity]\n");
    return 0;
}

static int config_update(void) {
    int exit_code = EINVAL;
    blackcat_exec_session_ctx *session = NULL;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto config_update_epilogue;
    }

    exit_code = 0;

    if (bcrepo_config_update(&session->catalog,
                             session->rootpath, session->rootpath_size, blackcat_checkpoint, session) != 1) {
        exit_code = EFAULT;
    }

config_update_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

static int config_remove(void) {
    int exit_code = EINVAL;
    blackcat_exec_session_ctx *session = NULL;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto config_remove_epilogue;
    }

    exit_code = 0;

    if (bcrepo_config_remove(&session->catalog,
                             session->rootpath, session->rootpath_size, blackcat_checkpoint, session) != 1) {
        exit_code = EFAULT;
    }

config_remove_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

static int check_integrity(void) {
    int exit_code = EINVAL;
    blackcat_exec_session_ctx *session = NULL;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto check_integrity_epilogue;
    }

    exit_code = 0;

    if (bcrepo_check_config_integrity(session->catalog, session->rootpath, session->rootpath_size) != 1) {
        fprintf(stderr, "ERROR: The config file has changed since the last update. "
                        "Check its content before doing a new update!\n");
        exit_code = EFAULT;
    }

check_integrity_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}
