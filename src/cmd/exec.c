/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/exec.h>
#include <cmd/defs.h>
#include <cmd/options.h>
#include <cmd/help.h>
#include <cmd/version.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_commands)
    BLACKCAT_COMMAND_TABLE_ENTRY(help),
    BLACKCAT_COMMAND_TABLE_ENTRY(version)
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands)

int blackcat_exec(int argc, char **argv) {
    size_t c;
    const char *command = NULL;

    blackcat_set_argc_argv(argc, argv);

    command = blackcat_get_command();

    if (command == NULL) {
        goto blackcat_exec_epilogue;
    }

    if (strcmp(command, "--version") == 0) {
        return blackcat_cmd_version();
    }

    for (c = 0; c < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands); c++) {
        if (strcmp(command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_commands, c)) == 0) {
            return GET_BLACKCAT_COMMAND_TEXT(g_blackcat_commands, c)();
        }
    }

blackcat_exec_epilogue:

    fprintf(stderr, "ERROR: Invalid command.\n");

    return -EINVAL;
}