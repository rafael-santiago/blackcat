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
#include <cmd/init.h>
#include <cmd/deinit.h>
#include <cmd/add.h>
#include <cmd/rm.h>
#include <cmd/lock.h>
#include <cmd/unlock.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_commands)
    BLACKCAT_COMMAND_TABLE_ENTRY(help),
    BLACKCAT_COMMAND_TABLE_ENTRY(version),
    BLACKCAT_COMMAND_TABLE_ENTRY(init),
    BLACKCAT_COMMAND_TABLE_ENTRY(deinit),
    BLACKCAT_COMMAND_TABLE_ENTRY(add),
    BLACKCAT_COMMAND_TABLE_ENTRY(rm),
    BLACKCAT_COMMAND_TABLE_ENTRY(lock),
    BLACKCAT_COMMAND_TABLE_ENTRY(unlock)
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands)

int blackcat_exec(int argc, char **argv) {
    size_t c;
    const char *command = NULL;
    int err = EINVAL;

    blackcat_set_argc_argv(argc, argv);

    if (blackcat_get_bool_option("set-high-priority", 0) == 1) {
        // WARN(Rafael): Yes, it is a paranoid care. This only seeks to mitigate the preemption, there is no guarantee.
        //               In fact, the best case would be a real-time OS, but...
        if ((err = setpriority(PRIO_PROCESS, 0, -20)) == -1) {
            fprintf(stderr, "ERROR: While setting the process' priority as high.\n");
            return err;
        }
    }

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

    return err;
}
