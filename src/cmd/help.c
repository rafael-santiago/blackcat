/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/help.h>
#include <cmd/defs.h>
#include <cmd/options.h>
#include <cmd/init.h>
#include <cmd/deinit.h>
#include <cmd/add.h>
#include <cmd/rm.h>
#include <cmd/lock.h>
#include <cmd/unlock.h>
#include <cmd/status.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_helper)
    BLACKCAT_COMMAND_TABLE_ENTRY(help_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(init_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(deinit_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(add_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(rm_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(lock_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(unlock_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(status_help)
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper)

int blackcat_cmd_help(void) {
    size_t h;
    char *topic, temp[100];
    int exit_code = EINVAL;

    topic = blackcat_get_argv(0);

    if (topic == NULL) {
        blackcat_cmd_help_help();
        goto blackcat_cmd_help_epilogue;
    }

    if (strlen(topic) > sizeof(temp) - 1) {
        fprintf(stderr, "Too long option. No SIGSEGVs for today. Goodbye!\n");
        goto blackcat_cmd_help_epilogue;
    }

    sprintf(temp, "%s_help", topic);

    for (h = 0; h < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper); h++) {
        if (strcmp(GET_BLACKCAT_COMMAND_NAME(g_blackcat_helper, h), temp) == 0) {
            return GET_BLACKCAT_COMMAND_TEXT(g_blackcat_helper, h)();
        }
    }

    fprintf(stderr, "No help entry for '%s'.\n", topic);

blackcat_cmd_help_epilogue:

    return exit_code;
}

int blackcat_cmd_help_help(void) {
    fprintf(stdout, "use: blackcat help <command>\n");
    return 0;
}
