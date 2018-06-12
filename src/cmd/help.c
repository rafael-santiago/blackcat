/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/help.h>
#include <cmd/defs.h>
#include <stdio.h>

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_helper)
    BLACKCAT_COMMAND_TABLE_ENTRY(help_help)
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper)

int blackcat_cmd_help(void) {
    size_t h;

    // TODO(Rafael): Guess what?....

    for (h = 0; h < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper); h++) {
    }
}

int blackcat_cmd_help_help(void) {
    fprintf(stdout, "use: blackcat help <command>\n");
}
