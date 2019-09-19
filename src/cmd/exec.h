/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CMD_EXEC_H
#define BLACKCAT_CMD_EXEC_H 1

#include <stdlib.h>
#include <cmd/defs.h>

extern struct blackcat_avail_cmds_ctx g_blackcat_commands[];

extern size_t g_blackcat_commands_nr;

int blackcat_exec(int argc, char **argv);

#endif
