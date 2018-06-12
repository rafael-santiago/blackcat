/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CMD_DEFS_H
#define BLACKCAT_CMD_DEFS_H 1

struct blackcat_avail_cmds_ctx {
    const char *name;
    int (*text)(void);
};

#define DECL_BLACKCAT_COMMAND_TABLE(table) static struct blackcat_avail_cmds_ctx table[] = {

#define BLACKCAT_COMMAND_TABLE_ENTRY(command) { #command, blackcat_cmd_ ## command }

#define DECL_BLACKCAT_COMMAND_TABLE_END };

#define DECL_BLACKCAT_COMMAND_TABLE_SIZE(table) static size_t table ## _nr = sizeof(table) / sizeof(table[0]);

#define GET_BLACKCAT_COMMAND_TABLE_SIZE(table) table ## _nr

#define GET_BLACKCAT_COMMAND_NAME(table, i) table[(i)].name

#define GET_BLACKCAT_COMMAND_TEXT(table, i) table[(i)].text

#endif
