/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CMD_OPTIONS_H
#define BLACKCAT_CMD_OPTIONS_H 1

char *blackcat_get_option(const char *option, char *default_option);

int blackcat_get_bool_option(const char *option, const int default_state);

char *blackcat_get_command(void);

void blackcat_set_argc_argv(int argc, char **argv);

#endif
