/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_CMD_OPTIONS_H
#define BLACKCAT_CMD_OPTIONS_H 1

#include <stdlib.h>
#include <kryptos.h>

char *blackcat_get_option(const char *option, char *default_option);

int blackcat_get_bool_option(const char *option, const int default_state);

char *blackcat_get_command(void);

void blackcat_set_argc_argv(int argc, char **argv);

char *blackcat_get_argv(const int v);

kryptos_u8_t *blackcat_getuserkey(size_t *key_size);

#define BLACKCAT_GET_OPTION_OR_DIE(option, cute_option, esc_label) {\
    if ((option = blackcat_get_option(cute_option, NULL)) == NULL) {\
        fprintf(stderr, "ERROR: The required '%s' option is missing.\n", cute_option);\
        goto esc_label;\
    }\
}

void blackcat_clear_options(void);

#endif
