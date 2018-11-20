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
#include <kbd/kbd.h>

char *blackcat_get_option(const char *option, char *default_option);

int blackcat_get_bool_option(const char *option, const int default_state);

char *blackcat_get_command(void);

void blackcat_set_argc_argv(int argc, char **argv);

char *blackcat_get_argv(const int v);

#define BLACKCAT_GET_OPTION_OR_DIE(option, cute_option, esc_label) {\
    if ((option = blackcat_get_option(cute_option, NULL)) == NULL) {\
        fprintf(stderr, "ERROR: The required '%s' option is missing.\n", cute_option);\
        goto esc_label;\
    }\
}

#define BLACKCAT_CONSUME_USER_OPTIONS(ac, option_var, consume_stmt) {\
    ac = 1;\
    do {\
        consume_stmt;\
        do {\
            option_var = blackcat_get_argv(ac++);\
            if (option_var != NULL) {\
                option_var = remove_go_ups_from_path(option_var, strlen(option_var) + 1);\
            }\
        } while (option_var != NULL && strlen(option_var) > 1 && option_var[0] == '-' && option_var[1] == '-');\
    } while(option_var != NULL);\
}

void blackcat_clear_options(void);

#endif
