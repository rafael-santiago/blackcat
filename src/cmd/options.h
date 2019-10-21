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

#define BLACKCAT_CONSUME_USER_OPTIONS(ac, option_var, consume_stmt, continue_from, consume_dashed_options) {\
    ac = continue_from;\
    do {\
        if (option_var == NULL || (!consume_dashed_options && option_var != NULL && strlen(option_var) > 1 &&\
                                   option_var[0] != '-' && option_var[1] != '-') || consume_dashed_options) {\
            consume_stmt;\
        }\
        do {\
            option_var = blackcat_get_argv(ac++);\
            if (option_var != NULL) {\
                option_var = remove_go_ups_from_path(option_var, strlen(option_var) + 1);\
            }\
        } while (option_var != NULL && strlen(option_var) > 1 && option_var[0] == '-' && option_var[1] == '-');\
    } while(option_var != NULL);\
}

void blackcat_clear_options(void);

char **mkargv(char **argv, const char *buf, const size_t buf_size, int *argc);

void freeargv(char **argv, const int argc);

char *blackcat_get_kdf_usr_params_from_cmdline(size_t *out_size);

int wrap_user_key_with_tokens(kryptos_u8_t **key, size_t *key_size);

int wrap_user_key_with_new_tokens(kryptos_u8_t **key, size_t *key_size);

#endif
