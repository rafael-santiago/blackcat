/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/options.h>
#include <string.h>
#include <stdio.h>

static char *g_blackcat_cmd = NULL;

static char **g_blackcat_argv = NULL;

static int g_blackcat_argc = 0;

char *blackcat_get_option(const char *option, char *default_option) {
    char temp[4096];
    int a;

    if (option == NULL) {
        return NULL;
    }

    sprintf(temp, "--%s=", option);

    for (a = 0; a < g_blackcat_argc; a++) {
        if (strstr(g_blackcat_argv[a], temp) == &g_blackcat_argv[a][0]) {
            return &g_blackcat_argv[a][0] + strlen(temp);
        }
    }

    return default_option;
}

int blackcat_get_bool_option(const char *option, const int default_state) {
    char temp[4096];
    int a;

    if (option == NULL) {
        return 0;
    }

    sprintf(temp, "--%s", option);

    for (a = 0; a < g_blackcat_argc; a++) {
        if (strcmp(g_blackcat_argv[a], temp) == 0) {
            return 1;
        }
    }

    return default_state;
}

char *blackcat_get_command(void) {
    return g_blackcat_cmd;
}

void blackcat_set_argc_argv(int argc, char **argv) {
    if (argv == NULL) {
        g_blackcat_cmd = NULL;
        g_blackcat_argv = NULL;
        g_blackcat_argc = 0;
    } else {
        g_blackcat_cmd = argv[1];
        g_blackcat_argv = &argv[2];
        g_blackcat_argc = argc - 2;
    }
}

char *blackcat_get_argv(const int v) {
    if (v < 0 || v >= g_blackcat_argc) {
        return NULL;
    }

    return &g_blackcat_argv[v][0];
}


void blackcat_clear_options(void) {
    // WARN(Rafael): This is not an alibi to pass sensible data through command line.
    size_t size;

    if (g_blackcat_cmd != NULL) {
        size = strlen(g_blackcat_cmd);
        memset(g_blackcat_cmd, 0, size);
    }

    if (g_blackcat_argv != NULL) {
        while (g_blackcat_argc-- > -1) {
            size = strlen(g_blackcat_argv[g_blackcat_argc]);
            memset(g_blackcat_argv[g_blackcat_argc], 0, size);
        }
    }

    g_blackcat_cmd = NULL;
    g_blackcat_argv = NULL;
    g_blackcat_argc = 0;
    size = 0;
}
