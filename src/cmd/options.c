/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/options.h>
#include <fs/bcrepo/config.h>
#include <string.h>
#include <stdio.h>

static char *g_blackcat_cmd = NULL;

static char **g_blackcat_argv = NULL;

static int g_blackcat_argc = 0;

static char  **g_blackcat_argv_head = NULL;

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
    struct bcrepo_config_ctx *cfg = NULL;
    char *cmdline = NULL, *cp;
    size_t cmdline_size, temp_size;
    int a;

    if (g_blackcat_argv_head != NULL) {
        blackcat_clear_options();
        g_blackcat_argv_head = NULL;
    }

    if (argv == NULL) {
        g_blackcat_cmd = NULL;
        g_blackcat_argv = NULL;
        g_blackcat_argc = 0;
    } else {

        if ((cfg = bcrepo_ld_config()) == NULL) {
            g_blackcat_cmd = argv[1];
            g_blackcat_argv = &argv[2];
            g_blackcat_argc = argc - 2;
        } else {
            if (bcrepo_config_get_section(cfg, BCREPO_CONFIG_SECTION_DEFAULT_ARGS) != 0) {
                cmdline_size = 0;
                for (a = 1; a < argc; a++) {
                    cmdline_size += strlen(argv[a]) + 1;
                }

                while (bcrepo_config_get_next_word(cfg) != 0) {
                    cmdline_size = cfg->word_end - cfg->word + 1;
                }

                if ((cmdline = (char *) kryptos_newseg(cmdline_size)) == NULL) {
                    goto blackcat_set_argc_argv_epilogue;
                }


                memset(cmdline, 0, cmdline_size);
                cp = cmdline;

                for (a = 1; a < argc; a++) {
                    temp_size = strlen(argv[a]);
                    memcpy(cp, argv[a], temp_size);
                    *(cp + temp_size) = ' ';
                    cp += temp_size + 1;
                }

                bcrepo_config_get_section(cfg, BCREPO_CONFIG_SECTION_DEFAULT_ARGS);

                while (bcrepo_config_get_next_word(cfg) != 0) {
                    temp_size = cfg->word_end - cfg->word;
                    memcpy(cp, cfg->word, temp_size);
                    *(cp + temp_size) = ' ';
                    cp += temp_size + 1;
                }

                // INFO(Rafael): Nasty trick for clearing original command line arguments easily.

                g_blackcat_argv_head = NULL;

                g_blackcat_cmd = argv[1];
                g_blackcat_argv = &argv[2];
                g_blackcat_argc = argc - 2;
                blackcat_clear_options();

                g_blackcat_argv_head = mkargv(g_blackcat_argv_head, cmdline, cmdline_size, &g_blackcat_argc);

                g_blackcat_cmd = g_blackcat_argv_head[1];
                g_blackcat_argv = &g_blackcat_argv_head[2];
                g_blackcat_argc = g_blackcat_argc - 1;
            }
        }
    }

blackcat_set_argc_argv_epilogue:

    if (cfg != NULL) {
        bcrepo_release_config(cfg);
    }

    if (cmdline != NULL) {
        kryptos_freeseg(cmdline, cmdline_size);
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

    if (g_blackcat_argv_head == NULL) {
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
    } else {
        freeargv(g_blackcat_argv_head, g_blackcat_argc + 1);
    }

    g_blackcat_cmd = NULL;
    g_blackcat_argv = NULL;
    g_blackcat_argc = 0;
    size = 0;
}

char **mkargv(char **argv, const char *buf, const size_t buf_size, int *argc) {
    const char *bp, *bp_end, *bp_off;
    int a;
    size_t a_size;

    if (buf == NULL || buf_size == 0 || argc == NULL) {
        return NULL;
    }

    bp = buf;
    bp_end = bp + buf_size + 1;

    *argc = 1;

    while (bp < bp_end) {
        if (*bp == '\\') {
            bp++;
        } else if (*bp == ' ' || *bp == 0) {
            (*argc)++;
            while (*bp == ' ') {
                bp++;
            }
        }
        bp++;
    }

    if ((argv = (char **) kryptos_newseg(sizeof(char *) * (*argc))) == NULL) {
        return NULL;
    }

    argv[0] = NULL; // INFO(Rafael): Dummy entry.
    a = 1;

    bp = bp_off = buf;
    bp_end = bp + buf_size + 1;

    while (bp < bp_end) {
        if (*bp == '\\') {
            bp++;
        } else if (*bp == ' ' || *bp == 0) {
            a_size = bp - bp_off + 1;
            if ((argv[a] = (char *) kryptos_newseg(a_size)) == NULL) {
                return NULL; // INFO(Rafael): Assuming it almost impossible, let leaking.
            }
            memset(argv[a], 0, a_size);
            memcpy(argv[a], bp_off, a_size - 1);
            a++;
            while (*bp == ' ') {
                bp++;
            }
            bp_off = bp;
        }
        bp++;
    }

    return argv;
}

void freeargv(char **argv, const int argc) {
    int a;

    if (argv == NULL || argc == 0) {
        return;
    }

    for (a = 0; a < argc; a++) {
        if (argv[a] != NULL) {
            kryptos_freeseg(argv[a], strlen(argv[a]));
        }
    }

    kryptos_freeseg(argv, sizeof(char *) * argc);
}
