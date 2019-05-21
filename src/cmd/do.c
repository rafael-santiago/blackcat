/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/do.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <fs/bcrepo/config.h>
#include <fs/bcrepo/bcrepo.h>
#include <kryptos.h>
#include <stdio.h>
#include <errno.h>

static char **get_cmds(const char *cmd_name, const blackcat_exec_session_ctx *session, int *argc);

static int is_registered_command(const char *cmd_name);

static char **get_cmds(const char *cmd_name, const blackcat_exec_session_ctx *session, int *argc) {
    struct bcrepo_config_ctx *cfg = NULL;
    int no_error = 0;
    char **argv = NULL;

    if (cmd_name == NULL || session == NULL || argc == NULL) {
        goto get_cmds_epilogue;
    }

    *argc = 0;

    if (!is_registered_command(cmd_name)) {
        fprintf(stderr, "ERROR: The command is not registered.\n");
        goto get_cmds_epilogue;
    }

    if (bcrepo_check_config_integrity(session->catalog, session->rootpath, session->rootpath_size) == 0) {
        fprintf(stderr, "ERROR: The config file seems corrupted. Open .bcrepo/CONFIG check it "
                        "and run 'blackcat config --update' if OK.\n");
        goto get_cmds_epilogue;
    }

    cfg = bcrepo_ld_config();

    if (bcrepo_config_get_section(cfg, cmd_name) == 0) {
        fprintf(stderr, "ERROR: Command body not found.\n");
        goto get_cmds_epilogue;
    }

    while (bcrepo_config_get_next_line(cfg) != 0) {
        (*argc)++;
    }

    if ((argv = (char **) kryptos_newseg((*argc) * sizeof(char *))) == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto get_cmds_epilogue;
    }

    no_error = 1;

    *argc = 0;

    bcrepo_config_get_section(cfg, cmd_name);

    while (bcrepo_config_get_next_line(cfg) != 0) {
        while (*cfg->line == '\t' || *cfg->line == ' ' && cfg->line != cfg->line_end) {
            cfg->line++;
        }

        if (cfg->line == cfg->line_end) {
            continue;
        }

        argv[*argc] = (char *) kryptos_newseg(cfg->line_end - cfg->line + 1);

        if (argv[*argc] == NULL) {
            fprintf(stderr, "ERROR: Not enough memory.\n");
            no_error = 0;
            goto get_cmds_epilogue;
        }

        memset(argv[*argc], 0, cfg->line_end - cfg->line + 1);
        memcpy(argv[*argc], cfg->line, cfg->line_end - cfg->line);

        (*argc)++;
    }

get_cmds_epilogue:

    if (cfg != NULL) {
        bcrepo_release_config(cfg);
    }

    if (no_error == 0 && argv != NULL) {
        freeargv(argv, *argc);
        *argc = 0;
        argv = NULL;
    }

    return argv;
}

static int is_registered_command(const char *cmd_name) {
    struct bcrepo_config_ctx *cfg = NULL;
    int is = 0;
    size_t cmd_name_size;

    if (cmd_name == NULL) {
        goto is_registered_command_epilogue;
    }

    if ((cfg = bcrepo_ld_config()) == NULL) {
        goto is_registered_command_epilogue;
    }

    if (bcrepo_config_get_section(cfg, BCREPO_CONFIG_SECTION_USER_COMMANDS) == 0) {
        goto is_registered_command_epilogue;
    }

    cmd_name_size = strlen(cmd_name);

    while (!is && bcrepo_config_get_next_word(cfg) != 0) {
        is = (cmd_name_size == (cfg->word_end - cfg->word)) && (memcmp(cmd_name, cfg->word, cmd_name_size) == 0);
    }

is_registered_command_epilogue:

    if (cfg != NULL) {
        bcrepo_release_config(cfg);
    }

    return is;
}

int blackcat_cmd_do(void) {
    int exit_code = EINVAL;
    char *do_param = NULL;
    blackcat_exec_session_ctx *session = NULL;
    int exec_nr = 0, a, aa;
    char temp[4096], cwd[4096];
    char **argv = NULL;
    int argc = 0;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_do_epilogue;
    }

    if (getcwd(cwd, sizeof(cwd) - 1) != NULL) {
        chdir(session->rootpath);
    }

    exit_code = 0;

    do_param = blackcat_get_argv(0);

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  do_param,
                                  {
                                      if (do_param == NULL || (argv = get_cmds(do_param + 2, session, &argc)) == NULL) {
                                          exit_code = EINVAL;
                                          goto blackcat_cmd_do_epilogue;
                                      }
                                      for (aa = 0; exit_code == 0 && aa < argc; aa++) {
                                          exit_code = system(argv[aa]);
                                      }
                                      if (exit_code != 0) {
                                          fprintf(stderr, "ERROR: While executing user command set. Aborted.\n");
                                          goto blackcat_cmd_do_epilogue;
                                      }
                                      freeargv(argv, argc);
                                      argv = NULL;
                                      argc = 0;
                                  })

    chdir(cwd);
    memset(cwd, 0, sizeof(cwd));

blackcat_cmd_do_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    if (argv != NULL) {
        freeargv(argv, argc);
    }

    return exit_code;
}

int blackcat_cmd_do_help(void) {
    fprintf(stdout, "use: blackcat do <pre-configured set of commands>\n");
    return 0;
}
