/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/status.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <fs/bcrepo/config.h>
#include <fs/strglob.h>
#include <accacia.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

static void set_stdout(void);

FILE *g_blackcat_cmd_status_stdout = NULL;

int blackcat_cmd_status(void) {
    int exit_code = EINVAL;
    blackcat_exec_session_ctx *session = NULL;
    bfs_catalog_relpath_ctx *fp;
    char *status_param;
    time_t t;
    char date[50];
    int a;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_status_epilogue;
    }

    if ((status_param = blackcat_get_argv(0)) != NULL) {
        status_param = remove_go_ups_from_path(status_param, strlen(status_param) + 1);
    }

    set_stdout();

#define print_file_info(f, d) {\
    switch (f->status) {\
        case kBfsFileStatusPlain:\
            accacia_textcolor(AC_TCOLOR_GREEN);\
            fprintf(stdout, "\tplain file: ");\
            break;\
        case kBfsFileStatusLocked:\
            accacia_textcolor(AC_TCOLOR_RED);\
            fprintf(stdout, "\tlocked file: ");\
            break;\
        case kBfsFileStatusUnlocked:\
            accacia_textcolor(AC_TCOLOR_YELLOW);\
            fprintf(stdout, "\tunlocked file: ");\
            break;\
        default:\
            break;\
    }\
    fprintf(stdout, "%s (%s)\n", f->path, d);\
    accacia_screennormalize();\
}

    if (session->catalog->files != NULL) {
        BLACKCAT_CONSUME_USER_OPTIONS(a,
                                      status_param,
                                      {
                                        for (fp = session->catalog->files; fp != NULL; fp = fp->next) {
                                            if (status_param == NULL || strglob(fp->path, status_param)) {
                                                t = (time_t)strtoul(fp->timestamp, NULL, 10);
                                                strftime(date, sizeof(date) - 1, "%b %d %Y %H:%M:%S", localtime(&t));
                                                print_file_info(fp, date);
                                            }
                                        }
                                        exit_code = 0;
                                       }, 1)
    } else {
        fprintf(stdout, "The catalog is empty.\n");
        exit_code = ENOENT;
    }

#undef print_file_info

blackcat_cmd_status_epilogue:

    if (stdout != g_blackcat_cmd_status_stdout) {
        pclose(stdout);
        stdout = g_blackcat_cmd_status_stdout;
    }

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_status_help(void) {
    fprintf(stdout, "use: blackcat status\n"
                    "              [relative file path | <glob pattern>]\n");
    return 0;
}

static void set_stdout(void) {
    struct bcrepo_config_ctx *bcrepo_cfg = NULL;
    char vcmd[4096];
    size_t vcmd_size;

    if (g_blackcat_cmd_status_stdout == NULL) {
        g_blackcat_cmd_status_stdout = stdout;
    }

    if ((bcrepo_cfg = bcrepo_ld_config()) == NULL) {
        goto get_stddest_epilogue;
    }

    if (bcrepo_config_get_section(bcrepo_cfg, "status-viewer") == 0) {
        goto get_stddest_epilogue;
    }

    if (bcrepo_config_get_next_word(bcrepo_cfg) == 0) {
        goto get_stddest_epilogue;
    }

    vcmd_size = bcrepo_cfg->word_end - bcrepo_cfg->word;

    if (vcmd_size > sizeof(vcmd) - 1) {
        fprintf(stderr, "ERROR: The status-viewer command is too long.\n");
        goto get_stddest_epilogue;
    }

    memset(vcmd, 0, sizeof(vcmd));
    memcpy(vcmd, bcrepo_cfg->word, vcmd_size);

    if ((stdout = popen(vcmd, "w")) == NULL) {
        fprintf(stderr, "ERROR: When trying to open status-viewer process. Assuming standard output.\n");
        stdout = g_blackcat_cmd_status_stdout;
    }

get_stddest_epilogue:

    if (bcrepo_cfg != NULL) {
        bcrepo_release_config(bcrepo_cfg);
    }
}
