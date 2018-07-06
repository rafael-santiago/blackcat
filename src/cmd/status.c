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
#include <fs/strglob.h>
#include <accacia.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

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
                                       })
    } else {
        fprintf(stdout, "The catalog is empty.\n");
        exit_code = ENOENT;
    }

#undef print_file_info

blackcat_cmd_status_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_status_help(void) {
    fprintf(stdout, "use: blackcat status [relative file path | <glob pattern>]\n");
    return 0;
}