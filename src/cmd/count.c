/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/count.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <fs/base/types.h>
#include <fs/bcrepo/bcrepo.h>
#include <accacia.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

int blackcat_cmd_count(void) {
    int count[255];
    blackcat_exec_session_ctx *session = NULL;
    int a;
    char *file_status;
    bfs_catalog_relpath_ctx *fp;
    int quiet;
    int exit_code = 0;
    bfs_file_status_t fstatus;

    file_status = blackcat_get_argv(0);
    if (file_status == NULL) {
        fprintf(stderr, "ERROR: You must inform at least one file status.\n");
        exit_code = EINVAL;
        goto blackcat_cmd_count_epilogue;
    }

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_count_epilogue;
    }

    quiet = blackcat_get_bool_option("quiet", 0);

    memset(count, 0, sizeof(count));

    if (session->catalog->files != NULL) {
        BLACKCAT_CONSUME_USER_OPTIONS(a,
                                      file_status,
                                      {
                                            fstatus = (strcmp(file_status, "--unlocked") == 0) ? 'U' :
                                                      (strcmp(file_status, "--locked")   == 0) ? 'L' :
                                                      (strcmp(file_status, "--plain")    == 0) ? 'P' : kBfsFileStatusNr;
                                            if (fstatus != kBfsFileStatusNr && count[(size_t)fstatus] == 0) {
                                                for (fp = session->catalog->files; fp != NULL; fp = fp->next) {
                                                    if (fp->status != fstatus) {
                                                        continue;
                                                    }
                                                    count[(size_t)fstatus]++;
                                                }
                                            }
                                      }, 1, 1)
    } else {
        fprintf(stderr, "The catalog is empty.\n");
    }

    if (quiet) {
        // INFO(Rafael): When --quiet is passed the count command will only return the total count as its exit code.
        //               Due to it do not do any wrong when passing quiet is quite important...
        exit_code = count[(size_t)'P'] + count[(size_t)'L'] + count[(size_t)'U'];
    } else {
        if (blackcat_get_bool_option("plain", 0)) {
            accacia_textcolor(AC_TCOLOR_GREEN);
            fprintf(stdout, "%12s %d file(s)\n", "Plain:", count[(size_t)'P']);
        }
        if (blackcat_get_bool_option("locked", 0)) {
            accacia_textcolor(AC_TCOLOR_RED);
            fprintf(stdout, "%12s %d file(s)\n", "Locked:", count[(size_t)'L']);
        }
        if (blackcat_get_bool_option("unlocked", 0)) {
            accacia_textcolor(AC_TCOLOR_YELLOW);
            fprintf(stdout, "%12s %d file(s)\n", "Unlocked:", count[(size_t)'U']);
        }
        accacia_screennormalize();
        fprintf(stdout, "Total count: %d file(s)\n", count[(size_t)'P'] + count[(size_t)'L'] + count[(size_t) + 'U']);
        exit_code = 0;
    }

blackcat_cmd_count_epilogue:

    memset(count, 0, sizeof(count));

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_count_help(void) {
    fprintf(stdout, "use: blackcat count --unlocked | --locked | --plain [--quiet]\n");
    return 0;
}
