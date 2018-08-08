/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/paranoid.h>
#include <cmd/defs.h>
#include <cmd/options.h>
#include <cmd/session.h>
#include <fs/bcrepo/bcrepo.h>
#include <dev/defs/io.h>
#include <dev/defs/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>

#define BLACKCAT_DEVPATH "/dev/" CDEVNAME

static int dig_up_repo(void);

static int bury_repo(void);

static int find_hooks(void);

static int no_history(void);

static int clear_history(void);

static int do_ioctl(unsigned long cmd);

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_paranoid_commands)
    { "--bury-repo",     bury_repo     },
    { "--dig-up-repo",   dig_up_repo   },
    { "--find-hooks",    find_hooks    },
    { "--no-history",    no_history    },
    { "--clear-history", clear_history }
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_paranoid_commands)

int blackcat_cmd_paranoid(void) {
    int exit_code = 0;
    int arg = 0;
    char *sub_command;
    size_t c;

    while (exit_code == 0 || (sub_command = blackcat_get_argv(arg++)) != NULL) {
        for (c = 0; c < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_paranoid_commands); c++) {
            if (strcmp(sub_command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_paranoid_commands, c)) == 0) {
                exit_code = GET_BLACKCAT_COMMAND_TEXT(g_blackcat_paranoid_commands, c)();
            }
        }
    }

    return exit_code;
}

int blackcat_cmd_paranoid_help(void) {
    fprintf(stdout, "use: blackcat paranoid [--bury-repo | --dig-up-repo | "
                    "--find-hooks | --no-history | --clear-history]\n");
    return 0;
}

static int dig_up_repo(void) {
    return do_ioctl(BLACKCAT_DIG_UP_FOLDER);
}

static int bury_repo(void) {
    return do_ioctl(BLACKCAT_BURY_FOLDER);
}

static int find_hooks(void) {
    // TODO(Rafael): Implement this feature inside the char device and request the scan through an ioctl from here.
    return 1;
}

static int no_history(void) {
    // TODO(Rafael): Try to implement it independent of the current user shell.
    return 1;
}

static int clear_history(void) {
    // TODO(Rafael): Try to implement it independent of the current user shell.
    return 1;
}

static int do_ioctl(unsigned long cmd) {
    int dev;
    int err = 0;
    blackcat_exec_session_ctx *session = NULL;
    char pattern[4096];
    char *rp, *rp_end;

    if ((dev = open(BLACKCAT_DEVPATH, O_WRONLY)) == -1) {
        return ENODEV;
    }

    if ((err = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto do_ioctl;
    }

    rp = session->rootpath;
    rp_end = rp + session->rootpath_size;

#ifndef _WIN32
    while (rp_end != rp && *rp != '/') {
#else
    while (rp_end != rp && *rp != '/' && *rp != '\\') {
#endif
        rp_end--;
    }

    memset(pattern, 0, sizeof(pattern));

    sprintf(pattern, "*%s*", rp_end);

    err = ioctl(dev, cmd, pattern);

do_ioctl:

    memset(pattern, 0, sizeof(pattern));

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    if (dev > -1) {
        close(dev);
    }

    return err;
}
