/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#if defined(__unix__)

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
#include <stdarg.h>

#define BLACKCAT_DEVPATH "/dev/" CDEVNAME

# if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)

static int dig_up(void);

static int bury(void);

static int bury_repo(void);

static int dig_up_repo(void);

static int find_hooks(void);

static int do_ioctl(unsigned long cmd, ...);

static int br_dgur_handle(unsigned long cmd);

# endif

static int disable_history(void);

static int enable_history(void);

static int clear_history(void);

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_paranoid_commands)
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
    { "--bury",            bury            },
    { "--dig-up",          dig_up          },
    { "--bury-repo",       bury_repo       },
    { "--dig-up-repo",     dig_up_repo     },
    { "--find-hooks",      find_hooks      },
#endif
    { "--disable-history", disable_history },
    { "--enable-history",  enable_history  },
    { "--clear-history",   clear_history   }
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_paranoid_commands)

static int arg = 0;

int blackcat_cmd_paranoid(void) {
    int exit_code = 0;
    char *sub_command;
    size_t c;

    arg = 0;

    while (exit_code == 0 && (sub_command = blackcat_get_argv(arg++)) != NULL) {
        for (c = 0; c < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_paranoid_commands); c++) {
            if (strcmp(sub_command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_paranoid_commands, c)) == 0) {
                exit_code = GET_BLACKCAT_COMMAND_TEXT(g_blackcat_paranoid_commands, c)();
            }
        }
    }

    return exit_code;
}

int blackcat_cmd_paranoid_help(void) {
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
    fprintf(stdout, "use: blackcat paranoid\n"
                    "               [--bury            |\n"
                    "                --bury-repo       |\n"
                    "                --dig-up          |\n"
                    "                --dig-up-repo     |\n"
                    "                --find-hooks      |\n"
                    "                --disable-history |\n"
                    "                --enable-history  |\n"
                    "                --clear-history   ]\n");
#elif defined(__OpenBSD__) || defined(__minix__)
    fprintf(stdout, "use: blackcat paranoid\n"
                    "               [--disable-history |\n"
                    "                --enable-history  |\n"
                    "                --clear-history   ]\n");
#else
# error Some code wanted.
#endif
    return 0;
}

# if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)

static int bury_repo(void) {
    int exit_code = br_dgur_handle(BLACKCAT_BURY);

    if (exit_code != 0) {
        fprintf(stderr, "ERROR: While trying to hide repo.\n");
    }

    return exit_code;
}

static int dig_up_repo(void) {
    int exit_code = br_dgur_handle(BLACKCAT_DIG_UP);

    if (exit_code != 0) {
        fprintf(stderr, "ERROR: While trying to show repo.\n");
    }

    return exit_code;
}

static int dig_up(void) {
    int exit_code = EINVAL;
    char *dig_up_param;
    blackcat_exec_session_ctx *session = NULL;
    int dig_up_nr = 0, a;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto dig_up_epilogue;
    }

    if ((dig_up_param = blackcat_get_argv(arg)) != NULL) {
        dig_up_param = remove_go_ups_from_path(dig_up_param, strlen(dig_up_param) + 1);
    }

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  dig_up_param,
                                  {
                                    dig_up_nr += bcrepo_dig_up(&session->catalog, session->rootpath, session->rootpath_size,
                                                               (dig_up_param != NULL) ? dig_up_param : "*",
                                                               (dig_up_param != NULL) ? strlen(dig_up_param) : 1);
                                  }, arg + 1);

    if (dig_up_nr > 0) {
        fprintf(stdout, "%d file(s) shown.\n", dig_up_nr);
        exit_code = 0;
    } else {
        fprintf(stdout, "File(s) not found.\n");
        exit_code = ENOENT;
    }

dig_up_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

static int bury(void) {
    int exit_code = EINVAL;
    char *bury_param;
    blackcat_exec_session_ctx *session = NULL;
    int bury_nr = 0, a;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto bury_epilogue;
    }

    if ((bury_param = blackcat_get_argv(arg)) != NULL) {
        bury_param = remove_go_ups_from_path(bury_param, strlen(bury_param) + 1);
    }

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  bury_param,
                                  {
                                    bury_nr += bcrepo_bury(&session->catalog, session->rootpath, session->rootpath_size,
                                                           (bury_param != NULL) ? bury_param : "*",
                                                           (bury_param != NULL) ? strlen(bury_param) : 1);
                                  }, arg + 1);

    if (bury_nr > 0) {
        fprintf(stdout, "%d file(s) hidden.\n", bury_nr);
        exit_code = 0;
    } else {
        fprintf(stdout, "File(s) not found.\n");
        exit_code = ENOENT;
    }

bury_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

static int find_hooks(void) {
    int err;
    blackcat_exec_session_ctx *session = NULL;

    if ((err = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto find_hooks_epilogue;
    }

    if ((err = do_ioctl(BLACKCAT_SCAN_HOOK)) != 0) {
        switch (err) {
            case ENODEV:
                fprintf(stdout, "ERROR: The hook finder cannot be started. The kernel module is not currently loaded.\n");
                break;

            default:
                fprintf(stdout, "WARN: The system seems hooked. "
                                "You should not edit sensible data here and also should burn this machine.\n");
                break;
        }
    }

find_hooks_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return err;
}

static int br_dgur_handle(unsigned long cmd) {
    int exit_code = 1;
    blackcat_exec_session_ctx *session = NULL;
    unsigned char temp[4096];
    char *rp_end;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto br_dgur_handle_epilogue;
    }

    rp_end = session->rootpath + session->rootpath_size;

    while (rp_end != session->rootpath && *rp_end != '/') {
        rp_end--;
    }

    sprintf((char *)temp, "*%s*", rp_end + (*rp_end == '/'));

    exit_code = do_ioctl(cmd, temp);

    memset(temp, 0, sizeof(temp));

br_dgur_handle_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

static int do_ioctl(unsigned long cmd, ...) {
    int dev;
    int err = 0;
    unsigned char *data = (unsigned char *)&cmd + sizeof(cmd);
    struct blackcat_devio_ctx devio, *devio_p = NULL;
    va_list vl;

    if ((dev = open(BLACKCAT_DEVPATH, O_WRONLY)) == -1) {
        return ENODEV;
    }

    if (cmd == BLACKCAT_BURY || cmd == BLACKCAT_DIG_UP) {
        va_start(vl, cmd);
        if (data != NULL) {
            devio.data = va_arg(vl, unsigned char *);
            devio.data_size = strlen((char *)devio.data);
            devio_p = &devio;
        }
    }

    err = ioctl(dev, cmd, devio_p);

    if (devio_p != NULL) {
        va_end(vl);
        devio_p->data = NULL;
        devio_p->data_size = 0;
    }

    if (dev > -1) {
        close(dev);
    }

    return err;
}

# endif

static int enable_history(void) {
    int err = 1;
    char *shell = getenv("SHELL");

    if (shell == NULL) {
        fprintf(stdout, "ERROR: Unable to find out your current shell.\n");
        goto enable_history_epilogue;
    }

    if (strstr(shell, "/bash") != NULL) {
        err = system("set -o history");
    } else if (strstr(shell, "/sh") != NULL) {
        err = system("unset HISTSIZE");
    } else if (strstr(shell, "/ksh") != NULL) {
        // TODO(Rafael): Implement.
        fprintf(stdout, "ERROR: No support for your current shell. Do it on your own.\n");
    } else if (strstr(shell, "/csh") != NULL || strstr(shell, "/tcsh") != NULL) {
        err = system("set history = 500");
    } else {
        fprintf(stdout, "ERROR: No support for your current shell. Do it on your own.\n");
    }

enable_history_epilogue:

    return err;
}

static int disable_history(void) {
    int err = 1;
    char *shell = getenv("SHELL");

    if (shell == NULL) {
        fprintf(stdout, "ERROR: Unable to find out your current shell.\n");
        goto disable_history_epilogue;
    }

    if (strstr(shell, "/bash") != NULL) {
        err = system("set +o history");
    } else if (strstr(shell, "/sh") != NULL) {
        err = system("export HISTSIZE=0");
    } else if (strstr(shell, "/ksh") != NULL) {
        // TODO(Rafael): Implement.
        fprintf(stdout, "ERROR: No support for your current shell. Do it on your own.\n");
    } else if (strstr(shell, "/csh") != NULL || strstr(shell, "/tcsh") != NULL) {
        err = system("unset history");
    } else {
        fprintf(stdout, "ERROR: No support for your current shell. Do it on your own.\n");
    }

disable_history_epilogue:

    return err;
}

static int clear_history(void) {
    // TODO(Rafael): Try to implement it independent of the current user shell.
    return 1;
}

#endif

#undef BLACKCAT_DEVPATH
