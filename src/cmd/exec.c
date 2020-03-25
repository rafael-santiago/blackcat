/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/exec.h>
#include <cmd/options.h>
#include <cmd/help.h>
#include <cmd/version.h>
#include <cmd/init.h>
#include <cmd/deinit.h>
#include <cmd/add.h>
#include <cmd/rm.h>
#include <cmd/lock.h>
#include <cmd/unlock.h>
#include <cmd/status.h>
#include <cmd/show.h>
#include <cmd/pack.h>
#include <cmd/unpack.h>
#include <cmd/setkey.h>
#include <cmd/undo.h>
#include <cmd/decoy.h>
#include <cmd/info.h>
#include <cmd/detach.h>
#include <cmd/attach.h>
#include <cmd/untouch.h>
#include <cmd/config.h>
#include <cmd/do.h>
#include <cmd/token.h>
#include <cmd/man.h>
#include <cmd/count.h>
#include <fs/bcrepo/bcrepo.h>
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
# include <cmd/lkm.h>
#endif
#if defined(__unix__)
# include <cmd/paranoid.h>
#endif
#if defined(__unix__) && !defined(__minix__) && !defined(__sun__)
# include <cmd/net.h>
#endif
#include <cmd/did_you_mean.h>
#if defined(_WIN32)
# include <kryptos_memory.h>
#endif
#if defined(__unix__)
# include <sys/mman.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#if defined(__unix__)
# include <sys/resource.h>
#endif
#if defined(_WIN32)
# include <windows.h>
#endif

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_commands)
    BLACKCAT_COMMAND_TABLE_ENTRY(help),
    BLACKCAT_COMMAND_TABLE_ENTRY(version),
    BLACKCAT_COMMAND_TABLE_ENTRY(init),
    BLACKCAT_COMMAND_TABLE_ENTRY(deinit),
    BLACKCAT_COMMAND_TABLE_ENTRY(add),
    BLACKCAT_COMMAND_TABLE_ENTRY(rm),
    BLACKCAT_COMMAND_TABLE_ENTRY(lock),
    BLACKCAT_COMMAND_TABLE_ENTRY(unlock),
    BLACKCAT_COMMAND_TABLE_ENTRY(status),
    BLACKCAT_COMMAND_TABLE_ENTRY(show),
    BLACKCAT_COMMAND_TABLE_ENTRY(pack),
    BLACKCAT_COMMAND_TABLE_ENTRY(unpack),
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
    BLACKCAT_COMMAND_TABLE_ENTRY(lkm),
#endif
#if defined(__unix__)
    BLACKCAT_COMMAND_TABLE_ENTRY(paranoid),
#endif
#if defined(__unix__) && !defined(__minix__) && !defined(__sun__)
    BLACKCAT_COMMAND_TABLE_ENTRY(net),
#endif
    BLACKCAT_COMMAND_TABLE_ENTRY(setkey),
    BLACKCAT_COMMAND_TABLE_ENTRY(undo),
    BLACKCAT_COMMAND_TABLE_ENTRY(decoy),
    BLACKCAT_COMMAND_TABLE_ENTRY(info),
    BLACKCAT_COMMAND_TABLE_ENTRY(detach),
    BLACKCAT_COMMAND_TABLE_ENTRY(attach),
    BLACKCAT_COMMAND_TABLE_ENTRY(untouch),
    BLACKCAT_COMMAND_TABLE_ENTRY(config),
    BLACKCAT_COMMAND_TABLE_ENTRY(do),
    BLACKCAT_COMMAND_TABLE_ENTRY(token),
    BLACKCAT_COMMAND_TABLE_ENTRY(man),
    BLACKCAT_COMMAND_TABLE_ENTRY(count)
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands)

int blackcat_exec(int argc, char **argv) {
    size_t c;
    const char *command = NULL;
    int err = EINVAL;

    blackcat_set_argc_argv(argc, argv);

#if defined(__unix__) && !defined(__minix__)
    if (blackcat_get_bool_option("no-swap", 0) == 1) {
        // WARN(Rafael): If the user suspend her/his machine this will be useless.
        if ((err = mlockall(MCL_CURRENT | MCL_FUTURE)) != 0) {
            perror("mlockall()");
            fprintf(stderr, "ERROR: While applying RAM locking.\n");
            return err;
        }
    }
#elif defined(_WIN32)
    if (blackcat_get_bool_option("no-swap", 0) == 1) {
        // WARN(Rafael): If the user suspend his/her machine all RAM will be flushed to disk,
        //               making this effort of not swapping useless.

        // INFO(Rafael): Since all relevant memory allocation is done by using kryptos_newseg()
        //               the produced effect will be similar (at least its intention) to Unix
        //               mlockall().
        kryptos_avoid_ram_swap();
    }
#else
    if (blackcat_get_bool_option("no-swap", 0) == 1) {
        fprintf(stderr, "ERROR: The option '--no-swap' is not supported in this platform.\n");
        return ENOSYS;
    }
#endif

    if (blackcat_get_bool_option("set-high-priority", 0) == 1) {
        // WARN(Rafael): Yes, it is a paranoid care. This only seeks to mitigate the preemption, there is no guarantee.
        //               In fact, the best case would be a real-time OS, but...
#if defined(__unix__)
        if ((err = setpriority(PRIO_PROCESS, 0, -20)) == -1) {
            fprintf(stderr, "ERROR: While setting the process priority as high.\n");
            return err;
        }
#elif defined(_WIN32)
        if (SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS) == 0) {
            // WARN(Rafael): Until now I am not considering to use REALTIME_PRIORITY_CLASS.
            //               We just want to the job done as fast as possible, not break all the Windows! \:p
            //               Less time running less possibility of kernel screwing something up related to blackcat instance,
            //               by preempting it.
            fprintf(stderr, "ERROR: While setting the process priority as high.\n");
            return GetLastError();
        }
#else
        fprintf(stderr, "ERROR: The option '--set-high-priority' is not supported.\n"); // WARN(Rafael): Poor girl, poor boy!
        return ENOSYS;
#endif
    }

    command = blackcat_get_command();

    if (command == NULL) {
        goto blackcat_exec_epilogue;
    }

    if (strcmp(command, "--version") == 0) {
        return blackcat_cmd_version();
    }

    if (strcmp(command, "--metadata-version") == 0) {
        fprintf(stdout, "bcrepo-metadata-v%s\n", bcrepo_metadata_version());
        return 0;
    }

    for (c = 0; c < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands); c++) {
        if (strcmp(command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_commands, c)) == 0) {
            return GET_BLACKCAT_COMMAND_TEXT(g_blackcat_commands, c)();
        }
    }

blackcat_exec_epilogue:

    fprintf(stderr, "ERROR: ");

    if (did_you_mean(command, 2) == 0) {
        // 'Eu num intindi o que ele falo...'
        fprintf(stderr, "Invalid command.\n");
    }

    return err;
}
