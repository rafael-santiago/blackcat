/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/exec.h>
#include <cmd/defs.h>
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
#if !defined(_WIN32)
# include <cmd/lkm.h>
# include <cmd/paranoid.h>
# include <cmd/net.h>
#endif
#include <cmd/levenshtein_distance.h>
#if !defined(_WIN32)
# include <sys/mman.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

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
#if !defined(_WIN32)
    BLACKCAT_COMMAND_TABLE_ENTRY(lkm),
    BLACKCAT_COMMAND_TABLE_ENTRY(paranoid),
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
    BLACKCAT_COMMAND_TABLE_ENTRY(do)
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands)

static int did_you_mean(const char *user_command, const int max_distance);

int blackcat_exec(int argc, char **argv) {
    size_t c;
    const char *command = NULL;
    int err = EINVAL;

    blackcat_set_argc_argv(argc, argv);

#if !defined(_WIN32)
    if (blackcat_get_bool_option("no-swap", 0) == 1) {
        // WARN(Rafael): If the user suspend the machine this will be useless.
        if ((err = mlockall(MCL_CURRENT | MCL_FUTURE)) != 0) {
            perror("mlockall()");
            fprintf(stderr, "ERROR: While applying RAM locking.\n");
            return err;
        }
    }
#endif

    if (blackcat_get_bool_option("set-high-priority", 0) == 1) {
        // WARN(Rafael): Yes, it is a paranoid care. This only seeks to mitigate the preemption, there is no guarantee.
        //               In fact, the best case would be a real-time OS, but...
        if ((err = setpriority(PRIO_PROCESS, 0, -20)) == -1) {
            fprintf(stderr, "ERROR: While setting the process' priority as high.\n");
            return err;
        }
    }

    command = blackcat_get_command();

    if (command == NULL) {
        goto blackcat_exec_epilogue;
    }

    if (strcmp(command, "--version") == 0) {
        return blackcat_cmd_version();
    }

    for (c = 0; c < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands); c++) {
        if (strcmp(command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_commands, c)) == 0) {
            return GET_BLACKCAT_COMMAND_TEXT(g_blackcat_commands, c)();
        }
    }

blackcat_exec_epilogue:

    if (did_you_mean(command, 2) == 0) {
        // 'Eu num intindi o que ele falo...'
        fprintf(stderr, "ERROR: Invalid command.\n");
    }

    return err;
}

static int did_you_mean(const char *user_command, const int max_distance) {
    int distances[0xFF];
    size_t d;
    int has_some_suggestion = 0, s_nr;

    for (d = 0; d < sizeof(distances) / sizeof(distances[0]); d++) {
        distances[d] = -1;
    }

    for (d = 0; d < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands); d++) {
        distances[d] = levenshtein_distance(user_command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_commands, d));
        has_some_suggestion |= (distances[d] >= 1 && distances[d] <= max_distance);
    }

    if (has_some_suggestion) {
        s_nr = 0;
        fprintf(stderr, "ERROR: Did you mean ");
        for (d = 0; d < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands); d++) {
            if (distances[d] >= 1 && distances[d] <= max_distance) {
                if (s_nr > 0) {
                    fprintf(stderr, "%s ", ((d + 1) == GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_commands)) ? " or" : ",");
                }
                fprintf(stderr, "'%s'", GET_BLACKCAT_COMMAND_NAME(g_blackcat_commands, d));
                s_nr++;
            }
        }
        fprintf(stderr, "?\n");
    }

    return has_some_suggestion;
}
