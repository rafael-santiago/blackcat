/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/help.h>
#include <cmd/defs.h>
#include <cmd/options.h>
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
# include <cmd/paranoid.h>
# include <cmd/lkm.h>
# include <cmd/net.h>
#endif
#include <string.h>
#include <stdio.h>
#include <errno.h>

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_helper)
    BLACKCAT_COMMAND_TABLE_ENTRY(help_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(init_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(deinit_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(add_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(rm_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(lock_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(unlock_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(status_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(show_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(pack_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(unpack_help),
#if !defined(_WIN32)
    BLACKCAT_COMMAND_TABLE_ENTRY(paranoid_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(lkm_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(net_help),
#endif
    BLACKCAT_COMMAND_TABLE_ENTRY(setkey_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(undo_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(decoy_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(info_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(detach_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(attach_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(untouch_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(config_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(do_help)
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper)

int blackcat_cmd_help(void) {
    size_t h;
    char *topic, temp[100];
    int exit_code;
    int a;

    topic = blackcat_get_argv(0);

    if (topic == NULL) {
        exit_code = EINVAL;
        blackcat_cmd_help_help();
        goto blackcat_cmd_help_epilogue;
    }

    a = 1;

    do {
        exit_code = EINVAL;

        if (strlen(topic) > sizeof(temp) - 20) {
            fprintf(stderr, "Too long option. No SIGSEGVs for today. Goodbye!\n");
            goto blackcat_cmd_help_epilogue;
        }

        sprintf(temp, "%s_help", topic);

        for (h = 0; h < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper) && exit_code == EINVAL; h++) {
            if (strcmp(GET_BLACKCAT_COMMAND_NAME(g_blackcat_helper, h), temp) == 0) {
                exit_code = GET_BLACKCAT_COMMAND_TEXT(g_blackcat_helper, h)();
            }
        }

        if (exit_code != 0) {
            fprintf(stderr, "No help entry for '%s'.\n", topic);
            goto blackcat_cmd_help_epilogue;
        }

        topic = blackcat_get_argv(a++);
    } while (topic != NULL);

blackcat_cmd_help_epilogue:

    return exit_code;
}

int blackcat_cmd_help_help(void) {
    fprintf(stdout, "usage: blackcat <command> [options]\n\n"
           "*** If you want to know more about some command you should try: \"blackcat help <command>\".\n"
           "    Do not you know any command name? Welcome newbie! It is time to read some documentation: "
           "\"man blackcat\".\n________\n"
           "blackcat is Copyright (C) 2004-2019 by Rafael Santiago.\n\n"
           "Bug reports, feedback, etc: <voidbrainvoid@tutanota.com> or "
           "<https://github.com/rafael-santiago/blackcat/issues>\n");
    return 0;
}
