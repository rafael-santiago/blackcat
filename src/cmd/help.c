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
#include <cmd/token.h>
#include <cmd/man.h>
#include <cmd/count.h>
#if !defined(_WIN32)
# include <cmd/paranoid.h>
# include <cmd/lkm.h>
# include <cmd/net.h>
#endif
#include <cmd/did_you_mean.h>
#include <kryptos_random.h>
#include <accacia.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_helper)
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
#if defined(__unix__)
    BLACKCAT_COMMAND_TABLE_ENTRY(paranoid_help),
#endif
#if defined(__unix__) && !defined(__minix__) && !defined(__sun__)
    BLACKCAT_COMMAND_TABLE_ENTRY(net_help),
#endif
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
    BLACKCAT_COMMAND_TABLE_ENTRY(lkm_help),
#endif
    BLACKCAT_COMMAND_TABLE_ENTRY(setkey_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(undo_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(decoy_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(info_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(detach_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(attach_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(untouch_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(config_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(do_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(token_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(man_help),
    BLACKCAT_COMMAND_TABLE_ENTRY(count_help)
DECL_BLACKCAT_COMMAND_TABLE_END

static DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper)

static char g_bcat_banner_v0[] = {
    "                          ;\n"
    "                        MW\n"
    "                     MM0MMMMMZ\n"
    "                     aMMMMMMMMMMM\n"
    "                     .MMMMMMMMMMMM\n"
    "                      MMMMMMMMMMB\n"
    "                      .MMMMMMMM\n"
    "                       MMMMMMMM\n"
    "                       MMMMMMMMM\n"
    "                      MMMMMMMMMMM\n"
    "                     8MMMMMMMMMMM:\n"
    "                   XMMMMMMMMMMMMMM\n"
    "                 MMMMMMMMMMMMMMMMM\n"
    "               MMMMMMMMMMMMMMMMMMM\n"
    "              MMMMMMMMMMMMMMMMMMMS\n"
    "             MMMMMMMMMMMMMMMMMMMM\n"
    "             MMMMMMMMMMMMMMMMMMMM\n"
    "            2MMMMMMMMMMMMMMMMMMMM\n"
    "            MMMMMMMMMMMMMMMMMMMMM\n"
    "            MMMMMMMMMMMMMMMMMMMMM7\n"
    "           MMMMMMMMMMMMMMMMMM MMMM\n"
    "           MMMMMMMMMMMMMMMMMM  MMM\n"
    "           MMMMMMMMMMMMMMMMMMM  MMM\n"
    "           MMMMMMMMMMMMMMMMMMM  ;MMM\n"
    "          8MMMMMMMMMMMMMMMMMMM2  MMM0\n"
    "         iMMMMMMMMMMMMMMMMMMMMM   MMMMM"
};

static char g_bcat_banner_v1[] = {
    "                                  @2\n"
    "                                 MMM\n"
    "                             aMMMMMM\n"
    "                           ZMMMMMMMMM0\n"
    "                          @MMMMMMMMMMMM\n"
    "                         rMMMMMMMMMMMMM\n"
    "                        MMMMMMMMMMMMMMMM\n"
    "                    XMMMMMMMMMMMMMMMMMM\n"
    "                @MMMMMMMMMMMMMMMMMM\n"
    "              MMMMMMMMMMMMMMMMMMMMM\n"
    "            ZMMMMMMMMMMMMMMMMMMMMMM\n"
    "           :MMMMMMMMMMMMMMMMMMMMM0\n"
    "          0MMMMMMMMMMMMMMMMMMMMM\n"
    "         MMMMMMMMMMMMMMMMMMMMMM\n"
    "        MMMMMMMMMMMMMMMMMMMMM\n"
    "       MMMMMMMMMMMMMMMMMMM;\n"
    "       MMMMMMMMMMMMMMMMMMM\n"
    "       MMMMMMMMMMMMMMMMMMM\n"
    "       MMMMMMMMMMMMMMMMMMM\n"
    "       MMMMMMMMMMMMMMMMMMM\n"
    "       MMMMMMMMMMMMMMMMMM8\n"
    "       MMMMMMMMMMMMMMMMMM                i,\n"
    "       MMMMMMMMMMMMMMM MM               MMMM\n"
    "      MMMMMMMMMMMMMMB  MM i             MMM0\n"
    "     rMMMMMMMMMMMMMMMMrMMMMM           MMMM\n"
    "      MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMX"
};

static char g_bcat_banner_v2[] = {
    "                  78MMMMM0i\n"
    "    ,SSS      aMMMMMMMMMMMMMMM\n"
    "  MMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"
    " MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"
    " MMMMZ  ,MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"
    " MMMM     MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMS\n"
    "  MMMM    MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"
    "   MMMMM  MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"
    "    0MMMMr MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"
    "      BMMM,XMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM2\n"
    "        MM  MMMMMMMMM MMMMMMMMMMMMMM      i\n"
    "           7MMMMMMMM:  ;MMMMMMMMMMM\n"
    "           MMMMMMMMZ    MMMMMMMMMM0\n"
    "           MMMMMMMM     .MMMMMMMMM\n"
    "           MMMMMMMM      MMMM MMMM@\n"
    "           MMM MMMM     ,MMMM ZMMMM\n"
    "          8MMMi MMMM     MMMW   MMMM:\n"
    "           0MMMMaMMMMM:  MMMM    MMMMMr;\n"
    "                 :MMMMM  :MMMMMr  MMMMMMM"
};

static char g_bcat_banner_v3[] = {
    "          ;WBZ;\n"
    "         MM7SMMMM\n"
    "        MM\n"
    "        MZ\n"
    "       MM\n"
    "       MM\n"
    "      MMM\n"
    "      MMM\n"
    "     aMMMMM:\n"
    "     MMMMMMMMM;\n"
    "    MMMMMMMMMMMMa\n"
    "    MMMMMMMMMMMMMMr\n"
    "    MMMMMMMMMMMMMMMM.         ,Z\n"
    "     MMMMMMMMMMMMMMMMM0     SMMM\n"
    "      MMMMMMMMMMMMMMMMMMMMMMMMMMMMX\n"
    "       MMMMMMMMMMMMMMMMMMMMMMMMMMMM\n"
    "       MMMMMMMMMMMMMMMMMMMMMMMMMMMM,\n"
    "       MMMMMMMMMMMMMMMMMMMMMMMMMMW.\n"
    "        MM   MMMWMMMMMMMMMMMMMMMMMMMMMM;\n"
    "         MMM2         ;7Xri2WMMMMMMMMMMMMMM\n"
    "           iM                           SMMM"
};

static char g_bcat_banner_v4[] = {
    "  M\n"
    ",MMMM\n"
    " MMMM\n"
    "  MMMM\n"
    "   MMMr\n"
    "   aMMM:\n"
    "   ;MMMM          ;Z\n"
    "    MMMMM      iZ:MM MM\n"
    "    MMMMMM  MMMMMMMMMM.\n"
    "    0MMMMMM MMMMMMMMMM\n"
    "     MMMMMMMMMMMMMMMMMr\n"
    "      MMMMMMMMMMMMMMMM\n"
    "      7MMMMMMMMMMMMMMS\n"
    "       0MMMMMMMMMMMMM\n"
    "        ;MMMMMMMMMMMM\n"
    "         MMMMMMMMMMMZ\n"
    "        MMMMMMMMMMMMM\n"
    "        MMMMMMMMMMMMMMM\n"
    "        iMMMMMMMMMMMMMMMB\n"
    "         MMMMMMMMMMMMMMMMM.\n"
    "          MMMMMMMMMMMMMMMMMM\n"
    "          MMMMMMMMMMMMMMMMMMM\n"
    "         XMMMMMMMMMMMMMMMMMMMM\n"
    "         WMMMMMMMMMMMMMMMMMMMMM\n"
    "         MMMMMMMMMMMMMMMMMMMMMMM\n"
    "         MMMMMMMMMMMMMMMMMMMMMMM:\n"
    "         MMMMMMMMMMMMMMMMMMMMMMMM\n"
    "         MMMMMMMMMMMMMMMMMMMMMMMM\n"
    "         MMM MMMMMMMMMMMMMMMMMMMM\n"
    "         MMM   :MMMMMMMMMMMMMMMM\n"
    "       XMMMM MMMMMMMMMMMMMMMMMMi\n"
    "       ZMMM      XMWZZZZZZZZX,"
};

static char g_bcat_banner_v5[] = {
    "                                 W\n"
    "                               @MMMZ\n"
    "                               MMMMi\n"
    "                              SMMM\n"
    "                              MMM\n"
    "                             MMMM\n"
    "                 M          MMMM0\n"
    "             0M rM Z7      MMMMM,\n"
    "              MMMMMMMMMM  MMMMMM\n"
    "              MMMMMMMMMM MMMMMMM\n"
    "              MMMMMMMMMMMMMMMMM\n"
    "              MMMMMMMMMMMMMMMM;\n"
    "               MMMMMMMMMMMMMMW\n"
    "               MMMMMMMMMMMMMM\n"
    "               MMMMMMMMMMMMZ\n"
    "               ,MMMMMMMMMMMr\n"
    "               MMMMMMMMMMMMM\n"
    "             MMMMMMMMMMMMMMM\n"
    "           2MMMMMMMMMMMMMMMZ\n"
    "          MMMMMMMMMMMMMMMMM\n"
    "        2MMMMMMMMMMMMMMMMM:\n"
    "       MMMMMMMMMMMMMMMMMMMS\n"
    "      MMMMMMMMMMMMMMMMMMMMM\n"
    "     MMMMMMMMMMMMMMMMMMMMMM\n"
    "    MMMMMMMMMMMMMMMMMMMMMMM\n"
    "    MMMMMMMMMMMMMMMMMMMMMMM\n"
    "   MMMMMMMMMMMMMMMMMMMMMMMM\n"
    "   MMMMMMMMMMMMMMMMMMMMMMMM\n"
    "   MMMMMMMMMMMMMMMMMMMM,MMM\n"
    "    MMMMMMMMMMMMMMMMX   2MM\n"
    "     MMMMMMMMMMMMMMMMMM MMMMZ\n"
    "      .XaZZZZZZZBMS      @MMM"
};

static char *g_bcat_banner[] = {
    g_bcat_banner_v0, g_bcat_banner_v1,
    g_bcat_banner_v2, g_bcat_banner_v3,
    g_bcat_banner_v4, g_bcat_banner_v5
};

static size_t g_bcat_banner_nr = sizeof(g_bcat_banner) / sizeof(g_bcat_banner[0]);

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

        snprintf(temp, sizeof(temp) - 1, "%s_help", topic);

        for (h = 0; h < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_helper) && exit_code == EINVAL; h++) {
            if (strcmp(GET_BLACKCAT_COMMAND_NAME(g_blackcat_helper, h), temp) == 0) {
                exit_code = GET_BLACKCAT_COMMAND_TEXT(g_blackcat_helper, h)();
            }
        }

        if (exit_code != 0) {
            fprintf(stderr, "No help entry for '%s'.\n", topic);
            did_you_mean(topic, 2);
            goto blackcat_cmd_help_epilogue;
        }

        topic = blackcat_get_argv(a++);
    } while (topic != NULL);

blackcat_cmd_help_epilogue:

    return exit_code;
}

int blackcat_cmd_help_help(void) {
    accacia_textstyle(AC_TSTYLE_BOLD);
    accacia_textcolor(AC_TCOLOR_BLACK);
    fprintf(stdout, "%s b l a c k c a t  ", g_bcat_banner[kryptos_get_random_byte() % g_bcat_banner_nr]);
    accacia_screennormalize();
    fprintf(stdout,  "is Copyright (C) 2004-2019 by Rafael Santiago.\n\n"
           "Bug reports, feedback, etc: <voidbrainvoid@tutanota.com> or "
           "<https://github.com/rafael-santiago/blackcat/issues>\n"
           "_____\nusage: blackcat <command> [options]\n\n"
           "*** If you want to know more about some command you should try: \"blackcat help <command>\".\n"
           "    Do not you know any command name? Welcome newbie! It is time to read some documentation.\n"
           "    Give it a try by running 'blackcat man'.\n"
            );
    return 0;
}
