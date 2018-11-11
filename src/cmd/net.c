/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/net.h>
#include <cmd/defs.h>
#include <cmd/options.h>
#include <net/db/db.h>
#include <kryptos_memory.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#define BLACKCAT_NET_DB_HOME "BLACKCAT_NET_DB_HOME"

static int add_rule(void);

static int run(void);

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_net_commands)
    { "--add-rule", add_rule },
    { "--run",      run      }
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_net_commands)

int blackcat_net_cmd(void) {
    char *sub_command;
    size_t c;
    int (*cmd_text)(void);

    sub_command = blackcat_get_argv(0);

    if (sub_command == NULL) {
        fprintf(stdout, "ERROR: no command was informed.\n");
        return EINVAL;
    }

    cmd_text = NULL;

    for (c = 0; cmd_text == NULL && c < GET_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_net_commands); c++) {
        if (strcmp(sub_command, GET_BLACKCAT_COMMAND_NAME(g_blackcat_net_commands, c)) == 0) {
            cmd_text = GET_BLACKCAT_COMMAND_TEXT(g_blackcat_net_commands, c);
        }
    }


    return (cmd_text != NULL) ? cmd_text() : EINVAL;
}

int blackcat_net_cmd_help(void) {
    fprintf(stdout, "use: blackcat net [--add-rule | --run]\n");
    return 0;
}

static int add_rule(void) {
    char *rule_id, *rule_type, *hash, *target, *pchain, *encoder, *db_path;
    char error[1024];
    kryptos_u8_t *key = NULL, *cp_key = NULL;
    size_t key_size, cp_key_size;
    int err = EINVAL;
    struct stat st;
    int first_access;

    BLACKCAT_GET_OPTION_OR_DIE(rule_id, "rule", add_rule_epilogue);

    BLACKCAT_GET_OPTION_OR_DIE(rule_type, "type", add_rule_epilogue);

    BLACKCAT_GET_OPTION_OR_DIE(hash, "hash", add_rule_epilogue);

    if (strcmp(rule_type, "socket") != 0) {
        BLACKCAT_GET_OPTION_OR_DIE(target, "target", add_rule_epilogue);
    }

    BLACKCAT_GET_OPTION_OR_DIE(pchain, "protection-layer", add_rule_epilogue);

    encoder = blackcat_get_option("encoder", NULL);

    if ((db_path = blackcat_get_option("db-path", getenv(BLACKCAT_NET_DB_HOME))) == NULL) {
        fprintf(stderr, "ERROR: NULL net database path.\n");
        goto add_rule_epilogue;
    }

    if (strcmp(rule_type, "socket") != 0) {
        fprintf(stderr, "ERROR: Not implemented.\n");
        err = ENOTSUP;
        goto add_rule_epilogue;
    }

    first_access = (stat(db_path, &st) == -1);

    fprintf(stdout, "Netdb key: ");
    if ((key = blackcat_getuserkey(&key_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL key.\n");
        goto add_rule_epilogue;
    }

    if (first_access) {
        fprintf(stdout, "Confirm the netdb key: ");

        if ((cp_key = blackcat_getuserkey(&cp_key_size)) == NULL) {
            fprintf(stderr, "ERROR: NULL key.\n");
            goto add_rule_epilogue;
        }

        if (cp_key_size != key_size && memcmp(cp_key, key, cp_key_size) != 0) {
            fprintf(stderr, "ERROR: The keys do not match.\n");
            goto add_rule_epilogue;
        }

        kryptos_freeseg(cp_key, cp_key_size);
        cp_key = NULL;
        cp_key_size = 0;
    }

    if ((err = blackcat_netdb_load(db_path)) == 0) {
        err = blackcat_netdb_add(rule_id, rule_type, hash, target, pchain, encoder, error, key, key_size);
        if (err != 0) {
            fprintf(stderr, "%s\n", err);
        }
        blackcat_netdb_unload();
    }

add_rule_epilogue:

    if (key != NULL) {
        kryptos_freeseg(key, key_size);
        key = NULL;
        key_size = 0;
    }

    if (cp_key != NULL) {
        kryptos_freeseg(cp_key, cp_key_size);
        cp_key = NULL;
        cp_key_size = 0;
    }

    return err;
}

static int run(void) {
    return 0;
}
