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
#include <kbd/kbd.h>
#include <keychain/keychain.h>
#include <accacia.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#define BLACKCAT_NET_DB_HOME "BLACKCAT_NET_DB_HOME"
#define BLACKCAT_BCSCK_LIB_HOME "BLACKCAT_BCSCK_LIB_HOME"

static int add_rule(void);

static int run(void);

static int drop_rule(void);

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_net_commands)
    { "--add-rule",  add_rule  },
    { "--run",       run       },
    { "--drop-rule", drop_rule }
DECL_BLACKCAT_COMMAND_TABLE_END

DECL_BLACKCAT_COMMAND_TABLE_SIZE(g_blackcat_net_commands)

int blackcat_cmd_net(void) {
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

int blackcat_cmd_net_help(void) {
    fprintf(stdout, "use: blackcat net [--add-rule | --run]\n");
    return 0;
}

static int drop_rule(void) {
    char *rule_id, *db_path;
    int err = EINVAL;
    kryptos_u8_t *ndb_key = NULL;
    size_t ndb_key_size;

    BLACKCAT_GET_OPTION_OR_DIE(rule_id, "rule", drop_rule_epilogue);

    if ((db_path = blackcat_get_option("db-path", getenv(BLACKCAT_NET_DB_HOME))) == NULL) {
        fprintf(stderr, "ERROR: NULL net database path.\n");
        goto drop_rule_epilogue;
    }

    accacia_savecursorposition();

    fprintf(stdout, "Netdb key: ");
    if ((ndb_key = blackcat_getuserkey(&ndb_key_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL Netdb key.\n");
        fflush(stderr);
        err = EFAULT;
        goto drop_rule_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();
    fflush(stdout);

    if ((err = blackcat_netdb_load(db_path, 1)) == 0) {
        err = blackcat_netdb_drop(rule_id, ndb_key, ndb_key_size);
        blackcat_netdb_unload();
        if (err == ENOENT) {
            fprintf(stderr, "ERROR: Rule '%s' does not exist.\n", rule_id);
        } else if (err == EFAULT) {
            fprintf(stderr, "ERROR: Unable to access the netdb data. Check your netdb key.\n");
        }
    }

drop_rule_epilogue:

    if (ndb_key != NULL) {
        kryptos_freeseg(ndb_key, ndb_key_size);
        ndb_key = NULL;
        ndb_key_size = 0;
    }

    return err;
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
    } else {
        target = NULL;
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

    accacia_savecursorposition();

    fprintf(stdout, "Netdb key: ");
    if ((key = blackcat_getuserkey(&key_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL key.\n");
        goto add_rule_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();
    fflush(stdout);

    if (first_access) {
        accacia_savecursorposition();

        fprintf(stdout, "Confirm the netdb key: ");

        if ((cp_key = blackcat_getuserkey(&cp_key_size)) == NULL) {
            fprintf(stderr, "ERROR: NULL key.\n");
            goto add_rule_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        if (cp_key_size != key_size && memcmp(cp_key, key, cp_key_size) != 0) {
            fprintf(stderr, "ERROR: The keys do not match.\n");
            goto add_rule_epilogue;
        }

        kryptos_freeseg(cp_key, cp_key_size);
        cp_key = NULL;
        cp_key_size = 0;
    }

    if ((err = blackcat_netdb_load(db_path, 1)) == 0) {
        err = blackcat_netdb_add(rule_id, rule_type, hash, target, pchain, encoder, error, key, key_size);
        if (err != 0) {
            fprintf(stderr, "%s\n", error);
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
    char *rule, *db_path, *bcsck_lib_path, *xchg_port, *xchg_addr;
    char *temp = NULL;
    size_t temp_size, db_key_size, cmdline_size = 0;
    char cmdline[4096], *cp;
    int err = EINVAL;
    size_t a;

    BLACKCAT_GET_OPTION_OR_DIE(rule, "rule", run_epilogue);

    if ((bcsck_lib_path = blackcat_get_option("bcsck-lib-path", getenv(BLACKCAT_BCSCK_LIB_HOME))) == NULL) {
        fprintf(stderr, "ERROR: NULL bcsck library path.\n");
        goto run_epilogue;
    }

    if ((db_path = blackcat_get_option("db-path", getenv(BLACKCAT_NET_DB_HOME))) == NULL) {
        fprintf(stderr, "ERROR: NULL net database path.\n");
        goto run_epilogue;
    }

    a = 0;
    while ((temp = blackcat_get_argv(a++)) != NULL && *temp == '-' && *(temp + 1) == '-')
        ;

    if (temp == NULL) {
        fprintf(stderr, "ERROR: NULL command. There is nothing to run.\n");
        goto run_epilogue;
    }

    cmdline_size = sizeof(cmdline);

    if (cmdline_size < strlen(bcsck_lib_path) + strlen(db_path) + strlen(rule)) {
        fprintf(stderr, "ERROR: The command line is too long.\n");
        err = EFAULT;
        goto run_epilogue;
    }

    memset(cmdline, 0, cmdline_size);
    if (blackcat_get_bool_option("e2ee", 0) == 0) {
        sprintf(cmdline, "LD_PRELOAD=%s BCSCK_DBPATH=%s BCSCK_RULE=%s ",
                        bcsck_lib_path, db_path, rule);
    } else {
        xchg_addr = blackcat_get_option("xchg-addr", NULL);
        BLACKCAT_GET_OPTION_OR_DIE(xchg_port, "xchg-port", run_epilogue);
        if (blackcat_is_dec(xchg_port, strlen(xchg_port)) == 0) {
            fprintf(stderr, "ERROR: Invalid data supplied in xchg-port option. It must be a valid port number.\n");
            goto run_epilogue;
        }
        if (xchg_addr != NULL) {
            sprintf(cmdline, "LD_PRELOAD=%s BCSCK_E2EE=1 BCSCK_PORT=%s BCSCK_ADDR=%s "
                             "BCSCK_DBPATH=%s BCSCK_RULE=%s ", bcsck_lib_path, xchg_port, xchg_addr, db_path, rule);
        } else {
            sprintf(cmdline, "LD_PRELOAD=%s BCSCK_E2EE=1 BCSCK_PORT=%s "
                             "BCSCK_DBPATH=%s BCSCK_RULE=%s ", bcsck_lib_path, xchg_port, db_path, rule);
        }
    }
    cmdline_size -= strlen(cmdline);
    cp = &cmdline[0] + (sizeof(cmdline) - cmdline_size);

    do {
        temp_size = strlen(temp);
        if (temp_size + 1 < cmdline_size - 1) {
            memcpy(cp, temp, temp_size);
            *(cp + temp_size) = ' ';
            cmdline_size -= temp_size + 1;
            cp += temp_size + 1;
        }
    } while((temp = blackcat_get_argv(a++)) != NULL);

    err = system(cmdline);

run_epilogue:

    if (cmdline_size > 0) {
        memset(cmdline, 0, sizeof(cmdline));
        cmdline_size = 0;
    }

    return err;
}

#undef BLACKCAT_NET_DB_HOME
#undef BLACKCAT_BCSCK_LIB_HOME
