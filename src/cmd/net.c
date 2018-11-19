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
#include <net/ctx/ctx.h>
#include <kryptos.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#define BLACKCAT_NET_DB_HOME "BLACKCAT_NET_DB_HOME"
#define BLACKCAT_BCSCK_LIB_HOME "BLACKCAT_BCSCK_LIB_HOME"

static int add_rule(void);

static int run(void);

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_net_commands)
    { "--add-rule", add_rule },
    { "--run",      run      }
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

    fprintf(stdout, "Netdb key: ");
    if ((key = blackcat_getuserkey(&key_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL key.\n");
        goto add_rule_epilogue;
    }

    if (first_access) {
        fprintf(stdout, "\nConfirm the netdb key: ");

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
    char *rule, *db_path, *bcsck_lib_path;
    kryptos_u8_t *key = NULL, *temp = NULL, *db_key = NULL, *enc_key = NULL, *enc_db_key = NULL;
    size_t key_size, temp_size, db_key_size, cmdline_size = 0, enc_key_size, enc_db_key_size;
    char cmdline[4096], *cp;
    int err = EINVAL;
    bnt_channel_rule_ctx *rule_entry = NULL;
    size_t a;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    BLACKCAT_GET_OPTION_OR_DIE(rule, "rule", run_epilogue);

    if ((bcsck_lib_path = blackcat_get_option("bcsck-lib-path", getenv(BLACKCAT_BCSCK_LIB_HOME))) == NULL) {
        fprintf(stderr, "ERROR: NULL bcsck library path.\n");
        goto run_epilogue;
    }

    if ((db_path = blackcat_get_option("db-path", getenv(BLACKCAT_NET_DB_HOME))) == NULL) {
        fprintf(stderr, "ERROR: NULL net database path.\n");
        goto run_epilogue;
    }

    fprintf(stdout, "Netdb key: ");
    if ((db_key = blackcat_getuserkey(&db_key_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL key.\n");
        goto run_epilogue;
    }

    if ((err = blackcat_netdb_load(db_path)) == 0) {
        if ((temp = (kryptos_u8_t *) kryptos_newseg(8)) == NULL) {
            err = ENOMEM;
            fprintf(stderr, "ERROR: Not enough memory.\n");
            goto run_epilogue;
        }
        temp_size = 8;
        rule_entry = blackcat_netdb_select(rule, db_key, db_key_size, &temp, &temp_size);
        if (rule_entry == NULL) {
            err = ENOENT;
            fprintf(stderr, "ERROR: The rule '%s' seems not exist.\n", rule);
            goto run_epilogue;
        }
        del_bnt_channel_rule_ctx(rule_entry);
        rule_entry = NULL;
    }

    fprintf(stdout, "\nEnter with the session key: ");
    if ((key = blackcat_getuserkey(&key_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL key.\n");
        goto run_epilogue;
    }

    fprintf(stdout, "\nConfirm the session key: ");
    if ((temp = blackcat_getuserkey(&temp_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL key.\n");
        goto run_epilogue;
    }

    if (key_size != temp_size || memcmp(key, temp, key_size) != 0) {
        fprintf(stderr, "ERROR: The session key does not match with its confirmation.\n");
        goto run_epilogue;
    }

    kryptos_freeseg(temp, temp_size);
    temp = NULL;
    temp_size = 0;

    a = 0;
    while ((temp = blackcat_get_argv(a++)) != NULL && *temp == '-' && *(temp + 1) == '-')
        ;

    if (temp == NULL) {
        fprintf(stderr, "ERROR: NULL command. There is nothing to run.\n");
        goto run_epilogue;
    }

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, key, key_size);

    if (!kryptos_last_task_succeed(ktask)) {
        err = EFAULT;
        goto run_epilogue;
    }

    enc_key = ktask->out;
    enc_key_size = ktask->out_size;
    ktask->out = NULL;
    ktask->out_size = 0;

    if (key != NULL) {
        kryptos_freeseg(key, key_size);
        key = NULL;
        key_size = 0;
    }

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, db_key, db_key_size);

    if (!kryptos_last_task_succeed(ktask)) {
        err = EFAULT;
        goto run_epilogue;
    }

    enc_db_key = ktask->out;
    enc_db_key_size = ktask->out_size;
    ktask->out = NULL;
    ktask->out_size = 0;

    if (db_key != NULL) {
        kryptos_freeseg(db_key, db_key_size);
        db_key = NULL;
        db_key_size = 0;
    }

    cmdline_size = sizeof(cmdline);

    if (cmdline_size < strlen(bcsck_lib_path) + strlen(db_path) + enc_db_key_size + enc_key_size + strlen(rule)) {
        fprintf(stderr, "ERROR: The command line is too long.\n");
        err = EFAULT;
        goto run_epilogue;
    }

    memset(cmdline, 0, cmdline_size);
    sprintf(cmdline, "LD_PRELOAD=%s BCSCK_DBPATH=%s BCSCK_DBKEY=%s BCSCK_SKEY=%s BCSCK_RULE=%s ",
                    bcsck_lib_path, db_path, enc_db_key, enc_key, rule);
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

    if (enc_key != NULL) {
        kryptos_freeseg(enc_key, enc_key_size);
        enc_key = NULL;
        enc_key_size = 0;
    }

    if (enc_db_key != NULL) {
        kryptos_freeseg(enc_db_key, enc_db_key_size);
        enc_db_key = NULL;
        enc_db_key_size = 0;
    }

    err = 0;
    system(cmdline);

run_epilogue:

    if (key != NULL) {
        kryptos_freeseg(key, key_size);
        key = NULL;
        key_size = 0;
    }

    if (rule_entry != NULL) {
        del_bnt_channel_rule_ctx(rule_entry);
        rule_entry = NULL;
    }

    if (db_key != NULL) {
        kryptos_freeseg(db_key, db_key_size);
        db_key = NULL;
        db_key_size = 0;
    }

    if (enc_key != NULL) {
        kryptos_freeseg(enc_key, enc_key_size);
        enc_key = NULL;
        enc_key_size = 0;
    }

    if (db_key != NULL) {
        kryptos_freeseg(db_key, db_key_size);
        db_key = NULL;
        db_key_size = 0;
    }

    if (temp != NULL) {
        kryptos_freeseg(temp, temp_size);
        temp = NULL;
        temp_size = 0;
    }

    if (cmdline_size > 0) {
        memset(cmdline, 0, sizeof(cmdline));
        cmdline_size = 0;
    }

    return err;
}

#undef BLACKCAT_NET_DB_HOME
#undef BLACKCAT_BCSCK_LIB_HOME
