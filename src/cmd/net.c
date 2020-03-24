/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#if defined(__unix__) && !defined(__minix__) && !defined(__sun__)
// WARN(Rafael): Until now I could not be able to actually do a decent system test on Minix, due to the lack of a good sniffer,
//               for this reason I have chosen make net command unavailable on Minix. If it cannot be tested it must not be
//               used. But if you want to use it anyway, all you should do is just removing '!defined(__minix__)' and
//               crossing your fingers.
//
// WARN(Rafael): The same on Solaris.
//

#include <cmd/net.h>
#include <cmd/defs.h>
#include <cmd/options.h>
#include <net/db/db.h>
#include <kbd/kbd.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/keychain.h>
#include <net/dh/dh.h>
#include <kryptos.h>
#include <accacia.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>

#define BLACKCAT_NET_DB_HOME "BLACKCAT_NET_DB_HOME"
#define BLACKCAT_BCSCK_LIB_HOME "BLACKCAT_BCSCK_LIB_HOME"

static int add_rule(void);

static int run(void);

static int drop_rule(void);

static int mk_dh_params(void);

static int mk_dh_key_pair(void);

static int skey_xchg(void);

static void skey_print(const kryptos_u8_t *skey, const size_t skey_size);

DECL_BLACKCAT_COMMAND_TABLE(g_blackcat_net_commands)
    { "--add-rule",       add_rule       },
    { "--run",            run            },
    { "--drop-rule",      drop_rule      },
    { "--mk-dh-params",   mk_dh_params   },
    { "--mk-dh-key-pair", mk_dh_key_pair },
    { "--skey-xchg",      skey_xchg      }
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

    if (cmd_text == NULL) {
        fprintf(stderr, "ERROR: What are intending to do?\n");
    }

    return (cmd_text != NULL) ? cmd_text() : EINVAL;
}

int blackcat_cmd_net_help(void) {
    fprintf(stdout, "use: blackcat net\n"
                    "              [--add-rule       |\n"
                    "               --run            |\n"
                    "               --drop-rule      |\n"
                    "               --mk-dh-params   |\n"
                    "               --mk-dh-key-pair |\n"
                    "               --skey-xchg      ]\n");
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

    if (is_pht(get_hash_processor(hash))) {
        fprintf(stderr, "ERROR: You cannot use '%s' here.\n", hash);
        goto add_rule_epilogue;
    }

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
    char *rule, *db_path, *bcsck_lib_path, *xchg_port, *xchg_addr = NULL, *kpriv = NULL, *kpub = NULL, *s_bits;
    char *temp = NULL;
    size_t temp_size, db_key_size, cmdline_size = 0;
    char cmdline[4096], *cp;
    int err = EINVAL;
    size_t a;
    struct stat st;

    BLACKCAT_GET_OPTION_OR_DIE(rule, "rule", run_epilogue);

    if ((bcsck_lib_path = blackcat_get_option("bcsck-lib-path", getenv(BLACKCAT_BCSCK_LIB_HOME))) == NULL) {
#if defined(__unix__)
        bcsck_lib_path = "/usr/lib/libbcsck.so";
        if (stat(bcsck_lib_path, &st) != 0) {
            fprintf(stderr, "ERROR: NULL bcsck library path.\n");
            goto run_epilogue;
        }
#else
        fprintf(stderr, "ERROR: NULL bcsck library path.\n");
        goto run_epilogue;
#endif
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

    if ((kpriv = blackcat_get_option("kpriv", NULL)) == NULL) {
        if ((kpub = blackcat_get_option("kpub", NULL)) != NULL) {
            BLACKCAT_GET_OPTION_OR_DIE(s_bits, "bits", run_epilogue);
        }
    }

    if (kpriv != NULL) {
        BLACKCAT_GET_OPTION_OR_DIE(xchg_addr, "xchg-addr", run_epilogue);
    }

    if (kpriv != NULL || kpub != NULL) {
        BLACKCAT_GET_OPTION_OR_DIE(xchg_port, "xchg-port", run_epilogue);

        if (blackcat_is_dec(xchg_port, strlen(xchg_port)) == 0) {
            fprintf(stderr, "ERROR: Invalid data supplied in xchg-port option. It must be a valid port number.\n");
            goto run_epilogue;
        }
    }

    memset(cmdline, 0, cmdline_size);
    if (blackcat_get_bool_option("e2ee", 0) == 0) {
        if (kpriv == NULL && kpub == NULL) {
            snprintf(cmdline, sizeof(cmdline) - 1, "LD_PRELOAD=%s BCSCK_DBPATH=%s BCSCK_RULE=%s ",
                            bcsck_lib_path, db_path, rule);
        } else {
            snprintf(cmdline, sizeof(cmdline) - 1,
                            "LD_PRELOAD=%s BCSCK_DBPATH=%s BCSCK_RULE=%s BCSCK_%s=%s BCSCK_PORT=%s BCSCK_ADDR=%s",
                            bcsck_lib_path, db_path, rule, (kpriv != NULL) ? "KPRIV" : "KPUB",
                                                           (kpriv != NULL) ? kpriv : kpub, xchg_port, xchg_addr);
        }
    } else {
#if defined(__NetBSD__)
        fprintf(stderr, "ERROR: No support for e2ee in NetBSD.\n");
        err = ENOSYS;
        goto run_epilogue;
#endif
        if (xchg_addr == NULL) {
            xchg_addr = blackcat_get_option("xchg-addr", NULL);
        }

        BLACKCAT_GET_OPTION_OR_DIE(xchg_port, "xchg-port", run_epilogue);

        if (blackcat_is_dec(xchg_port, strlen(xchg_port)) == 0) {
            fprintf(stderr, "ERROR: Invalid data supplied in xchg-port option. It must be a valid port number.\n");
            goto run_epilogue;
        }

        if (xchg_addr != NULL) {
            if (kpriv == NULL) {
                snprintf(cmdline, sizeof(cmdline) - 1, "LD_PRELOAD=%s BCSCK_E2EE=1 BCSCK_PORT=%s BCSCK_ADDR=%s "
                                 "BCSCK_DBPATH=%s BCSCK_RULE=%s ", bcsck_lib_path, xchg_port, xchg_addr, db_path, rule);
            } else {
                snprintf(cmdline, sizeof(cmdline) - 1, "LD_PRELOAD=%s BCSCK_E2EE=1 BCSCK_PORT=%s BCSCK_ADDR=%s "
                                 "BCSCK_DBPATH=%s BCSCK_RULE=%s BCSCK_KPRIV=%s ", bcsck_lib_path, xchg_port, xchg_addr,
                                                                                  db_path, rule, kpriv);
            }
        } else {
            if (kpub == NULL) {
                snprintf(cmdline, sizeof(cmdline) - 1, "LD_PRELOAD=%s BCSCK_E2EE=1 BCSCK_PORT=%s "
                                 "BCSCK_DBPATH=%s BCSCK_RULE=%s ", bcsck_lib_path, xchg_port, db_path, rule);
            } else {
                snprintf(cmdline, sizeof(cmdline) - 1, "LD_PRELOAD=%s BCSCK_E2EE=1 BCSCK_PORT=%s "
                                 "BCSCK_DBPATH=%s BCSCK_RULE=%s BCSCK_KPUB=%s BCSCK_S_BITS=%s ", bcsck_lib_path, xchg_port,
                                                                                                 db_path, rule, kpub, s_bits);
            }
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

static int mk_dh_params(void) {
    int err = EINVAL;
    size_t p_bits, q_bits;
    kryptos_u8_t *params = NULL;
    size_t params_size;
    char *out = NULL, *temp;
    FILE *fp = NULL;

    BLACKCAT_GET_OPTION_OR_DIE(out, "out", mk_dh_params_epilogue);

    BLACKCAT_GET_OPTION_OR_DIE(temp, "p-bits", mk_dh_params_epilogue);
    if (!blackcat_is_dec(temp, strlen(temp))) {
        fprintf(stderr, "ERROR: Invalid number in '--p-bits' option.\n");
        goto mk_dh_params_epilogue;
    }

    p_bits = strtoul(temp, NULL, 10);

    BLACKCAT_GET_OPTION_OR_DIE(temp, "q-bits", mk_dh_params_epilogue);
    if (!blackcat_is_dec(temp, strlen(temp))) {
        fprintf(stderr, "ERROR: Invalid number in '--q-bits' option.\n");
        goto mk_dh_params_epilogue;
    }

    q_bits = strtoul(temp, NULL, 10);

    if (kryptos_dh_mk_domain_params(p_bits, q_bits, &params, &params_size) != kKryptosSuccess) {
        fprintf(stderr, "ERROR: When generating DH parameters.\n");
        err = EFAULT;
        goto mk_dh_params_epilogue;
    }

    if ((fp = fopen(out, "w")) == NULL) {
        fprintf(stderr, "ERROR: Unable to write to '%s'.\n", out);
        err = EFAULT;
        goto mk_dh_params_epilogue;
    }

    if (fwrite(params, 1, params_size, fp) != params_size) {
        fprintf(stderr, "ERROR: When writing to the file '%s'.\n", out);
        fclose(fp);
        fp = NULL;
        remove(out);
        err = EFAULT;
        goto mk_dh_params_epilogue;
    }

    fclose(fp);
    fp = NULL;

    err = 0;

mk_dh_params_epilogue:

    if (params != NULL) {
        kryptos_freeseg(params, params_size);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    return err;
}

static int mk_dh_key_pair(void) {
    int err = EINVAL;
    int use_dh_group;
    char *group_bits, *temp, *k_pub_out, *k_priv_out;
    struct avail_groups {
        kryptos_dh_modp_group_bits_t bits_n;
        char *bits_s;
    };
    struct avail_groups *dh_group;
    static struct avail_groups dh_groups[] = {
        { kKryptosDHGroup1536, "1536" },
        { kKryptosDHGroup2048, "2048" },
        { kKryptosDHGroup3072, "3072" },
        { kKryptosDHGroup4096, "4096" },
        { kKryptosDHGroup6144, "6144" },
        { kKryptosDHGroup8192, "8192" }
    };
    static size_t dh_groups_nr = sizeof(dh_groups) / sizeof(dh_groups[0]), di;
    struct kryptos_dh_xchg_ctx dh_ctx, *dh = &dh_ctx;
    kryptos_u8_t *params = NULL;
    size_t params_size;
    FILE *fp = NULL;
    kryptos_u8_t *k_pub = NULL, *k_priv = NULL, *enc_k_priv = NULL;
    size_t k_pub_size, k_priv_size, enc_k_priv_size;
    kryptos_u8_t *kpriv_key[2];
    size_t kpriv_key_size[2];

    kpriv_key[0] = kpriv_key[1] = NULL;
    kpriv_key_size[0] = kpriv_key_size[1] = 0;

    kryptos_dh_init_xchg_ctx(dh);

    BLACKCAT_GET_OPTION_OR_DIE(k_pub_out, "public-key-out", mk_dh_key_pair_epilogue);

    BLACKCAT_GET_OPTION_OR_DIE(k_priv_out, "private-key-out", mk_dh_key_pair_epilogue);

    if ((use_dh_group = blackcat_get_bool_option("use-dh-group", 0)) == 1) {
        BLACKCAT_GET_OPTION_OR_DIE(group_bits, "group-bits", mk_dh_key_pair_epilogue);

        dh_group = NULL;
        for (di = 0; di < dh_groups_nr && dh_group == NULL; di++) {
            if (strcmp(dh_groups[di].bits_s, group_bits) == 0) {
                dh_group = &dh_groups[di];
            }
        }

        if (dh_group == NULL) {
            fprintf(stderr, "ERROR: Unsupported group-bits '%s'. Available are: '1536', '2048',"
                            " '3072', '4096', '6144' and '8192'.\n", group_bits);
            goto mk_dh_key_pair_epilogue;
        }

        if (kryptos_dh_get_modp(dh_group->bits_n, &dh->p, &dh->g) != kKryptosSuccess) {
            fprintf(stderr, "ERROR: During mod-p parameters loading.\n");
            goto mk_dh_key_pair_epilogue;
        }

    } else {
        BLACKCAT_GET_OPTION_OR_DIE(temp, "dh-params-in", mk_dh_key_pair_epilogue);

        if ((fp = fopen(temp, "r")) == NULL) {
            fprintf(stderr, "ERROR: Unable to read from file '%s'.\n", temp);
            err = EFAULT;
            goto mk_dh_key_pair_epilogue;
        }

        fseek(fp, 0L, SEEK_END);
        params_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        if ((params = (kryptos_u8_t *) kryptos_newseg(params_size)) == NULL) {
            fprintf(stderr, "ERROR: Not enough memory!\n");
            err = ENOMEM;
            goto mk_dh_key_pair_epilogue;
        }

        fread(params, 1, params_size, fp);
        fclose(fp);
        fp = NULL;

        if (kryptos_dh_get_modp_from_params_buf(params, params_size, &dh->p, NULL, &dh->g) != kKryptosSuccess) {
            fprintf(stderr, "ERROR: When getting DH parameters.\n");
            err = EFAULT;
            goto mk_dh_key_pair_epilogue;
        }
    }

    accacia_savecursorposition();
    fprintf(stdout, "Kpriv key: ");
    if ((kpriv_key[0] = blackcat_getuserkey(&kpriv_key_size[0])) == NULL) {
        fprintf(stderr, "ERROR: NULL Kpriv key.\n");
        fflush(stderr);
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();
    fflush(stdout);

    fprintf(stdout, "Re-type kpriv key: ");
    if ((kpriv_key[1] = blackcat_getuserkey(&kpriv_key_size[1])) == NULL) {
        fprintf(stderr, "ERROR: NULL Kpriv key confirmation.\n");
        fflush(stderr);
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();
    fflush(stdout);

    if (kpriv_key_size[0] != kpriv_key_size[1] || memcmp(kpriv_key[0], kpriv_key[1], kpriv_key_size[0]) != 0) {
        fprintf(stderr, "ERROR: The key does not match with its confirmation.\n");
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    kryptos_dh_mk_key_pair(&k_pub, &k_pub_size, &k_priv, &k_priv_size, &dh);

    if (!kryptos_last_task_succeed(dh)) {
        fprintf(stderr, "ERROR: While making the key pair.\n");
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    if ((fp = fopen(k_pub_out, "w")) == NULL) {
        fprintf(stderr, "ERROR: Unable to write to '%s'.", k_pub_out);
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    if (fwrite(k_pub, 1, k_pub_size, fp) == -1) {
        fprintf(stderr, "ERROR: Unable to write to save the public key.\n");
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    fclose(fp);

    if ((fp = fopen(k_priv_out, "w")) == NULL) {
        fprintf(stderr, "ERROR: Unable to write to '%s'.", k_priv_out);
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    if ((enc_k_priv = encrypt_dh_kpriv(k_priv, k_priv_size, kpriv_key[0], kpriv_key_size[0], &enc_k_priv_size)) == NULL) {
        fprintf(stderr, "ERROR: Unable to encrypt the kpriv buffer.\n");
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    if (fwrite(enc_k_priv, 1, enc_k_priv_size, fp) == -1) {
        fprintf(stderr, "ERROR: Unable to write to save the private key.\n");
        err = EFAULT;
        goto mk_dh_key_pair_epilogue;
    }

    fclose(fp);
    fp = NULL;
    err = 0;

mk_dh_key_pair_epilogue:

    if (k_pub != NULL) {
        kryptos_freeseg(k_pub, k_pub_size);
    }

    if (k_priv != NULL) {
        kryptos_freeseg(k_priv, k_priv_size);
    }

    if (kpriv_key[0] != NULL) {
        kryptos_freeseg(kpriv_key[0], kpriv_key_size[0]);
    }

    if (kpriv_key[1] != NULL) {
        kryptos_freeseg(kpriv_key[1], kpriv_key_size[1]);
    }

    kpriv_key[0] = kpriv_key[1] = NULL;
    kpriv_key_size[0] = kpriv_key_size[1] = 0;

    if (err != 0) {
        remove(k_pub_out);
        remove(k_priv_out);
    }

    if (params != NULL) {
        kryptos_freeseg(params, params_size);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    kryptos_clear_dh_xchg_ctx(dh);

    if (enc_k_priv != NULL) {
        kryptos_freeseg(enc_k_priv, enc_k_priv_size);
        enc_k_priv_size = 0;
    }

    return err;
}

static int skey_xchg(void) {
    char *temp;
    int err = EINVAL;
    struct skey_xchg_ctx sx;
    skey_xchg_trap sx_trap;
    FILE *fp = NULL;
    kryptos_u8_t *k_buf = NULL, *kpriv_key = NULL;
    size_t k_buf_size, kpriv_key_size;
    int server = blackcat_get_bool_option("server", 0);

    sx.libc_socket = NULL;
    sx.libc_send = NULL;
    sx.libc_recv = NULL;
    sx.keep_sk_open = 0;

    BLACKCAT_GET_OPTION_OR_DIE(temp, (server) ? "kpub" : "kpriv", skey_xchg_epilogue);

    if ((fp = fopen(temp, "r")) == NULL) {
        err = EFAULT;
        fprintf(stderr, "ERROR: Unable to open '%s'.\n", temp);
        goto skey_xchg_epilogue;
    }

    fseek(fp, 0L, SEEK_END);
    k_buf_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    if ((k_buf = (kryptos_u8_t *)kryptos_newseg(k_buf_size)) == NULL) {
        err = ENOMEM;
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto skey_xchg_epilogue;
    }

    if (fread(k_buf, 1, k_buf_size, fp) == -1) {
        err = EFAULT;
        fprintf(stderr, "ERROR: Unable to read the dh parameters.\n");
        goto skey_xchg_epilogue;
    }

    fclose(fp);
    fp = NULL;

    sx.verbose = 1;

    if (server) {
        BLACKCAT_GET_OPTION_OR_DIE(temp, "bits", skey_xchg_epilogue);

        if (!blackcat_is_dec(temp, strlen(temp))) {
            fprintf(stderr, "ERROR: The '--bits' option should has a valid number.\n");
            goto skey_xchg_epilogue;
        }

        sx.s_bits = strtoul(temp, NULL, 10);

        BLACKCAT_GET_OPTION_OR_DIE(temp, "port", skey_xchg_epilogue);

        if (!blackcat_is_dec(temp, strlen(temp))) {
            fprintf(stderr, "ERROR: The option '--port' must have a valid port number.\n");
            goto skey_xchg_epilogue;
        }

        sx.key_size = 0;
        memset(sx.addr, 0, sizeof(sx.addr));
        sx.port = atoi(temp);
        sx.k_pub = k_buf;
        sx.k_pub_size = k_buf_size;
        sx_trap = skey_xchg_server;
    } else {
        accacia_savecursorposition();
        fprintf(stdout, "Kpriv key: ");
        if ((kpriv_key = blackcat_getuserkey(&kpriv_key_size)) == NULL) {
            fprintf(stderr, "ERROR: NULL Kpriv key.\n");
            fflush(stderr);
            err = EFAULT;
            goto skey_xchg_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        if ((sx.k_priv = decrypt_dh_kpriv(k_buf, k_buf_size, kpriv_key, kpriv_key_size, &sx.k_priv_size)) == NULL) {
            fprintf(stderr, "ERROR: Invalid Kpriv key.\n");
            err = EFAULT;
            goto skey_xchg_epilogue;
        }

        kryptos_freeseg(kpriv_key, kpriv_key_size);
        kpriv_key = NULL;
        kpriv_key_size = 0;

        BLACKCAT_GET_OPTION_OR_DIE(temp, "port", skey_xchg_epilogue);
        if (!blackcat_is_dec(temp, strlen(temp))) {
            fprintf(stderr, "ERROR: The option '--port' must have a valid port number.\n");
            goto skey_xchg_epilogue;
        }
        sx.port = atoi(temp);

        BLACKCAT_GET_OPTION_OR_DIE(temp, "addr", skey_xchg_epilogue);
        if (temp == NULL) {
            memset(sx.addr, 0, sizeof(sx.addr));
        } else {
            snprintf(sx.addr, sizeof(sx.addr) - 1, "%s", temp);
        }

        sx_trap = skey_xchg_client;
    }

    err = sx_trap(&sx);

skey_xchg_epilogue:

    if (kpriv_key != NULL) {
        kryptos_freeseg(kpriv_key, kpriv_key_size);
        kpriv_key = NULL;
        kpriv_key_size = 0;
    }

    if (fp != NULL) {
        fclose(fp);
    }

    if (sx_trap == skey_xchg_client) {
        if (err == 0) {
            skey_print(sx.session_key, sx.session_key_size);
            kryptos_freeseg(sx.session_key, sx.session_key_size);
        }
        kryptos_freeseg(sx.k_priv, sx.k_priv_size);
    }

    if (k_buf != NULL) {
        kryptos_freeseg(k_buf, k_buf_size);
    }

    memset(&sx, 0, sizeof(sx));

    return err;
}

static void skey_print(const kryptos_u8_t *skey, const size_t skey_size) {
    const kryptos_u8_t *sp = skey, *sp_end = skey + skey_size;

    fprintf(stdout, "INFO: The session key is '");

    while (sp != sp_end) {
        if (isprint(*sp)) {
            fprintf(stdout, "%c", *sp);
        } else {
            fprintf(stdout, "\\x%.2X", *sp);
        }
        sp++;
    }

    fprintf(stdout, "'.\n");
    sp = sp_end = NULL;
}

#endif

#undef BLACKCAT_NET_DB_HOME
#undef BLACKCAT_BCSCK_LIB_HOME
