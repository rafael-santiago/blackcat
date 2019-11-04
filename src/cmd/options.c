/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/options.h>
#include <fs/bcrepo/config.h>
#include <keychain/keychain.h>
#include <keychain/kdf/kdf_utils.h>
#include <keychain/ciphering_schemes.h>
#include <util/token.h>
#include <string.h>
#include <stdio.h>

static char *g_blackcat_cmd = NULL;

static char **g_blackcat_argv = NULL;

static int g_blackcat_argc = 0;

static char  **g_blackcat_argv_head = NULL;

static struct blackcat_kdf_clockwork_ctx *blackcat_kdf_usr_params_hkdf(void);

static struct blackcat_kdf_clockwork_ctx *blackcat_kdf_usr_params_pbkdf2(void);

static struct blackcat_kdf_clockwork_ctx *blackcat_kdf_usr_params_argon2i(void);

static int wrap_user_key_with_tokens_stmt(kryptos_u8_t **key, size_t *key_size,
                                          char **token_options, size_t token_options_nr);

char *blackcat_get_option(const char *option, char *default_option) {
    char temp[4096];
    int a;

    if (option == NULL) {
        return NULL;
    }

    snprintf(temp, sizeof(temp) - 1, "--%s=", option);

    for (a = 0; a < g_blackcat_argc; a++) {
        if (strstr(g_blackcat_argv[a], temp) == &g_blackcat_argv[a][0]) {
            return &g_blackcat_argv[a][0] + strlen(temp);
        }
    }

    return default_option;
}

int blackcat_get_bool_option(const char *option, const int default_state) {
    char temp[4096];
    int a;

    if (option == NULL) {
        return 0;
    }

    snprintf(temp, sizeof(temp) - 1, "--%s", option);

    for (a = 0; a < g_blackcat_argc; a++) {
        if (strcmp(g_blackcat_argv[a], temp) == 0) {
            return 1;
        }
    }

    return default_state;
}

char *blackcat_get_command(void) {
    return g_blackcat_cmd;
}

void blackcat_set_argc_argv(int argc, char **argv) {
    struct bcrepo_config_ctx *cfg = NULL;
    char *cmdline = NULL, *cp;
    size_t cmdline_size, temp_size;
    int a;

    if (g_blackcat_argv_head != NULL) {
        blackcat_clear_options();
        //g_blackcat_argv_head = NULL;
    }

    if (argv == NULL) {
        g_blackcat_cmd = NULL;
        g_blackcat_argv = NULL;
        g_blackcat_argc = 0;
    } else {
        if ((cfg = bcrepo_ld_config()) == NULL || bcrepo_config_get_section(cfg, BCREPO_CONFIG_SECTION_DEFAULT_ARGS) == 0) {
            g_blackcat_cmd = argv[1];
            g_blackcat_argv = &argv[2];
            g_blackcat_argc = argc - 2;
        } else {
            cmdline_size = 0;
            for (a = 1; a < argc; a++) {
                cmdline_size += strlen(argv[a]) + 1;
            }

            while (bcrepo_config_get_next_word(cfg) != 0) {
                cmdline_size += cfg->word_end - cfg->word + 1;
            }

            cmdline_size += 64;

            if ((cmdline = (char *) kryptos_newseg(cmdline_size)) == NULL) {
                goto blackcat_set_argc_argv_epilogue;
            }


            memset(cmdline, 0, cmdline_size);
            cp = cmdline;

            for (a = 1; a < argc; a++) {
                temp_size = strlen(argv[a]);
                memcpy(cp, argv[a], temp_size);
                *(cp + temp_size) = ' ';
                cp += temp_size + 1;
            }

            bcrepo_config_get_section(cfg, BCREPO_CONFIG_SECTION_DEFAULT_ARGS);

            while (bcrepo_config_get_next_word(cfg) != 0) {
                temp_size = cfg->word_end - cfg->word;
                memcpy(cp, cfg->word, temp_size);
                *(cp + temp_size) = ' ';
                cp += temp_size + 1;
            }

            // INFO(Rafael): Nasty trick for clearing original command line arguments easily.

            g_blackcat_argv_head = NULL;

            g_blackcat_cmd = argv[1];
            g_blackcat_argv = &argv[2];
            g_blackcat_argc = argc - 2;
            blackcat_clear_options();

            g_blackcat_argv_head = mkargv(g_blackcat_argv_head, cmdline, cmdline_size, &g_blackcat_argc);

            g_blackcat_cmd = g_blackcat_argv_head[1];
            g_blackcat_argv = &g_blackcat_argv_head[2];
            g_blackcat_argc = g_blackcat_argc;
        }
    }

blackcat_set_argc_argv_epilogue:

    if (cfg != NULL) {
        bcrepo_release_config(cfg);
    }

    if (cmdline != NULL) {
        kryptos_freeseg(cmdline, cmdline_size);
    }
}

char *blackcat_get_argv(const int v) {
    if (v < 0 || v >= g_blackcat_argc) {
        return NULL;
    }

    return &g_blackcat_argv[v][0];
}

void blackcat_clear_options(void) {
    // WARN(Rafael): This is not an alibi to pass sensible data through command line.
    size_t size;

    if (g_blackcat_argv_head == NULL) {
        if (g_blackcat_cmd != NULL) {
            size = strlen(g_blackcat_cmd);
            memset(g_blackcat_cmd, 0, size);
        }

        if (g_blackcat_argv != NULL) {
            while (g_blackcat_argc-- > -1) {
                size = strlen(g_blackcat_argv[g_blackcat_argc]);
                memset(g_blackcat_argv[g_blackcat_argc], 0, size);
            }
        }
    } else {
        freeargv(g_blackcat_argv_head, g_blackcat_argc + 1);
    }

    g_blackcat_cmd = NULL;
    g_blackcat_argv = NULL;
    g_blackcat_argc = 0;
    g_blackcat_argv_head = NULL;
    size = 0;
}

char **mkargv(char **argv, const char *buf, const size_t buf_size, int *argc) {
    const char *bp, *bp_end, *bp_off;
    int a;
    size_t a_size;

    if (buf == NULL || buf_size == 0 || argc == NULL) {
        return NULL;
    }

    bp = buf;
    bp_end = bp + buf_size + 1;

    *argc = 1;

    while (bp < bp_end) {
        if (*bp == '\\') {
            bp++;
        } else if (*bp == ' ' || *bp == '\t' || *bp == 0) {
            (*argc)++;
            if (*bp == 0) {
                break;
            }
            while (*bp == ' ' || *bp == '\t') {
                bp++;
            }
        }
        bp++;
    }

    if ((argv = (char **) kryptos_newseg(sizeof(char *) * (*argc + 1))) == NULL) {
        return NULL;
    }

    for (a = 0; a < *argc + 1; a++) {
        argv[a] = NULL;
    }

    //argv[0] = NULL; // INFO(Rafael): Dummy entry.
    a = 1;

    bp = bp_off = buf;
    bp_end = bp + buf_size + 1;

    while (bp < bp_end) {
        if (*bp == '\\') {
            bp++;
        } else if (*bp == ' ' || *bp == 0) {
            a_size = bp - bp_off + 1;
            if ((argv[a] = (char *) kryptos_newseg(a_size)) == NULL) {
                return NULL; // INFO(Rafael): Assuming it almost impossible, let leaking.
            }
            memset(argv[a], 0, a_size);
            memcpy(argv[a], bp_off, a_size - 1);
            a++;
            if (*bp == 0) {
                break;
            }
            while (*bp == ' ') {
                bp++;
            }
            bp_off = bp;
        }
        bp++;
    }

    return argv;
}

void freeargv(char **argv, const int argc) {
    int a;

    if (argv == NULL || argc == 0) {
        return;
    }

    for (a = 0; a < argc; a++) {
        if (argv[a] != NULL) {
            kryptos_freeseg(argv[a], strlen(argv[a]));
        }
    }

    kryptos_freeseg(argv, sizeof(char *) * argc);
}

char *blackcat_get_kdf_usr_params_from_cmdline(size_t *out_size) {
    char *kdf;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    char *out = NULL;

    if ((kdf = blackcat_get_option("kdf", NULL)) == NULL) {
        return NULL;
    }

    if (strcmp(kdf, "hkdf") == 0) {
        kdf_clockwork = blackcat_kdf_usr_params_hkdf();
    } else if (strcmp(kdf, "pbkdf2") == 0) {
        kdf_clockwork = blackcat_kdf_usr_params_pbkdf2();
    } else if (strcmp(kdf, "argon2i") == 0) {
        kdf_clockwork = blackcat_kdf_usr_params_argon2i();
    }

    if (kdf_clockwork != NULL) {
        out = get_kdf_usr_params(kdf_clockwork, out_size);
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
    }

    return out;
}

int wrap_user_key_with_tokens(kryptos_u8_t **key, size_t *key_size) {
    static char *token_options[] = {
        "soft-token"
    };
    static size_t token_options_nr = sizeof(token_options) / sizeof(token_options[0]);
    return wrap_user_key_with_tokens_stmt(key, key_size, token_options, token_options_nr);
}

int wrap_user_key_with_new_tokens(kryptos_u8_t **key, size_t *key_size) {
    // INFO(Rafael): This function is used during a setkey operation.
    static char *token_options[] = {
        "new-soft-token"
    };
    static size_t token_options_nr = sizeof(token_options) / sizeof(token_options[0]);
    return wrap_user_key_with_tokens_stmt(key, key_size, token_options, token_options_nr);
}

static int wrap_user_key_with_tokens_stmt(kryptos_u8_t **key, size_t *key_size,
                                          char **token_options, size_t token_options_nr) {
    FILE *fp = NULL;
    size_t t;
    char token_path[4096];
    char *option, *op_head, *op, *op_end;
    size_t path_size;
    int no_error = 1;
    kryptos_u8_t *token_data = NULL;
    size_t token_data_size = 0;

    for (t = 0; t < token_options_nr; t++) {
        if ((option = blackcat_get_option(token_options[t], NULL)) == NULL) {
            continue;
        }

        op = option;
        op_end = op + strlen(option);

        while (op < op_end && no_error) {
            op_head = op;
            while (op != op_end && *op != ',') {
                op++;
            }

            path_size = op - op_head;

            if (path_size >= sizeof(token_path)) {
                fprintf(stderr, "ERROR: The token path is too large.\n");
                no_error = 0;
                goto wrap_user_key_with_tokens_epilogue;
            }

            memset(token_path, 0, sizeof(token_path));
            memcpy(token_path, op_head, path_size);

            if ((fp = fopen(token_path, "rb")) == NULL) {
                fprintf(stderr, "ERROR: Unable to read token data from '%s'.\n", token_path);
                no_error = 0;
                goto wrap_user_key_with_tokens_epilogue;
            }

            if (fseek(fp, 0L, SEEK_END) == -1) {
                fprintf(stderr, "ERROR: Unable to seek along token data from '%s' until its end.\n", token_path);
                no_error = 0;
                goto wrap_user_key_with_tokens_epilogue;
            }

            token_data_size = ftell(fp);

            if (fseek(fp, 0L, SEEK_SET) == -1) {
                fprintf(stderr, "ERROR: Unable to seek along token data from '%s' until its beginning.\n", token_path);
                no_error = 0;
                goto wrap_user_key_with_tokens_epilogue;
            }

            token_data = (kryptos_u8_t *) kryptos_newseg(token_data_size);

            if (token_data == NULL) {
                fprintf(stderr, "ERROR: Not enough memory to read data from token at '%s'.\n", token_path);
                no_error = 0;
                goto wrap_user_key_with_tokens_epilogue;
            }

            fread(token_data, 1, token_data_size, fp);

            fclose(fp);
            fp = NULL;

            no_error = token_wrap(key, key_size, token_data, token_data_size);

            kryptos_freeseg(token_data, token_data_size);
            token_data = NULL;
            token_data_size = 0;

            op++;
        }
    }

wrap_user_key_with_tokens_epilogue:

    memset(token_path, 0, sizeof(token_path));

    option = op_head = op = op_end = NULL;

    if (token_data != NULL) {
        kryptos_freeseg(token_data, token_data_size);
        token_data = NULL;
        token_data_size = 0;
    }

    if (fp != NULL) {
        fclose(fp);
        fp = NULL;
    }

    return no_error;
}

static struct blackcat_kdf_clockwork_ctx *blackcat_kdf_usr_params_hkdf(void) {
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    char *option;

    new_blackcat_kdf_clockwork_ctx(kdf_clockwork, goto blackcat_kdf_usr_params_hkdf_epilogue);

    if ((option = blackcat_get_option("hkdf-hash", NULL)) == NULL) {
        option = blackcat_get_option("protection-layer-hash", NULL);
        if (option == NULL) {
            fprintf(stderr, "ERROR: The '--protection-layer-hash' option is missing.\n");
            del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
            kdf_clockwork = NULL;
            goto blackcat_kdf_usr_params_hkdf_epilogue;
        }
    }

    kdf_clockwork->kdf = blackcat_hkdf;

    kdf_clockwork->arg_data[0] = (void *) get_hash_processor(option);

    if (kdf_clockwork->arg_data[0] == NULL) {
        fprintf(stderr, "ERROR: Unknown hash function : '%s'.\n", option);
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_hkdf_epilogue;
    }

    kdf_clockwork->arg_data[3] = blackcat_fmt_str(blackcat_get_option("hkdf-salt", NULL), &kdf_clockwork->arg_size[3]);
    kdf_clockwork->arg_data[4] = &kdf_clockwork->arg_size[3];
    kdf_clockwork->arg_size[4] = 0;
    kdf_clockwork->arg_data[5] = blackcat_fmt_str(blackcat_get_option("hkdf-info", NULL), &kdf_clockwork->arg_size[5]);
    kdf_clockwork->arg_data[6] = &kdf_clockwork->arg_size[5];
    kdf_clockwork->arg_size[6] = 0;

blackcat_kdf_usr_params_hkdf_epilogue:

    option = NULL;

    return kdf_clockwork;
}

static struct blackcat_kdf_clockwork_ctx *blackcat_kdf_usr_params_pbkdf2(void) {
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    char *option;

    new_blackcat_kdf_clockwork_ctx(kdf_clockwork, goto blackcat_kdf_usr_params_pbkdf2_epilogue);

    if ((option = blackcat_get_option("pbkdf2-hash", NULL)) == NULL) {
        option = blackcat_get_option("protection-layer-hash", NULL);
        if (option == NULL) {
            fprintf(stderr, "ERROR: The '--protection-layer-hash' option is missing.\n");
            del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
            kdf_clockwork = NULL;
            goto blackcat_kdf_usr_params_pbkdf2_epilogue;
        }
    }

    kdf_clockwork->kdf = blackcat_pbkdf2;

    kdf_clockwork->arg_data[0] = (void *) get_hash_processor(option);

    if (kdf_clockwork->arg_data[0] == NULL) {
        fprintf(stderr, "ERROR: Unknown hash function : '%s'.\n", option);
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_pbkdf2_epilogue;
    }

    kdf_clockwork->arg_data[3] = blackcat_fmt_str(blackcat_get_option("pbkdf2-salt", NULL), &kdf_clockwork->arg_size[3]);
    kdf_clockwork->arg_data[4] = &kdf_clockwork->arg_size[3];
    kdf_clockwork->arg_size[4] = 0;

    option = blackcat_get_option("pbkdf2-count", NULL);

    if (option == NULL) {
        fprintf(stderr, "ERROR: The '--pbkdf2-count' option is missing.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_pbkdf2_epilogue;
    }

    if (!blackcat_is_dec(option, strlen(option))) {
        fprintf(stderr, "ERROR: The '--pbkdf2-count' must be a valid decimal number.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_pbkdf2_epilogue;
    }

    kdf_clockwork->arg_data[5] = (size_t *)kryptos_newseg(sizeof(size_t));

    if (kdf_clockwork->arg_data[5] == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to get data from '--pbkdf2-count' option.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_pbkdf2_epilogue;
    }

    kdf_clockwork->arg_size[5] = sizeof(size_t);
    *((size_t *)kdf_clockwork->arg_data[5]) = strtoul(option, NULL, 10);

blackcat_kdf_usr_params_pbkdf2_epilogue:

    option = NULL;

    return kdf_clockwork;
}

static struct blackcat_kdf_clockwork_ctx *blackcat_kdf_usr_params_argon2i(void) {
    char *option;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;

    // INFO(Rafael): ARGON2 is really picky about its parameters... Let's check...

#define BLACKCAT_ARGON2I_LIMIT (0xFFFFFFFF >> 3)

    new_blackcat_kdf_clockwork_ctx(kdf_clockwork, goto blackcat_kdf_usr_params_argon2i_epilogue);

    kdf_clockwork->kdf = blackcat_argon2i;

    kdf_clockwork->arg_data[0] = blackcat_fmt_str(blackcat_get_option("argon2i-salt", NULL), &kdf_clockwork->arg_size[0]);
    kdf_clockwork->arg_data[1] = &kdf_clockwork->arg_size[0];
    kdf_clockwork->arg_size[1] = 0;

    if (kdf_clockwork->arg_size[0] > BLACKCAT_ARGON2I_LIMIT) {
        fprintf(stderr, "ERROR: The '--argon2i-salt' option exceeds its limit.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    // INFO(Rafael): We will use parallelism equals to 1 here in blackcat. It explains why to use a default of 8 kb.
    //               Any doubt take a look at ARGON2's standard spec.

    option = blackcat_get_option("argon2i-memory", "8");

    if (!blackcat_is_dec(option, strlen(option))) {
        fprintf(stderr, "ERROR: The option '--argon2i-memory' must be a valid decimal number.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    kdf_clockwork->arg_data[2] = (kryptos_u32_t *)kryptos_newseg(sizeof(kryptos_u32_t));

    if (kdf_clockwork->arg_data[2] == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to get data from '--argon2i-memory' option.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    *((kryptos_u32_t *)kdf_clockwork->arg_data[2]) = atoi(option);
    kdf_clockwork->arg_size[2] = sizeof(kryptos_u32_t);

    if (*((kryptos_u32_t *)kdf_clockwork->arg_data[2]) > BLACKCAT_ARGON2I_LIMIT) {
        fprintf(stderr, "ERROR: The option '--argon2i-memory' exceeds its limit.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    option = blackcat_get_option("argon2i-iterations", NULL);

    if (option == NULL) {
        fprintf(stderr, "ERROR: The '--argon2i-iterations' option is missing.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    if (!blackcat_is_dec(option, strlen(option))) {
        fprintf(stderr, "ERROR: The option '--argon2i-iterations' must be a valid decimal number.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    kdf_clockwork->arg_data[3] = (kryptos_u32_t *)kryptos_newseg(sizeof(kryptos_u32_t));

    if (kdf_clockwork->arg_data[3] == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to get data from '--argon2i-iterations' option.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    *((kryptos_u32_t *)kdf_clockwork->arg_data[3]) = atoi(option);
    kdf_clockwork->arg_size[3] = sizeof(kryptos_u32_t);

    if (*((kryptos_u32_t *)kdf_clockwork->arg_data[3]) > BLACKCAT_ARGON2I_LIMIT) {
        fprintf(stderr, "ERROR: The option '--argon2i-iterations' exceeds its limit.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    kdf_clockwork->arg_data[4] = blackcat_fmt_str(blackcat_get_option("argon2i-key", NULL), &kdf_clockwork->arg_size[4]);
    kdf_clockwork->arg_data[5] = &kdf_clockwork->arg_size[4];
    kdf_clockwork->arg_size[5] = 0;

    if (kdf_clockwork->arg_size[4] > BLACKCAT_ARGON2I_LIMIT) {
        fprintf(stderr, "ERROR: The option '--argon2i-key' exceeds its limit.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

    kdf_clockwork->arg_data[6] = blackcat_fmt_str(blackcat_get_option("argon2i-aad", NULL), &kdf_clockwork->arg_size[6]);
    kdf_clockwork->arg_data[7] = &kdf_clockwork->arg_size[6];
    kdf_clockwork->arg_size[7] = 0;

    if (kdf_clockwork->arg_size[6] > BLACKCAT_ARGON2I_LIMIT) {
        fprintf(stderr, "ERROR: The option '--argon2i-aad' exceeds its limit.\n");
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto blackcat_kdf_usr_params_argon2i_epilogue;
    }

#undef BLACKCAT_ARGON2I_LIMIT

blackcat_kdf_usr_params_argon2i_epilogue:

    option = NULL;

    return kdf_clockwork;
}
