/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/token.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <keychain/keychain.h>
#include <errno.h>
#include <stdio.h>

int blackcat_cmd_token(void) {
    char *bytes;
    int exit_code = EINVAL;
    size_t bytes_total;
    int overwrite;
    char *file_param = NULL;
    int a;
    size_t token_nr = 0;

    BLACKCAT_GET_OPTION_OR_DIE(bytes, "bytes", blackcat_cmd_token_epilogue);

    if (blackcat_is_dec(bytes, strlen(bytes)) == 0) {
        fprintf(stderr, "ERROR: The --bytes option has an invalid value (it should be a decimal number).\n");
        goto blackcat_cmd_token_epilogue;
    }

    bytes_total = strtoul(bytes, NULL, 10);

    overwrite = blackcat_get_bool_option("overwrite", 0);

    if ((file_param = blackcat_get_argv(0)) == NULL) {
        fprintf(stderr, "ERROR: No file name(s) specified.\n");
        goto blackcat_cmd_token_epilogue;
    }

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  file_param,
                                  strlen(file_param),
                                  {
                                        if (bcrepo_decoy(file_param, bytes_total, NULL, 0, overwrite) == 0) {
                                            exit_code = EFAULT;
                                            goto blackcat_cmd_token_epilogue;
                                        }
                                        token_nr++;
                                  }, 1, 0)

    if (token_nr == 0) {
        fprintf(stderr, "ERROR: You must specify at least one file path.\n");
        exit_code = EFAULT;
        goto blackcat_cmd_token_epilogue;
    }

    exit_code = 0;

blackcat_cmd_token_epilogue:

    return exit_code;
}

int blackcat_cmd_token_help(void) {
    fprintf(stdout, "use: blackcat token\n"
                    "              <files>\n"
                    "              --bytes=<n>\n"
                    "             [--overwrite]\n");
    return 0;
}
