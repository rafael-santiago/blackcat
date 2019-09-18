/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/decoy.h>
#include <cmd/session.h>
#include <cmd/options.h>
#include <fs/bcrepo/bcrepo.h>
#include <keychain/keychain.h>
#include <keychain/ciphering_schemes.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_decoy(void) {
    int exit_code = EINVAL;
    int a;
    char *encoder_name, *fsize_option;
    int overwrite;
    blackcat_encoder encoder = NULL;
    char *file_param = NULL;
    size_t fsize = 0;
    blackcat_exec_session_ctx *session = NULL;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 0)) != 0) {
        goto blackcat_cmd_decoy_epilogue;
    }

    BLACKCAT_GET_OPTION_OR_DIE(fsize_option, "fsize", blackcat_cmd_decoy_epilogue);

    if (blackcat_is_dec(fsize_option, strlen(fsize_option)) == 0) {
        fprintf(stdout, "ERROR: The --fsize option has an invalid value (it should be a decimal number).\n");
        goto blackcat_cmd_decoy_epilogue;
    }

    fsize = strtoul(fsize_option, NULL, 10);

    if ((encoder_name = blackcat_get_option("encoder", NULL)) != NULL) {
        if ((encoder = get_encoder(encoder_name)) == NULL) {
            fprintf(stderr, "ERROR: Unknown encoder '%s'.\n", encoder_name);
            goto blackcat_cmd_decoy_epilogue;
        }
    } else {
        // INFO(Rafael): When not forced it will follow the default repo encoder.
        encoder = session->catalog->encoder;
    }

    overwrite = blackcat_get_bool_option("overwrite", 0);

    if ((file_param = blackcat_get_argv(0)) == NULL) {
        fprintf(stderr, "ERROR: No file name(s) specified.\n");
        goto blackcat_cmd_decoy_epilogue;
    } else {
        file_param = remove_go_ups_from_path(file_param, strlen(file_param) + 1);
    }

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  file_param,
                                  {
                                        if (bcrepo_decoy(file_param, fsize, encoder, session->catalog->otp, overwrite) == 0) {
                                            exit_code = EFAULT;
                                            goto blackcat_cmd_decoy_epilogue;
                                        }
                                   }, 1)

    exit_code = 0;

blackcat_cmd_decoy_epilogue:

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    return exit_code;
}

int blackcat_cmd_decoy_help(void) {
    fprintf(stdout, "use: blackcat decoy\n"
                    "              <files>\n"
                    "              --fsize=<n>\n"
                    "              [--encoder=<uuencode | base64>\n"
                    "              --overwrite]\n");
    return 0;
}
