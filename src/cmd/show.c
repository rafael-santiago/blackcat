/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/show.h>
#include <cmd/options.h>
#include <cmd/did_you_mean.h>
#include <fs/bcrepo/bcrepo.h>
#include <keychain/ciphering_schemes.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_show(void) {
    char *show_param;
    kryptos_u8_t *data;
    size_t data_size;
    int exit_code = EINVAL;
    int a = 0;
    static const char *known_terms[] = {
        "ciphers",
        "hmacs",
        "hashes",
        "encoders",
        "kdfs"
    };
    static size_t known_terms_nr = sizeof(known_terms) / sizeof(known_terms[0]);

    show_param = blackcat_get_argv(0);

    if (show_param == NULL) {
        fprintf(stderr, "ERROR: What I should show?\n");
        goto blackcat_cmd_show_epilogue;
    }

    BLACKCAT_CONSUME_USER_OPTIONS(a,
                                  show_param,
                                  {
                                     if (strcmp(show_param, "ciphers") == 0) {
                                        data = blackcat_get_avail_ciphers(&data_size);
                                     } else if (strcmp(show_param, "hmacs") == 0) {
                                        data = blackcat_get_avail_hmacs(&data_size);
                                     } else if (strcmp(show_param, "hashes") == 0) {
                                        data = blackcat_get_avail_hashes(&data_size);
                                     } else if (strcmp(show_param, "encoders") == 0) {
                                        data = blackcat_get_avail_encoders(&data_size);
                                     } else if (strcmp(show_param, "kdfs") == 0) {
                                        data = blackcat_get_avail_kdfs(&data_size);
                                     } else {
                                        if (custom_did_you_mean(show_param, 2, known_terms, known_terms_nr) == 0) {
                                            fprintf(stderr, "ERROR: '%s' is a unknown show parameter.\n", show_param);
                                        }
                                        goto blackcat_cmd_show_epilogue;
                                     }
                                     if (data == NULL) {
                                        fprintf(stderr, "ERROR: Unable to get data buffer.\n");
                                        exit_code = ENOMEM;
                                        goto blackcat_cmd_show_epilogue;
                                     }
                                     fwrite(data, 1, data_size, stdout);
                                     kryptos_freeseg(data, data_size);
                                 }, 1, 0)

    exit_code = 0;

blackcat_cmd_show_epilogue:

    return exit_code;
}

int blackcat_cmd_show_help(void) {
    fprintf(stdout, "use: blackcat show\n"
                    "              <ciphers  |\n"
                    "               hmacs    |\n"
                    "               hashes   |\n"
                    "               encoders |\n"
                    "               kdfs>\n");
    return 0;
}
