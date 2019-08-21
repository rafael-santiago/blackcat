/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/kdf/argon2i.h>
#include <keychain/kdf/kdf_utils.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

IMPL_BLACKCAT_KDF_PROCESSOR(argon2i, ikm, ikm_size, okm_size, args,
                            {
                                return kryptos_do_argon2(ikm, ikm_size,
                                                         (kryptos_u8_t *)args[0],
                                                         *((size_t *)args[1]),
                                                         1, // WARN(Rafael): Libkryptos' argon implementation
                                                            // allows greater parallelism, but timing attacks
                                                            // are possible in this case. Let's avoid it.
                                                         (kryptos_u32_t)okm_size,
                                                         *((kryptos_u32_t *)args[2]),
                                                         *((kryptos_u32_t *)args[3]),
                                                         (kryptos_u8_t *)args[4],
                                                         *((size_t *)args[5]),
                                                         (kryptos_u8_t *)args[6],
                                                         *((size_t *)args[7]),
                                                         kArgon2i);
                            })

struct blackcat_kdf_clockwork_ctx *get_argon2i_clockwork(const char *usr_params, const size_t usr_params_size,
                                                         char *err_msg) {
    // INFO(Rafael): This function expects the following string format:
    //               'argon2i:<salt-radix-64>:<memory-kb-size-as-decimal-str>:<iteration-as-decimal-str>:
    //                <key-radix-64>:<associated-data-radix-64>'
    kryptos_task_ctx t, *ktask = &t;
    char *arg = NULL, *next = NULL;
    size_t arg_size, delta_offset = 0;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;

    kryptos_task_init_as_null(ktask);

    if (usr_params == NULL || usr_params_size == 0) {
        goto get_argon2i_clockwork_epilogue;
    }

    arg = blackcat_kdf_usr_params_get_next(usr_params, usr_params_size, &next, &arg_size, &delta_offset);
    if (arg == NULL || strcmp(arg, "argon2i") != 0) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: wrong clockwork processor; it should be '%s'.", arg);
        }
        goto get_argon2i_clockwork_epilogue;
    }

    new_blackcat_kdf_clockwork_ctx(kdf_clockwork, goto get_argon2i_clockwork_epilogue);

    kdf_clockwork->kdf = blackcat_argon2i;

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing argon2i salt parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, arg, arg_size);

    if (!kryptos_last_task_succeed(ktask)) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while decoding argon2i salt parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[0] = ktask->out;
    kdf_clockwork->arg_size[0] = ktask->out_size;
    kdf_clockwork->arg_data[1] = &kdf_clockwork->arg_size[0];
    kdf_clockwork->arg_size[1] = 0;
    ktask->out = NULL;

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing argon2i memory kb size parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    if (!blackcat_is_dec(arg, arg_size)) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: argon2i memory kb size must be a decimal number.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[2] = (kryptos_u32_t *) kryptos_newseg(sizeof(kryptos_u32_t));
    if (kdf_clockwork->arg_data[2] == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: not enough memory to argon2i memory kb parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    *((kryptos_u32_t *)kdf_clockwork->arg_data[2]) = (kryptos_u32_t)atoi(arg);
    kdf_clockwork->arg_size[2] = sizeof(kryptos_u32_t);

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing argon2i iterations parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    if (!blackcat_is_dec(arg, arg_size)) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: argon2i iterations parameter must be a decimal number.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[3] = (kryptos_u32_t *) kryptos_newseg(sizeof(kryptos_u32_t));
    if (kdf_clockwork->arg_data[3] == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: not enough memory to argon2i iterations parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    *((kryptos_u32_t *)kdf_clockwork->arg_data[3]) = (kryptos_u32_t)atoi(arg);
    kdf_clockwork->arg_size[3] = sizeof(kryptos_u32_t);

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing argon2i key parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, arg, arg_size);

    if (!kryptos_last_task_succeed(ktask)) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while decoding argon2i key parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[4] = ktask->out;
    kdf_clockwork->arg_size[4] = ktask->out_size;
    kdf_clockwork->arg_data[5] = &kdf_clockwork->arg_size[4];
    kdf_clockwork->arg_size[5] = 0;
    ktask->out = NULL;

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing argon2i associated data parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, arg, arg_size);

    if (!kryptos_last_task_succeed(ktask)) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while decoding argon2i associated data parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_argon2i_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[6] = ktask->out;
    kdf_clockwork->arg_size[6] = ktask->out_size;
    kdf_clockwork->arg_data[7] = &kdf_clockwork->arg_size[6];
    kdf_clockwork->arg_size[7] = 0;
    ktask->out = NULL;

get_argon2i_clockwork_epilogue:

    if (arg != NULL) {
        kryptos_freeseg(arg, arg_size);
        arg_size = 0;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    return kdf_clockwork;
}
