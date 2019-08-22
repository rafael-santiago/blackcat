/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/kdf/pbkdf2.h>
#include <keychain/kdf/kdf_utils.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

IMPL_BLACKCAT_KDF_PROCESSOR(pbkdf2, ikm, ikm_size, okm_size, args,
                            {
                                return kryptos_do_pbkdf2(ikm,
                                                         ikm_size,
                                                         (kryptos_hash_func)args[0],
                                                         (kryptos_hash_size_func)args[1],
                                                         (kryptos_hash_size_func)args[2],
                                                         (kryptos_u8_t *)args[3],
                                                         *((size_t *)args[4]),
                                                         *((size_t *)args[5]),
                                                         okm_size);
                            })

struct blackcat_kdf_clockwork_ctx *get_pbkdf2_clockwork(const char *usr_params, const size_t usr_params_size,
                                                        char *err_msg) {
    //INFO(Rafael): This function expects this kind of user parameter string:
    //              'pbkdf2:<hash>:<salt-radix-64>:<count-as-decimal-string>'.

    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    kryptos_task_ctx t, *ktask = &t;
    char *arg = NULL, *next = NULL;
    size_t arg_size, delta_offset = 0;

    kryptos_task_init_as_null(ktask);

    if (usr_params == NULL || usr_params_size == 0) {
        goto get_pbkdf2_clockwork_epilogue;
    }

    arg = blackcat_kdf_usr_params_get_next(usr_params, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL || strcmp(arg, "pbkdf2") != 0) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: wrong clockwork processor; it should be '%s'.", arg);
        }
        goto get_pbkdf2_clockwork_epilogue;
    }

    new_blackcat_kdf_clockwork_ctx(kdf_clockwork, goto get_pbkdf2_clockwork_epilogue);

    kdf_clockwork->kdf = blackcat_pbkdf2;

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing hash algorithm.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_pbkdf2_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[0] = get_hash_processor(arg);
    kdf_clockwork->arg_size[0] = 0;

    if (kdf_clockwork->arg_data[0] == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: unknown hash algorithm : '%s'.", arg);
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_pbkdf2_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[1] = get_hash_size(arg);
    kdf_clockwork->arg_size[1] = 0;

    kdf_clockwork->arg_data[2] = get_hash_input_size(arg);
    kdf_clockwork->arg_size[2] = 0;

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing pbkdf2 salt parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_pbkdf2_clockwork_epilogue;
    }

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, arg, arg_size);

    if (!kryptos_last_task_succeed(ktask)) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while decoding pbkdf2 salt parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_pbkdf2_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[3] = ktask->out;
    kdf_clockwork->arg_size[3] = ktask->out_size;
    kdf_clockwork->arg_data[4] = &kdf_clockwork->arg_size[3];
    kdf_clockwork->arg_size[4] = 0;
    ktask->out = NULL;

    kryptos_freeseg(arg, arg_size);
    arg = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &arg_size, &delta_offset);

    if (arg == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: while parsing pbkdf2 count parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_pbkdf2_clockwork_epilogue;
    }

    if (!blackcat_is_dec(arg, arg_size)) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: pbkdf2 count parameter must be a decimal number.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_pbkdf2_clockwork_epilogue;
    }

    kdf_clockwork->arg_data[5] = (size_t *) kryptos_newseg(sizeof(size_t));
    if (kdf_clockwork->arg_data[5] == NULL) {
        if (err_msg != NULL) {
            sprintf(err_msg, "ERROR: not enough memory to pbkdf2 count parameter.");
        }
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        kdf_clockwork = NULL;
        goto get_pbkdf2_clockwork_epilogue;
    }

    *((size_t *)kdf_clockwork->arg_data[5]) = strtoul(arg, NULL, 10);
    kdf_clockwork->arg_size[5] = sizeof(size_t);

get_pbkdf2_clockwork_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    if (arg != NULL) {
        kryptos_freeseg(arg, arg_size);
        arg_size = 0;
    }

    return kdf_clockwork;
}

char *get_pbkdf2_usr_params(const struct blackcat_kdf_clockwork_ctx *kdf_clockwork, size_t *out_size) {
    char temp[65535];
    char *tp, *out = NULL, *data, count[10], *tp_end;
    size_t data_size;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    if (kdf_clockwork == NULL || out_size == NULL ||
        kdf_clockwork->arg_data[0] == NULL ||
        kdf_clockwork->arg_data[3] == NULL || kdf_clockwork->arg_size[3] == 0 ||
        kdf_clockwork->arg_data[5] == NULL || kdf_clockwork->arg_size[5] != sizeof(size_t)) {
        goto get_pbkdf2_usr_params_epilogue;
    }

    *out_size = 0;

    memset(temp, 0, sizeof(temp));
    tp = &temp[0];
    tp_end = tp + sizeof(temp);

    memcpy(tp, "pbkdf2:", 7);
    tp += 7;

    data = (char *)get_hash_processor_name((blackcat_hash_processor)kdf_clockwork->arg_data[0]);

    if (data == NULL) {
        goto get_pbkdf2_usr_params_epilogue;
    }

    data_size = strlen(data);
    memcpy(tp, data, data_size);
    tp += data_size;

    data = NULL;
    data_size = 0;

    *tp = ':';
    tp += 1;

    kryptos_task_set_encode_action(ktask);
    kryptos_run_encoder(base64, ktask, kdf_clockwork->arg_data[3], kdf_clockwork->arg_size[3]);

    if (!kryptos_last_task_succeed(ktask)) {
        goto get_pbkdf2_usr_params_epilogue;
    }

    if ((tp + ktask->out_size + 1) >= tp_end) {
        goto get_pbkdf2_usr_params_epilogue;
    }

    memcpy(tp, ktask->out, ktask->out_size);
    tp += ktask->out_size;
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    *tp = ':';
    tp += 1;

    sprintf(count, "%d", *((size_t *)kdf_clockwork->arg_data[5]));

    data_size = strlen(count);

    if ((tp + data_size) >= tp_end) {
        goto get_pbkdf2_usr_params_epilogue;
    }

    memcpy(tp, count, data_size);
    tp += data_size;

    data_size = 0;
    memset(count, 0, sizeof(count));

    *out_size = tp - &temp[0];

    if ((out = (char *)kryptos_newseg(*out_size + 1)) == NULL) {
        goto get_pbkdf2_usr_params_epilogue;
    }

    memset(out, 0, *out_size + 1);
    memcpy(out, temp, *out_size);

get_pbkdf2_usr_params_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    memset(temp, 0, sizeof(temp));

    return out;
}
