/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/steganography/gibberish_wrap.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <string.h>

// WARN(Rafael): Maybe "gibberish" could have a double meaning when cascading. Use it at your own risk.
//               In almost all cases it tends to make harder a CPA. Keeping secret (of course) its parameters.

static void gibberish_wrap(kryptos_task_ctx **ktask, const size_t pfx_size, const size_t sfx_size);

static int gibberish_wrap_size_verifier(const char *data, const size_t data_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(gibberish_wrap, ktask, p_layer,
                               gibberish_wrap(ktask, *(size_t *)p_layer->arg[0], *(size_t *)p_layer->arg[1]))

static void gibberish_wrap(kryptos_task_ctx **ktask, const size_t pfx_size, const size_t sfx_size) {
    kryptos_u8_t *pfx = NULL, *sfx = NULL;

    switch ((*ktask)->action) {
        case kKryptosEncrypt:
            (*ktask)->out_size = pfx_size + sfx_size + (*ktask)->in_size;
            if (((*ktask)->out = kryptos_newseg((*ktask)->out_size)) == NULL) {
                (*ktask)->out_size = 0;
                (*ktask)->result = kKryptosProcessError;
                goto gibberish_wrap_epilogue;
            }

            if (pfx_size > 0) {
                if ((pfx = kryptos_get_random_block(pfx_size)) == NULL) {
                    (*ktask)->result = kKryptosProcessError;
                }
                memcpy((*ktask)->out, pfx, pfx_size);
            }

            memcpy((*ktask)->out + pfx_size, (*ktask)->in, (*ktask)->in_size);

            if (sfx_size > 0) {
                if ((sfx = kryptos_get_random_block(sfx_size)) == NULL) {
                    (*ktask)->result = kKryptosProcessError;
                }

                memcpy((*ktask)->out + pfx_size + (*ktask)->in_size, sfx, sfx_size);
            }

            (*ktask)->result = kKryptosSuccess;
            break;

        case kKryptosDecrypt:
            (*ktask)->out_size = (*ktask)->in_size - pfx_size - sfx_size;

            if (((*ktask)->out = kryptos_newseg((*ktask)->out_size)) == NULL) {
                (*ktask)->out_size = 0;
                (*ktask)->result = kKryptosProcessError;
                goto gibberish_wrap_epilogue;
            }

            memcpy((*ktask)->out, (*ktask)->in + pfx_size, (*ktask)->out_size);

            (*ktask)->result = kKryptosSuccess;
            break;

        default:
            (*ktask)->result = kKryptosProcessError;
            break;
    }

gibberish_wrap_epilogue:
    if (pfx != NULL) {
        kryptos_freeseg(pfx, pfx_size);
    }

    if (sfx != NULL) {
        kryptos_freeseg(sfx, sfx_size);
    }
}

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(gibberish_wrap, algo_params, algo_params_size,
                                      args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *pfx_size, *sfx_size;
    size_t pfx_value, sfx_value;
    int no_error = 1;

    blackcat_keychain_verify_argv_bounds(args_nr, 2, err_mesg);

    blackcat_keychain_arg_init(algo_params, algo_params_size, &begin, &end);

    pfx_size = blackcat_keychain_arg_next(&begin, end, err_mesg, gibberish_wrap_size_verifier);

    if (pfx_size == NULL) {
        no_error = 0;
        goto gibberish_wrap_args_reader_epilogue;
    }

    sfx_size = blackcat_keychain_arg_next(&begin, end, err_mesg, gibberish_wrap_size_verifier);

    if (sfx_size == NULL) {
        no_error = 0;
        goto gibberish_wrap_args_reader_epilogue;
    }

    pfx_value = strtoul(pfx_size, NULL, 10);
    sfx_value = strtoul(sfx_size, NULL, 10);

    if (pfx_value == 0 && sfx_value == 0) {
        no_error = 0;
        sprintf(err_mesg, "ERROR: Both sizes for GIBBERISH-WRAP is zero.\n");
        goto gibberish_wrap_args_reader_epilogue;
    }

    args[0] = (size_t *)kryptos_newseg(sizeof(size_t));
    *(size_t *)args[0] = pfx_value;

    args[1] = (size_t *)kryptos_newseg(sizeof(size_t));
    *(size_t *)args[1] = sfx_value;

    *argc = 2;

gibberish_wrap_args_reader_epilogue:

    pfx_value = sfx_value = 0;

    if (pfx_size != NULL) {
        kryptos_freeseg(pfx_size, strlen(pfx_size));
    }

    if (sfx_size != NULL) {
        kryptos_freeseg(sfx_size, strlen(sfx_size));
    }

    return no_error;
}

static int gibberish_wrap_size_verifier(const char *data, const size_t data_size, char *err_mesg) {
    long value;

    if (data == NULL || data_size == 0) {
        return 0;
    }

    if (!blackcat_is_dec(data, data_size)) {
        sprintf(err_mesg, "ERROR: Invalid size argument for GIBBERISH-WRAP.\n");
        return 0;
    }

    value = strtol(data, NULL, 10);

    if (value < 0) {
        sprintf(err_mesg, "ERROR: Negative size argument for GIBBERISH-WRAP.\n");
        return 0;
    }

    return 1;
}
