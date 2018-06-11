/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/seal.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SEAL_KSTREAM_SIZE 65535

static int seal_version_verifier(const char *data, const size_t data_size, char *err_mesg);

static int seal_L_verifier(const char *data, const size_t data_size, char *err_mesg);

static int seal_n_verifier(const char *data, const size_t data_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(seal, ktask, p_layer,
                               kryptos_run_cipher(seal, *ktask, p_layer->key, p_layer->key_size,
                                                  (kryptos_seal_version_t *)p_layer->arg[0],
                                                  (size_t *)p_layer->arg[1],
                                                  (size_t *)p_layer->arg[2]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(seal, algo_params, args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *arg = NULL;
    int no_error = 1;

    blackcat_keychain_verify_argv_bounds(args_nr, 3, err_mesg);

    if (algo_params == NULL) {
        no_error = 0;
        goto seal_args_reader_epilogue;
    }

    blackcat_keychain_arg_init(algo_params, strlen(algo_params), &begin, &end);
    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, seal_version_verifier);

    if (arg == NULL) {
        no_error = 0;
        goto seal_args_reader_epilogue;
    }

    args[0] = (kryptos_seal_version_t *) kryptos_newseg(sizeof(kryptos_seal_version_t));
    *(kryptos_seal_version_t *)args[0] = atoi(arg);
    free(arg);

    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, seal_L_verifier);

    if (arg == NULL) {
        no_error = 0;
        goto seal_args_reader_epilogue;
    }

    args[1] = (size_t *) kryptos_newseg(sizeof(size_t));
    *(size_t *)args[1] = atoi(arg);
    free(arg);

    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, seal_n_verifier);

    if (arg == NULL) {
        no_error = 0;
        goto seal_args_reader_epilogue;
    }

    args[2] = (size_t *) kryptos_newseg(sizeof(size_t));
    *(size_t *)args[2] = atoi(arg);

    *argc = 3;

seal_args_reader_epilogue:

    if (arg != NULL) {
        free(arg);
    }

    return no_error;
}

static int seal_version_verifier(const char *data, const size_t data_size, char *err_mesg) {
    kryptos_seal_version_t v;

    if (data == NULL || data_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Version argument for SEAL is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(data, data_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Version argument for SEAL must be a number.\n");
        }
        return 0;
    }

    v = (kryptos_seal_version_t) atoi(data);

    if (v != kKryptosSEAL20 && v != kKryptosSEAL30) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Version argument for SEAL must be %d or %d.\n", kKryptosSEAL20, kKryptosSEAL30);
        }
        return 0;
    }

    return 1;
}

static int seal_L_verifier(const char *data, const size_t data_size, char *err_mesg) {
    size_t L;

    if (data == NULL || data_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: L argument for SEAL is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(data, data_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: L argument for SEAL must be a number.\n");
        }
        return 0;
    }

    L = atoi(data);

    if (L < 1 || L > SEAL_KSTREAM_SIZE) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: L argument must be between 1 and %d.\n", SEAL_KSTREAM_SIZE);
        }
        return 0;
    }

    return  1;
}

static int seal_n_verifier(const char *data, const size_t data_size, char *err_mesg) {
    if (data == NULL || data_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: N argument for SEAL is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(data, data_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: N argument must be a positive number.\n");
        }
        return 0;
    }

    return 1;
}

#undef SEAL_KSTREAM_SIZE
