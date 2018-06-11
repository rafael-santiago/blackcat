/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/feal.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define FEAL_MAX_ROUNDS_NR 801

static int feal_rounds_arg_verifier(const char *data, const size_t data_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(feal, ktask, p_layer,
                               kryptos_run_cipher(feal, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(feal, algo_params, args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *arg;

    blackcat_keychain_verify_argv_bounds(args_nr, 1, err_mesg);

    blackcat_keychain_arg_init(algo_params, strlen(algo_params), &begin, &end);
    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, feal_rounds_arg_verifier);

    if (arg == NULL) {
        return 0;
    }

    args[0] = (int *) kryptos_newseg(sizeof(int));
    *(int *) args[0] = atoi(arg);
    free(arg);

    *argc = 1;

    return 1;
}

static int feal_rounds_arg_verifier(const char *data, const size_t data_size, char *err_mesg) {
    int rounds;

    if (data == NULL || data_size == 0) {
        return 0;
    }

    if (!blackcat_is_dec(data, data_size)) {
        sprintf(err_mesg, "ERROR: Invalid rounds argument for FEAL.\n");
        return 0;
    }

    rounds = atoi(data);

    if (rounds < 1 || rounds > (FEAL_MAX_ROUNDS_NR - 8)) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Invalid rounds value for FEAL.\n");
        }
        return 0;
    }

    return 1;
}

#undef FEAL_MAX_ROUNDS_NR
