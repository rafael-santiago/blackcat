/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/saferk64.h>
#include <keychain/keychain.h>
#include <memory/memory.h>
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

#define SAFERK64_MAX_K_NR 800

static int saferk64_rounds_verifier(const char *data, const size_t data_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(saferk64, ktask, p_layer,
                               kryptos_run_cipher(saferk64, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_saferk64, ktask, p_layer,
                               kryptos_run_cipher_hmac(saferk64, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(saferk64, algo_params, args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *arg;

    blackcat_keychain_verify_argv_bounds(args_nr, 1, err_mesg);

    blackcat_keychain_arg_init(algo_params, strlen(algo_params), &begin, &end);
    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, saferk64_rounds_verifier);

    if (arg == NULL) {
        return 0;
    }

    args[0] = (int *) blackcat_getseg(sizeof(int));
    *(int *)args[0] = atoi(arg);

    free(arg);

    *argc = 1;

    return 1;
}

static int saferk64_rounds_verifier(const char *data, const size_t data_size, char *err_mesg) {
    int rounds;

    if (data == NULL || data_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for SAFER-K64 is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(data, data_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for SAFER-K64 must be a number.\n");
        }
        return 0;
    }

    rounds = atoi(data);

    if (rounds < 1 || rounds > SAFERK64_MAX_K_NR) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: SAFER-K64's rounds argument must be between 1 and %d\n", SAFERK64_MAX_K_NR);
        }
        return 0;
    }

    return 1;
}

#undef SAFERK64_MAX_K_NR
