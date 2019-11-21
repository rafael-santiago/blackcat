/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/xtea.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

static int xtea_rounds_verifier(const char *data, const size_t data_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(xtea, ktask, p_layer,
                               kryptos_run_cipher(xtea, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_xtea, ktask, p_layer,
                               kryptos_run_cipher_hmac(xtea, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(xtea, algo_params, algo_params_size, args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *arg;

    blackcat_keychain_verify_argv_bounds(args_nr, 1, err_mesg);

    blackcat_keychain_arg_init(algo_params, algo_params_size, &begin, &end);
    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, xtea_rounds_verifier);

    if (arg == NULL) {
        return 0;
    }

    args[0] = (int *) kryptos_newseg(sizeof(int));
    *(int *)args[0] = atoi(arg);
    free(arg);

    *argc = 1;

    return 1;
}

static int xtea_rounds_verifier(const char *data, const size_t data_size, char *err_mesg) {
    int rounds;

    if (data == NULL || data_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for XTEA is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(data, data_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for XTEA must be a number.\n");
        }
        return 0;
    }

    rounds = atoi(data);

    if (rounds < 1) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: XTEA's rounds argument must be greater than zero.\n");
        }
        return 0;
    }

    return 1;
}
