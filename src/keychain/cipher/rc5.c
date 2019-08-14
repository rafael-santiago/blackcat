/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/rc5.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

#define RC5_MAX_K_NR 800

static int rc5_rounds_verifier(const char *data, const size_t data_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc5, ktask, p_layer,
                               kryptos_run_cipher(rc5, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_rc5, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc5, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(rc5, algo_params, args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *arg;

    blackcat_keychain_arg_init(algo_params, strlen(algo_params), &begin, &end);
    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, rc5_rounds_verifier);

    if (arg == NULL) {
        return 0;
    }

    args[0] = (int *) kryptos_newseg(sizeof(int));
    *(int *)args[0] = atoi(arg);

    free(arg);

    *argc = 1;

    return 1;
}

static int rc5_rounds_verifier(const char *data, const size_t data_size, char *err_mesg) {
    int rounds;

    if (data == NULL || data_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for RC5 is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(data, data_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for RC5 must be a number.\n");
        }
        return 0;
    }

    rounds = atoi(data);

    if (rounds < 1 || ((rounds + 2) << 1) > RC5_MAX_K_NR) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: RC5's rounds argument must be between 1 and %d\n", RC5_MAX_K_NR);
        }
        return 0;
    }

    return 1;
}

#undef RC5_MAX_K_NR
