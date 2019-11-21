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

#define RC6_MAX_K_NR 800

static int rc6_rounds_verifier(const char *data, const size_t data_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc6_128, ktask, p_layer,
                               kryptos_run_cipher(rc6_128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_rc6_128, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_128, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc6_192, ktask, p_layer,
                               kryptos_run_cipher(rc6_192, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_rc6_192, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_192, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc6_256, ktask, p_layer,
                               kryptos_run_cipher(rc6_256, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_rc6_256, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc6_256, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(rc6, algo_params, algo_params_size, args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *arg;

    blackcat_keychain_arg_init(algo_params, algo_params_size, &begin, &end);
    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, rc6_rounds_verifier);

    if (arg == NULL) {
        return 0;
    }

    args[0] = (int *) kryptos_newseg(sizeof(int));
    *(int *)args[0] = atoi(arg);

    free(arg);

    *argc = 1;

    return 1;
}

static int rc6_rounds_verifier(const char *data, const size_t data_size, char *err_mesg) {
    int rounds;

    if (data == NULL || data_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for RC6 is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(data, data_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: Rounds argument for RC6 must be a number.\n");
        }
        return 0;
    }

    rounds = atoi(data);

    if (rounds < 1 || ((rounds + 2) << 1) > RC6_MAX_K_NR) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: RC6's rounds argument must be between 1 and %d\n", RC6_MAX_K_NR);
        }
        return 0;
    }

    return 1;
}

#undef RC6_MAX_K_NR
