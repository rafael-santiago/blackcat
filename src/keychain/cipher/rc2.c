/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/rc2.h>
#include <keychain/keychain.h>
#include <memory/memory.h>
#include <kryptos.h>
#include <stdlib.h>
#include <stdio.h>

static int rc2_T1_verifier(const char *t1, const size_t t1_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc2, ktask, p_layer,
                               kryptos_run_cipher(rc2, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc2, ktask, p_layer,
                               kryptos_run_cipher_hmac(rc2, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(rc2, algo_params, args, args_nr, key, key_size, argc, err_mesg) {
    const char *begin, *end;
    char *arg;

    blackcat_keychain_verify_argv_bounds(args_nr, 1, err_mesg);

    if (algo_params == NULL) {
        return 0;
    }

    blackcat_keychain_arg_init(algo_params, strlen(algo_params), &begin, &end);
    arg = blackcat_keychain_arg_next(&begin, end, err_mesg, rc2_T1_verifier);

    if (arg == NULL) {
        return 0;
    }

    args[0] = (int *) blackcat_getseg(sizeof(int));
    *(int *)args[0] = atoi(arg);

    free(arg);

    *argc = 1;

    return 1;
}

static int rc2_T1_verifier(const char *t1, const size_t t1_size, char *err_mesg) {
    int value;

    if (t1 == NULL || t1_size == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: T1 argument for RC2 is missing.\n");
        }
        return 0;
    }

    if (blackcat_is_dec(t1, t1_size) == 0) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: The RC2's T1 argument must be a number.\n");
        }
        return 0;
    }

    value = atoi(t1);

    if (value < 1 || value > 1025) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: The RC2's T1 argument must be between 1 and 1025.\n");
        }
        return 0;
    }

    return 1;
}
