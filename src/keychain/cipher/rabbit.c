/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/rabbit.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <stdio.h>

static int rabbit_iv64_verifier(const char *iv, const size_t iv_size, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(rabbit, ktask, p_layer,
                               kryptos_run_cipher(rabbit, *ktask, p_layer->key, p_layer->key_size,
                                                  (kryptos_u8_t *)p_layer->arg[0]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(rabbit, algo_params, args, args_nr, key, key_size, argc, err_mesg) {
    void *ap = args, *ap_end;
    const char *begin, *end;

    blackcat_keychain_verify_argv_bounds(args_nr, 1, err_mesg);

    blackcat_keychain_arg_init(algo_params, strlen(algo_params), &begin, &end);
    args[0] = blackcat_keychain_arg_next(&begin, end, err_mesg, rabbit_iv64_verifier);

    if (args[0] == NULL) {
        return 0;
    }

    *argc = 1;

    return 1;
}

static int rabbit_iv64_verifier(const char *iv, const size_t iv_size, char *err_mesg) {
    if (iv == NULL && err_mesg != NULL) {
        sprintf(err_mesg, "ERROR: iv64 argument for RABBIT is missing.\n");
        return 0;
    }

    if (iv_size != 8) {
        if (err_mesg != NULL) {
            sprintf(err_mesg, "ERROR: iv64 argument for RABBIT must have 64-bits.\n");
        }
        return 0;
    }

    return 1;
}
