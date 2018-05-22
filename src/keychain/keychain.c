/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/keychain.h>
#include <keychain/ciphering_schemes.h>
#include <memory/memory.h>
#include <kryptos.h>
#include <ctype.h>

static kryptos_u8_t *keychain_hash_user_weak_key(const kryptos_u8_t *key, const size_t key_size, ssize_t *wanted_size);

static kryptos_u8_t *blackcat_derive_key(const size_t algo, const kryptos_u8_t *key, const size_t key_size,
                                         size_t *derived_size);

int blackcat_set_keychain(blackcat_protlayer_chain_ctx **protlayer,
                          const char *algo_params, const kryptos_u8_t *key, const size_t key_size,
                          const size_t args_nr, char *err_mesg) {
    ssize_t algo = get_algo_index(algo_params);
    blackcat_protlayer_chain_ctx *p;
    int no_error = 1;
    blackcat_cipher_args_reader args_reader;

    if (algo == -1 || protlayer == NULL) {
        return 0;
    }

    p = (*protlayer);

    p->key = blackcat_derive_key(algo, key, key_size, &p->key_size);
    p->processor = g_blackcat_ciphering_schemes[algo].processor;
    p->is_hmac = is_hmac_processor(p->processor);
    p->mode = g_blackcat_ciphering_schemes[algo].mode;

    args_reader = g_blackcat_ciphering_schemes[algo].args;

    if (!is_null_arg_handler(args_reader)) {
        no_error = args_reader(algo_params, p->arg, args_nr, (kryptos_u8_t *)key, key_size, &p->argc, err_mesg);
    }

    return no_error;
}

void blackcat_keychain_arg_init(const char *algo_params, const size_t algo_params_size, const char **begin, const char **end) {
    if (begin == NULL || end == NULL) {
        return;
    }

    if (algo_params == NULL) {
        *begin = NULL;
        *end = NULL;
        return;
    }

    *begin = algo_params;
    *end = algo_params + algo_params_size;

    while (*begin != *end && **begin != '/' && **begin != 0) {
        (*begin) += 1;
    }

    if (*begin != *end) {
        (*begin) += (**begin == '/');
    }
}

char *blackcat_keychain_arg_next(const char **begin, const char *end, char *err_mesg,
                                 blackcat_keychain_arg_verifier verifier) {
    const char *bp, *bp_next;
    char *arg = NULL;
    size_t arg_size;

    bp = bp_next = *begin;

    if (bp == end) {
        goto blackcat_keychain_arg_next_epilogue;
    }

    while (bp_next != end && *bp_next != 0 && *bp_next != '-') {
        bp_next++;
    }

    arg_size = (bp_next - bp);
    arg = (char *) blackcat_getseg(arg_size + 1);
    memset(arg, 0, arg_size + 1);
    memcpy(arg, bp, arg_size);

    if (verifier != NULL) {
        if (verifier(arg, arg_size, err_mesg) == 0) {
            free(arg);
            arg = NULL;
            goto blackcat_keychain_arg_next_epilogue;
        }
    }

    if (bp_next != end) {
        bp_next += (*bp_next == '-');
    }

    *begin = bp_next;

blackcat_keychain_arg_next_epilogue:

    return arg;
}

int blackcat_is_dec(const char *buf, const size_t buf_size) {
    const char *bp;
    const char *bp_end;

    if (buf == NULL || buf_size == 0) {
        return 0;
    }

    bp = buf;
    bp_end = bp + buf_size;

    while (bp != bp_end) {
        if (!isdigit(*bp)) {
            return 0;
        }
        bp++;
    }

    return 1;
}

static kryptos_u8_t *blackcat_derive_key(const size_t algo, const kryptos_u8_t *key, const size_t key_size,
                                         size_t *derived_size) {
    if (key == NULL || derived_size == NULL || algo > g_blackcat_ciphering_schemes_nr) {
        return NULL;
    }

    *derived_size = g_blackcat_ciphering_schemes[algo].key_size;

    return keychain_hash_user_weak_key(key, key_size, derived_size);
}

static kryptos_u8_t *keychain_hash_user_weak_key(const kryptos_u8_t *key, const size_t key_size,
                                                 ssize_t *wanted_size) {
    kryptos_u8_t *kp = NULL;
    kryptos_task_ctx t, *ktask = &t;
    size_t kp_size, curr_size;

    if (*wanted_size == - 1) {
        kp = (kryptos_u8_t *) blackcat_getseg(key_size);
        memcpy(kp, key, key_size); // XXX(Rafael): Maybe hash it too.
        *wanted_size = key_size;
    } else {
        kp = (kryptos_u8_t *) blackcat_getseg(*wanted_size);
        kp_size = *wanted_size;

        kryptos_task_init_as_null(ktask);

        ktask->in = (kryptos_u8_t *) blackcat_getseg(key_size);
        ktask->in_size = key_size;
        memcpy(ktask->in, key, key_size);

        while (kp_size > 0) {
            kryptos_hash(sha3_512, ktask, (kryptos_u8_t *)ktask->in, ktask->in_size, 0);
            curr_size = (ktask->out_size < kp_size) ? ktask->out_size : kp_size;
            memcpy(kp, ktask->out, kp_size);
            if (ktask->in == key) {
                ktask->in = NULL;
                ktask->in_size = 0;
            }
            kryptos_task_free(ktask, KRYPTOS_TASK_IN);
            kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
            kp_size -= curr_size;
        }

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }

    return kp;
}
