/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_H
#define BLACKCAT_KEYCHAIN_H 1

#include <basedefs/defs.h>
#include <kryptos_types.h>

int blackcat_set_keychain(blackcat_protlayer_chain_ctx **protlayer,
                          const char *algo_params, const kryptos_u8_t *key, const size_t key_size,
                          const size_t args_nr,
                          blackcat_hash_processor hash,
                          char *err_mesg);

void blackcat_keychain_arg_init(const char *algo_params, const size_t algo_params_size, const char **begin, const char **end);

typedef int (*blackcat_keychain_arg_verifier)(const char *arg, const size_t arg_size, char *err_mesg);

char *blackcat_keychain_arg_next(const char **begin, const char *end, char *err_mesg, blackcat_keychain_arg_verifier verifier);

int blackcat_is_dec(const char *buf, const size_t buf_size);

#define blackcat_keychain_verify_argv_bounds(args_nr, args_needed_nr, err_mesg) {\
    if (args_nr < args_needed_nr) {\
        if (err_mesg != NULL) {\
            sprintf(err_mesg, "ERROR: Too much extra arguments to read. There is no space.\n");\
        }\
        return 0;\
    }\
}

#endif
