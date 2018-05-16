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

void blackcat_set_keychain(blackcat_protlayer_chain_ctx **protlayer,
                           const char *algo_params, const kryptos_u8_t *key, const size_t key_size);

void blackcat_keychain_arg_init(const char *algo_params, const size_t algo_params_size, const char **begin, const char **end);

char *blackcat_keychain_arg_next(const char **begin, const char **end);

#define blackcat_keychain_verify_argv_bounds(ap, ap_end, args_nr, args_needed_nr, err_mesg) {\
    ap_end = ap + (sizeof(void *) * args_nr);\
    if (ap + (sizeof(void *) * args_needed_nr) >= ap_end) {\
        if (err_mesg != NULL) {\
            sprintf(err_mesg, "ERROR: Too much extra arguments to read. There is no space.\n");\
        }\
        return 0;\
    }\
}

#endif
