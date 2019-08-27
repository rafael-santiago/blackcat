/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_KDF_KDF_UTILS_H
#define BLACKCAT_KEYCHAIN_KDF_KDF_UTILS_H 1

#include <basedefs/defs.h>

char *blackcat_kdf_usr_params_get_next(const char *usr_params, const size_t usr_params_size,
                                       char **usr_params_next, size_t *out_size, size_t *delta_offset);

#define new_blackcat_kdf_clockwork_ctx(c, esc_stmt) {\
    (c) = (struct blackcat_kdf_clockwork_ctx *) kryptos_newseg(sizeof(struct blackcat_kdf_clockwork_ctx));\
    if ((c) == NULL) {\
        esc_stmt;\
    }\
    (c)->kdf = NULL;\
    memset((c)->arg_data, 0, (sizeof((c)->arg_data) / sizeof((c)->arg_data[0])) * sizeof((c)->arg_data[0]));\
    memset((c)->arg_size, 0, (sizeof((c)->arg_size) / sizeof((c)->arg_size[0])) * sizeof((c)->arg_size[0]));\
}

void del_blackcat_kdf_clockwork_ctx(struct blackcat_kdf_clockwork_ctx *kdf_clockwork);

struct blackcat_kdf_clockwork_ctx *get_kdf_clockwork(const char *usr_params, const size_t usr_params_size, char *error);

char *get_kdf_usr_params(const struct blackcat_kdf_clockwork_ctx *kdf_clockwork, size_t *out_size);

#endif
