/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/kdf/kdf_utils.h>
#include <kryptos.h>

char *blackcat_kdf_usr_params_get_next(const char *usr_params, const size_t usr_params_size,
                                       char **usr_params_next, size_t *out_size, size_t *delta_offset) {
    const char *up, *up_end;
    char *out;

    if (usr_params == NULL || usr_params_size == 0 || usr_params_next == NULL || out_size == NULL || delta_offset == NULL) {
        if (out_size != NULL) {
            *out_size = 0;
        }
        return NULL;
    }

    up = usr_params;
    up_end = up + usr_params_size - *delta_offset;

    if (*up == 0 || up == up_end) {
        *out_size = 0;
        return NULL;
    }

    while (up != up_end && *up != ':') {
        up++;
    }

    *out_size = up - usr_params;
    out = (char *) kryptos_newseg(*out_size + 1);
    memset(out, 0, *out_size + 1);
    memcpy(out, usr_params, *out_size);

    (*usr_params_next) = (up != up_end) ? (char *)(up + (*up == ':')) : NULL;

    if (*usr_params_next != NULL) {
        (*delta_offset) += *out_size + (*up == ':');
    }

    return out;
}

void del_blackcat_kdf_clockwork_ctx(struct blackcat_kdf_clockwork_ctx *kdf_clockwork) {
    size_t a;

    if (kdf_clockwork == NULL) {
        return;
    }

    for (a = 0; a < BLACKCAT_KDF_ARGS_NR && kdf_clockwork->arg_data[a] != NULL; a++) {
        if (kdf_clockwork->arg_size[a] > 0) {
            kryptos_freeseg(kdf_clockwork->arg_data[a], kdf_clockwork->arg_size[a]);
            kdf_clockwork->arg_size[a] = 0;
        } else {
            kdf_clockwork->arg_data[a] = NULL; // INFO(Rafael): Static data.
        }
    }

    kryptos_freeseg(kdf_clockwork, sizeof(struct blackcat_kdf_clockwork_ctx));
}
