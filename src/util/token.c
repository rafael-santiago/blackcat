/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <util/token.h>

int token_wrap(kryptos_u8_t **key, size_t *key_size, const kryptos_u8_t *token, const size_t token_size) {
    const kryptos_u8_t *tp, *tp_mid, *tp_end;
    kryptos_u8_t *kp;
    size_t kp_size, first_half_size;
    int no_error = 1;

    if (token == NULL || token_size == 0 || key == NULL || key_size == NULL) {
        return 0;
    }

    tp = token;
    tp_mid = tp + (token_size >> 1);
    tp_end = tp + token_size;

    kp_size = *key_size + token_size;

    kp = (kryptos_u8_t *) kryptos_newseg(kp_size);

    if (kp == NULL) {
        no_error = 0;
        goto token_wrap_epilogue;
    }

    first_half_size = tp_mid - tp;
    memcpy(kp, tp, first_half_size);

    if (*key != NULL && *key_size > 0) {
        memcpy(kp + first_half_size, *key, *key_size);
    }

    memcpy(kp + first_half_size + *key_size, tp_mid, tp_end - tp_mid);

    if (*key != NULL) {
        kryptos_freeseg(*key, *key_size);
    }

    *key = kp;
    *key_size = kp_size;

    kp = NULL;

token_wrap_epilogue:

    tp = tp_mid = tp_end = NULL;

    first_half_size = 0;

    if (kp == NULL) {
        kp_size = 0;
    } else {
        kryptos_freeseg(kp, kp_size);
        kp_size = 0;
    }

    return no_error;
}
