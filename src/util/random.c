/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <util/random.h>

kryptos_u8_t *random_printable_padding(size_t *size) {
    // WARN(Rafael): This function only generates random blocks from 1b up to 1Kb. However,
    //               it is enough to make harder the building of an infrastructure to promote
    //               a chosen-plaintext attack over the catalog's data.
    static kryptos_u8_t s1[62] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };
    kryptos_u8_t s2[62];
    size_t s;
    kryptos_u8_t *data, *dp, *dp_end;

    *size = kryptos_unbiased_rand_mod_u16(1025);

    if (*size == 0) {
        *size = 1;
    }

    dp = data = (kryptos_u8_t *) kryptos_newseg(*size);

    if (dp == NULL) {
        *size = 0;
        goto random_printable_padding_epilogue;
    }

    dp_end = dp + *size;

    for (s = 0; s < 62; s++) {
        s2[s] = s1[kryptos_unbiased_rand_mod_u8(62)];
    }

    while (dp != dp_end) {
        *dp = s2[kryptos_unbiased_rand_mod_u8(62)];
        dp++;
    }

random_printable_padding_epilogue:

    memset(s2, 0, sizeof(s2));

    dp = dp_end = NULL;

    return data;
}
