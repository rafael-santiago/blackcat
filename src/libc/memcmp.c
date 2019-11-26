/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <libc/memcmp.h>

int blackcat_memcmp(const void *s1, const void *s2, size_t n) {
    // WARN(Rafael): It is important to make this function constant-time in order to mitigate timing attacks.
    //               No performance improvements here, please, any earthworm would know that the following
    //               code is inefficient.
    const unsigned char *p1 = (unsigned char *)s1, *p2 = (unsigned char *)s2;
    int result = 0;

    while (n-- > 0) {
        result |= (*p1) - (*p2);
        p1++;
        p2++;
    }

    return result;
}
