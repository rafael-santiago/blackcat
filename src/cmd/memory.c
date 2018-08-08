/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/memory.h>

void *blackcat_cmd_memset(void *s, int c, size_t n) {
    unsigned char *bp = (unsigned char *)s, *bp_end = (unsigned char *)s + n, b = (unsigned char) c;

    while (bp != bp_end) {
        *bp = b;
        bp++;
    }

    return s;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    unsigned char *b1 = (unsigned char *)s1, *b2 = (unsigned char *)s2;
    int result = 0;

    while (n-- > 0) {
        result |= *b1 - *b2;
        b1++;
        b2++;
    }

    return result;
}

