/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <libc/memcpy.h>

void *blackcat_memcpy(void *dest, void *src, size_t n) {
#if !defined(__i386__)
    unsigned char *dest_p = (unsigned char *)dest, *src_p = (unsigned char *)src;
#endif

    if (dest == NULL) {
        goto blackcat_memcpy_epilogue;
    }

#if defined(__i386__)
    __asm__ __volatile__("pusha\n\t"
                         "cld\n\t"
                         "rep movsb\n\t"
                         "popa" : : "c"(n), "D"(dest), "S"(src));
#else
    dest_p = dest;
    src_p = src;

    while (n-- > 0) {
        *dest_p = *src_p;
        dest_p++;
        src_p++;
    }
#endif

blackcat_memcpy_epilogue:

    return dest;
}
