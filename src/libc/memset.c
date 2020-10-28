/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <libc/memset.h>

void *blackcat_memset(void *s, int c, size_t n) {
#if !defined(__i386__)
    unsigned char *sp_end, *sp;
#endif

    if (s == NULL) {
        goto blackcat_memset_epilogue;
    }

#if defined(__i386__)
    __asm__ __volatile__ ("pusha\n\t"
                          "cld\n\t"
                          "rep stosb\n\t"
                          "popa" : : "a"(c), "c"(n), "D"(s));
#else
    sp = s;
    sp_end = sp + n;

    while (sp != sp_end) {
        *sp = (unsigned char)c;
        sp++;
    }
#endif

blackcat_memset_epilogue:

    return s;
}
