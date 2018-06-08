/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <memory/memory.h>
#if defined(__linux__) || defined(__FreeBSD__)
# include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>

void *blackcat_getseg(const size_t ssize) {
    void *seg = malloc(ssize);

    if (seg == NULL) {
        fprintf(stderr, "PANIC: no memory!\n");
        exit(1);
    }

    return seg;
}

void blackcat_free(void *seg, size_t *ssize) {
    if (seg == NULL) {
        return;
    }

    if (ssize == NULL) {
        free(seg);
    } else {
        memset(seg, 0, *ssize);
        free(seg);
        *ssize = 0;
    }
}
