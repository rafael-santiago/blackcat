/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <memory/memory.h>
#include <unistd.h>

void *blackcat_getseg(const size_t ssize) {
    void *seg = malloc(ssize);

    if (seg == NULL) {
        printf("PANIC: no memory!\n");
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
