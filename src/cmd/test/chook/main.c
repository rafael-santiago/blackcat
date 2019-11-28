/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

// WARN(Rafael): This code is a trinket to help on testing the static linkage in cmd tool. If it is broken or simply not done
//               the 'peacock's alarms' will show up...
//
//               Since build's bad string scanner is work on, this tool will not allowed to hook anything relevant that
//               could configure a risk, threat, issue, etc. Thus, stderr must be clean when talking about hook messages.

#ifndef RTLD_NEXT
# define RTLD_NEXT ((void *)-1)
#endif

#define PEACOCK_ALARM(function) fprintf(stderr, "-- [" #function "] -- "\
                                                "'Somos todos piratas audazes e temerarios, terriveis e ordinarios... "\
                                                                              "copiar, colar e compilar, hey!'...\n");

#define HOOK_BODY(func, args...) {\
    if (libc_ ## func == NULL) {\
        libc_ ## func = dlsym(RTLD_NEXT, #func);\
    }\
    /*WARN(Rafael): Do not mind about nulls... script kiddie mode on...*/\
    PEACOCK_ALARM(func)\
    return libc_ ## func (args);\
}

#if defined(__linux__)

size_t (*libc_fwrite)(const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __s) = NULL;

size_t (*libc_fread)(void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) = NULL;

void *(*libc_memset)(void *s, int c, size_t n) = NULL;

void *(*libc_memcpy)(void *dest, const void *src, size_t n) = NULL;

int (*libc_memcmp)(const void *s1, const void *s2, size_t n) = NULL;


size_t fread (void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) {
    HOOK_BODY(fread, __ptr, __size, __n, __stream)
}

size_t fwrite (const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __s) {
    HOOK_BODY(fwrite, __ptr, __size, __n, __s)
}

void *memset(void *s, int c, size_t n) {
    HOOK_BODY(memset, s, c, n)
}

void *memcpy(void *dest, const void *src, size_t n) {
    HOOK_BODY(memcpy, dest, src, n)
}

int memcmp(const void *s1, const void *s2, size_t n) {
    HOOK_BODY(memcmp, s1, s2, n)
}

#else
# error Some code wanted.
#endif

