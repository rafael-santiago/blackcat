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

// INFO(Rafael): This code is quite sloppy. I am sorry! Moreover, it is just a helper trinket for cmd's system tests.

// WARN(Rafael): It intends to help on testing the static linkage in cmd tool. If it is broken or simply not being done,
//               the 'peacock's alarms' will show up...
//
//               Since build's bad string scanner is work on, this tool will not be allowed to hook anything relevant that
//               could configure a risk, threat, issue, etc. Thus, stderr must be clean when talking about hook messages.

#ifndef RTLD_NEXT
# define RTLD_NEXT ((void *)-1)
#endif

#define PEACOCK_ALARM(function) fprintf(stderr, "-- [" #function "] -- "\
                                                "'Somos todos piratas audazes e temerarios, terriveis e ordinarios... "\
                                                                              "copiar, colar e compilar, hey!'...\n");

#define CHOOK_BODY(func, alarm, args...) {\
    if (libc_ ## func == NULL) {\
        libc_ ## func = dlsym(RTLD_NEXT, #func);\
    }\
    /*WARN(Rafael): Do not mind about nulls... script kiddie mode on...*/\
    alarm;\
    return libc_ ## func (args);\
}

#if defined(__linux__)

static size_t (*libc_fwrite)(const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __s) = NULL;

static size_t (*libc_fread)(void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) = NULL;

static void *(*libc_memset)(void *s, int c, size_t n) = NULL;

static void *(*libc_memcpy)(void *dest, const void *src, size_t n) = NULL;

static int (*libc_memcmp)(const void *s1, const void *s2, size_t n) = NULL;

size_t fread (void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) {
    CHOOK_BODY(fread, PEACOCK_ALARM(fread), __ptr, __size, __n, __stream)
}

size_t fwrite (const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __s) {
    CHOOK_BODY(fwrite, {}, // TIP(Rafael): Otherwise you will hit the board of this universe, kid... HUahauhauha!!!
               __ptr, __size, __n, __s)
}

void *memset(void *s, int c, size_t n) {
    CHOOK_BODY(memset, PEACOCK_ALARM(memset), s, c, n)
}

void *memcpy(void *dest, const void *src, size_t n) {
    CHOOK_BODY(memcpy, PEACOCK_ALARM(memcpy), dest, src, n)
}

int memcmp(const void *s1, const void *s2, size_t n) {
    CHOOK_BODY(memcmp, PEACOCK_ALARM(memcmp), s1, s2, n)
}

#elif defined(__FreeBSD__)

static size_t (*libc_fwrite)(const void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream);

static size_t (*libc_fread)(void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream);

static void *(*libc_memset)(void *b, int c, size_t len);

static void *(*libc_memcmp)(const void *b1, const void *b2, size_t len);

static void *(*libc_memcpy)(void *dst, const void *src, size_t len);

size_t fwrite(const void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream) {
    CHOOK_BODY(fwrite, {}, ptr, size, nmemb, stream)
}

size_t fread(void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream) {
    CHOOK_BODY(fread, PEACOCK_ALARM(fread), ptr, size, nmemb, stream)
}

void *memset(void *b, int c, size_t len) {
    CHOOK_BODY(memset, PEACOCK_ALARM(memset), b, c, len)
}

void *memcmp(const  void *b1, const void *b2, size_t len) {
    CHOOK_BODY(memcmp, PEACOCK_ALARM(memcmp), b1, b2, len)
}

void *memcpy(void *dst, const void *src, size_t len) {
    CHOOK_BODY(memcpy, PEACOCK_ALARM(memcpy), dst, src, len)
}

#elif defined(__NetBSD__)

static size_t (*libc_fwrite)(const void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream);

static size_t (*libc_fread)(void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream);

static void *(*libc_memset)(void *b, int c, size_t len);

static void *(*libc_memcmp)(const void *b1, const void *b2, size_t len);

static void *(*libc_memcpy)(void *__restrict dst, const void *__restrict src, size_t len);

size_t fwrite(const void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream) {
    CHOOK_BODY(fwrite, {}, ptr, size, nmemb, stream)
}

size_t fread(void *__restrict ptr, size_t size, size_t nmemb, FILE *__restrict stream) {
    CHOOK_BODY(fread, PEACOCK_ALARM(fread), ptr, size, nmemb, stream)
}

void *memset(void *b, int c, size_t len) {
    CHOOK_BODY(memset, PEACOCK_ALARM(memset), b, c, len)
}

void *memcmp(const  void *b1, const void *b2, size_t len) {
    CHOOK_BODY(memcmp, PEACOCK_ALARM(memcmp), b1, b2, len)
}

void *memcpy(void *__restrict dst, const void *__restrict src, size_t len) {
    CHOOK_BODY(memcpy, PEACOCK_ALARM(memcpy), dst, src, len)
}

#else
# error Some code wanted.
#endif

#undef PEACOCK_ALARM
#undef HOOK_BODY
