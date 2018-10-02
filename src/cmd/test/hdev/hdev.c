/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#if defined(__linux__)
#include <linux/init.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <kook.h>

MODULE_LICENSE("GPL");

static int (*sys_write)(int fd, const void *buf, size_t count) = NULL;

static ssize_t (*sys_read)(int fd, void *buf, size_t len) = NULL;

static ssize_t hook_read(int fd, void *buf, size_t len);

static int hook_write(int fd, const void *buf, size_t count);

static int __init hook_ini(void) {
    kook(__NR_read, hook_read, (void *)&sys_read);
    kook(__NR_write, hook_write, (void *)&sys_write);
    return 0;
}

static void __exit hook_finis(void) {
    kook(__NR_read, sys_read, NULL);
    kook(__NR_write, sys_write, NULL);
}

static ssize_t hook_read(int fd, void *buf, size_t len) {
    return sys_read(fd, buf, len);
}

static int hook_write(int fd, const void *buf, size_t count) {
    return sys_write(fd, buf, count);
}

module_init(hook_ini);

module_exit(hook_finis);

#elif defined(__FreeBSD__)

#elif defined(__NetBSD__)

#endif
