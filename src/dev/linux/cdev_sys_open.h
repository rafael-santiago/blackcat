/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_LINUX_CDEV_SYS_OPEN_H
#define BLACKCAT_DEV_LINUX_CDEV_SYS_OPEN_H 1

#include <linux/fcntl.h>
#include <kook.h>

extern asmlinkage long (*native_sys_open)(const char __user *, int, mode_t);

asmlinkage long cdev_sys_open(const char __user *file, int flags, mode_t mode);

#endif
