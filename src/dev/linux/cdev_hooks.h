/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_LINUX_CDEV_HOOKS_H
#define BLACKCAT_DEV_LINUX_CDEV_HOOKS_H 1

#include <linux/fcntl.h>
#include <kook.h>

extern asmlinkage long (*native_sys_open)(const char __user *, int, umode_t);

extern asmlinkage long (*native_sys_openat)(int, const char __user *, int, umode_t);

extern asmlinkage long (*native_sys_creat)(const char __user *, umode_t);

extern asmlinkage long (*native_sys_unlink)(const char __user *);

extern asmlinkage long (*native_sys_unlinkat)(int, const char __user *, int);

extern asmlinkage long (*native_sys_rename)(const char __user *, const char __user *);

extern asmlinkage long (*native_sys_renameat)(int, const char __user *, int, const char __user *);

extern asmlinkage long (*native_sys_renameat2)(int, const char __user *, int, const char __user *, unsigned int);

asmlinkage long cdev_sys_open(const char __user *pathname, int flags, umode_t mode);

asmlinkage long cdev_sys_openat(int dfd, const char __user *pathname, int flags, umode_t mode);

asmlinkage long cdev_sys_creat(const char __user *file, umode_t mode);

asmlinkage long cdev_sys_unlink(const char __user *pathname);

asmlinkage long cdev_sys_unlinkat(int dirfd, const char __user *pathname, int flags);

asmlinkage long cdev_sys_rename(const char __user *oldpath, const char __user *newpath);

asmlinkage long cdev_sys_renameat(int olddir, const char __user *oldpath, int newdirfd, const char __user *newpath);

asmlinkage long cdev_sys_renameat2(int olddirfd, const char __user *oldpath, int newdirfd, const char __user *newpath,
                                   unsigned int flags);

#endif
