/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_NETBSD_CDEV_HOOKS_H
#define BLACKCAT_DEV_NETBSD_CDEV_HOOKS_H 1

#include <kook.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/syscallargs.h>
#include <sys/syscall.h>
#include <sys/fcntl.h>

extern int (*native_sys_open)(struct lwp *lp, struct sys_open_args *uap, register_t *rp);

extern int (*native_sys_openat)(struct lwp *lp, struct sys_openat_args *uap, register_t *rp);

extern int (*native_sys_rename)(struct lwp *lp, struct sys_rename_args *uap, register_t *rp);

extern int (*native_sys_renameat)(struct lwp *lp, struct sys_renameat_args *uap, register_t *rp);

extern int (*native_sys_unlink)(struct lwp *lp, struct sys_unlink_args *uap, register_t *rp);

extern int (*native_sys_unlinkat)(struct lwp *lp, struct sys_unlinkat_args *uap, register_t *rp);

int cdev_sys_open(struct lwp *lp, struct sys_open_args *uap, register_t *rp);

int cdev_sys_openat(struct lwp *lp, struct sys_openat_args *uap, register_t *rp);

int cdev_sys_rename(struct lwp *lp, struct sys_rename_args *uap, register_t *rp);

int cdev_sys_renameat(struct lwp *lp, struct sys_renameat_args *uap, register_t *rp);

int cdev_sys_unlink(struct lwp *lp, struct sys_unlink_args *uap, register_t *rp);

int cdev_sys_unlinkat(struct lwp *lp, struct sys_unlinkat_args *uap, register_t *rp);

#endif
