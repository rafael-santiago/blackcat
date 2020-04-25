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
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/fcntl.h>

extern int (*native_sys_open)(struct thread *td, struct open_args *uap);

extern int (*native_sys_openat)(struct thread *td, struct openat_args *uap);

extern int (*native_sys_rename)(struct thread *td, struct rename_args *uap);

extern int (*native_sys_renameat)(struct thread *td, struct renameat_args *uap);

extern int (*native_sys_unlink)(struct thread *td, struct unlink_args *uap);

extern int (*native_sys_unlinkat)(struct thread *td, struct unlinkat_args *uap);

int cdev_sys_open(struct thread *td, struct open_args *uap);

int cdev_sys_openat(struct thread *td, struct openat_args *uap);

int cdev_sys_rename(struct thread *td, struct rename_args *uap);

int cdev_sys_renameat(struct thread *td, struct renameat_args *uap);

int cdev_sys_unlink(struct thread *td, struct unlink_args *uap);

int cdev_sys_unlinkat(struct thread *td, struct unlinkat_args *uap);

#endif
