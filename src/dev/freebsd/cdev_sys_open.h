/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_FREEBSD_CDEV_SYS_OPEN_H
#define BLACKCAT_DEV_FREEBSD_CDEV_SYS_OPEN_H 1

#include <kook.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/fcntl.h>

extern int (*native_sys_open)(struct thread *td, void *args);

extern int (*native_sys_openat)(struct thread *td, void *args);

extern int (*native_sys_readlink)(struct thread *td, void *args);

int cdev_sys_open(struct thread *td, void *args);

int cdev_sys_openat(struct thread *td, void *args);

int cdev_sys_readlink(struct thread *td, void *args);

#endif
