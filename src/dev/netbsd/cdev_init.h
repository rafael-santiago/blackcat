/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_NETBSD_CDEV_INIT_H
#define BLACKCAT_DEV_NETBSD_CDEV_INIT_H 1

#include <netbsd/cdev_open.h>
#include <netbsd/cdev_close.h>
#include <netbsd/cdev_ioctl.h>
#include <defs/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/systm.h>

static struct cdevsw blackcat_cdevsw = {
    .d_open = cdev_open,
    .d_close = cdev_close,
    .d_ioctl = cdev_ioctl
};

int cdev_init(void);

#endif

