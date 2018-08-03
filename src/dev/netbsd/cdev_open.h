/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_NETBSD_CDEV_OPEN_H
#define BLACKCAT_DEV_NETBSD_CDEV_OPEN_H 1

#include <sys/module.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>

dev_type_open(cdev_open);

#endif
