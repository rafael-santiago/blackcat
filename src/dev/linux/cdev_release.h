/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_LINUX_CDEV_RELEASE_H
#define BLACKCAT_DEV_LINUX_CDEV_RELEASE_H 1

#include <linux/fs.h>

int cdev_release(struct inode *ip, struct file *fp);

#endif
