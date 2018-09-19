/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/cdev_release.h>
#include <defs/types.h>

int cdev_release(struct inode *ip, struct file *fp) {
    cdev_mtx_unlock(&g_cdev()->lock);
    return 0;
}
