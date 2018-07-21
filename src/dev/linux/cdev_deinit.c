/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/cdev_deinit.h>
#include <defs/types.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>

void cdev_deinit(void) {
    cdev_mtx_deinit(&g_cdev.lock);
    device_destroy(g_cdev.device_class, MKDEV(g_cdev.major_nr, 0));
    class_unregister(g_cdev.device_class);
    class_destroy(g_cdev.device_class);
    unregister_chrdev(g_cdev.major_nr, CDEVNAME);
}
