/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/cdev_deinit.h>
#include <linux/cdev_hooks.h>
#include <defs/types.h>
#include <kook.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/unistd.h>

void cdev_deinit(void) {
    cdev_mtx_deinit(&g_cdev()->lock);
    kook(__NR_unlink, native_sys_unlink, NULL);
    kook(__NR_unlinkat, native_sys_unlinkat, NULL);
    kook(__NR_rename, native_sys_rename, NULL);
    kook(__NR_renameat, native_sys_renameat, NULL);
    kook(__NR_renameat2, native_sys_renameat2, NULL);
    kook(__NR_open, native_sys_open, NULL);
    kook(__NR_openat, native_sys_openat, NULL);
    kook(__NR_creat, native_sys_creat, NULL);
    device_destroy(g_cdev()->device_class, MKDEV(g_cdev()->major_nr, 0));
    class_unregister(g_cdev()->device_class);
    class_destroy(g_cdev()->device_class);
    unregister_chrdev(g_cdev()->major_nr, CDEVNAME);
}
