/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <freebsd/cdev_deinit.h>
#include <freebsd/cdev_hooks.h>
#include <defs/types.h>
#include <kook.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/syscall.h>

int cdev_deinit(void) {
    if (g_cdev()->device == NULL) {
        return EFAULT;
    }

    kook(SYS_open, native_sys_open, NULL);
    kook(SYS_openat, native_sys_openat, NULL);
    kook(SYS_rename, native_sys_rename, NULL);
    kook(SYS_renameat, native_sys_renameat, NULL);
    kook(SYS_unlink, native_sys_unlink, NULL);
    kook(SYS_unlinkat, native_sys_unlinkat, NULL);

    cdev_mtx_deinit(&g_cdev()->lock);
    destroy_dev(g_cdev()->device);

    return 0;
}
