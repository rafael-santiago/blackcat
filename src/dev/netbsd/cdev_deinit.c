/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <netbsd/cdev_deinit.h>
#include <netbsd/cdev_init.h>
#include <netbsd/cdev_hooks.h>
#include <kook.h>
#include <sys/syscall.h>

int cdev_deinit(void) {
    cdev_mtx_deinit(&g_cdev()->lock);
    kook(SYS_open, native_sys_open, NULL);
    kook(SYS_openat, native_sys_openat, NULL);
    kook(SYS_unlink, native_sys_unlink, NULL);
    kook(SYS_unlinkat, native_sys_unlinkat, NULL);
    kook(SYS_rename,  native_sys_rename, NULL);
    kook(SYS_renameat, native_sys_renameat, NULL);
    return devsw_detach(NULL, &blackcat_cdevsw);
}
