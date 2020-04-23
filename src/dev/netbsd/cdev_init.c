/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <netbsd/cdev_init.h>
#include <netbsd/cdev_deinit.h>
#include <netbsd/cdev_hooks.h>
#include <icloak.h>
#include <kook.h>
#include <sys/syscall.h>

int cdev_init(void) {
    int errno = 0;
    int bmajor = -1, cmajor = CDEV_MAJOR_NR;

    cdev_mtx_init(&g_cdev()->lock);

    if ((errno = devsw_attach(CDEVNAME, NULL, &bmajor, &blackcat_cdevsw, &cmajor)) != 0) {
        cdev_mtx_deinit(&g_cdev()->lock);
    }

    // INFO(Rafael): This code is impossible to be executed here in NetBSD, so we will hide the module
    //               through a specific ioctl call.

    /*
    if (icloak_ko(CDEVNAME) != 0) {
        uprintf("/dev/blackcat: Unable to hide the kernel module.\n");
        cdev_deinit();
        return 1;
    }
    */

    kook(SYS_open, cdev_sys_open, (void **)&native_sys_open);
    kook(SYS_openat, cdev_sys_openat, (void **)&native_sys_openat);
    kook(SYS_unlink, cdev_sys_unlink, (void **)&native_sys_unlink);
    kook(SYS_unlinkat, cdev_sys_unlinkat, (void **)&native_sys_unlinkat);
    kook(SYS_rename, cdev_sys_rename, (void **)&native_sys_rename);
    kook(SYS_renameat, cdev_sys_renameat, (void **)&native_sys_renameat);

    return errno;
}
