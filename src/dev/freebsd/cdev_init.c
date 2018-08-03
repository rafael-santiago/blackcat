/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <freebsd/cdev_init.h>
#include <freebsd/cdev_open.h>
#include <freebsd/cdev_ioctl.h>
#include <freebsd/cdev_close.h>
#include <freebsd/cdev_deinit.h>
#include <defs/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/systm.h>

static struct cdevsw blackcat_cdevsw = {
    .d_version = D_VERSION,
    .d_open = cdev_open,
    .d_ioctl = cdev_ioctl,
    .d_close = cdev_close,
    .d_name = CDEVNAME
};

int cdev_init(void) {
    int error = 0;

    cdev_mtx_init(&g_cdev.lock);

    g_cdev.device = make_dev(&blackcat_cdevsw, 0, UID_ROOT, GID_WHEEL, 0666, CDEVNAME);

    if (g_cdev.device == NULL) {
        cdev_mtx_deinit(&g_cdev.lock);
        error = EFAULT;
    }

    if (icloak_ko(CDEVNAME) != 0) {
        uprintf("/dev/blackcat: Unable to hide the kernel module.\n");
        cdev_deinit();
        return 1;
    }

    return error;
}
