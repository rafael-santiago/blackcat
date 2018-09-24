/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <netbsd/cdev_ioctl.h>
#include <netbsd/cdev_deinit.h>
#include <netbsd/scan_hook.h>
#include <defs/types.h>
#include <defs/io.h>
#include <icloak.h>

int cdev_ioctl(dev_t dev, u_long cmd, void *u_addr, int flag, struct lwp *lp) {
    int errno = 0;
    struct blackcat_devio_ctx *devio;

    switch (cmd) {
        case BLACKCAT_BURY:
        case BLACKCAT_DIG_UP:
            if (u_addr == NULL) {
                return EINVAL;
            }

            devio = (struct blackcat_devio_ctx *)u_addr;

            errno = (cmd == BLACKCAT_BURY) ? icloak_hide_file(devio->data) :
                                             icloak_show_file(devio->data);

            devio = NULL;
            break;

        case BLACKCAT_SCAN_HOOK:
            errno = scan_hook();
            break;

        case BLACKCAT_MODHIDE:
            if ((errno = icloak_ko(CDEVNAME)) != 0) {
                uprintf("/dev/blackcat: Unable to hide the kernel module.\n");
            }
            break;

        default:
            errno = EINVAL;
            break;
    }

    return errno;
}
