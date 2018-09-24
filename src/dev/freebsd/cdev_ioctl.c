/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <freebsd/cdev_ioctl.h>
#include <freebsd/scan_hook.h>
#include <defs/io.h>
#include <icloak.h>

int cdev_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data, int flag __unused, struct thread *td __unused) {
    int error = 0;
    struct blackcat_devio_ctx *devio;

    switch (cmd) {
        case BLACKCAT_BURY:
        case BLACKCAT_DIG_UP:
            if (data == NULL) {
                return EINVAL;
            }

            devio = (struct blackcat_devio_ctx *)data;

            error = (cmd == BLACKCAT_BURY) ? icloak_hide_file(devio->data) :
                                             icloak_show_file(devio->data);

            devio = NULL;
            break;

        case BLACKCAT_SCAN_HOOK:
            error = scan_hook();
            break;

        default:
            error = EINVAL;
            break;
    }

    return error;
}
