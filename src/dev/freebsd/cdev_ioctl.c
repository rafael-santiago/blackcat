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
    size_t data_size;
    char temp[4096];

    switch (cmd) {
        case BLACKCAT_BURY_FOLDER:
        case BLACKCAT_DIG_UP_FOLDER:
            if (data == NULL) {
                return EINVAL;
            }

            data_size = strlen((char *)data);

            if (data_size > sizeof(temp) - 1) {
                return EINVAL;
            }

            memset(temp, 0, sizeof(data));
            memcpy(temp, (char *)data, data_size);

            error = (cmd == BLACKCAT_BURY_FOLDER) ? icloak_hide_file(temp) :
                                                    icloak_show_file(temp);

            memset(temp, 0, data_size);
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
