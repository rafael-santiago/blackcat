/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/cdev_ioctl.h>
#include <linux/scan_hook.h>
#include <defs/io.h>
#include <icloak.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

long cdev_ioctl(struct file *fp, unsigned int cmd, unsigned long user_param) {
    int error = 0;
    size_t data_size;
    char data[4096];

    switch (cmd) {
        case BLACKCAT_BURY:
        case BLACKCAT_DIG_UP:
            if ((void *)user_param == NULL || !access_ok(VERIFY_READ, (void __user *)user_param, _IOC_SIZE(cmd))) {
                return -EFAULT;
            }

            data_size = strlen((unsigned char *)user_param);

            if (data_size > sizeof(data)) {
                return -EINVAL;
            }

            memset(data, 0, sizeof(data));

            if (copy_from_user(data, (unsigned char *)user_param, data_size) != 0) {
                return -EFAULT;
            }

            error = (cmd == BLACKCAT_BURY) ? icloak_hide_file(data) :
                                             icloak_show_file(data);

            memset(data, 0, sizeof(data));
            break;

        case BLACKCAT_SCAN_HOOK:
            error = scan_hook();
            break;

        default:
            error = -EINVAL;
            break;
    }

    return error;
}
