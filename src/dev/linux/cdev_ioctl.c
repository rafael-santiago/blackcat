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
#include <kook.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

long cdev_ioctl(struct file *fp, unsigned int cmd, unsigned long user_param) {
    int error = 0;
    struct blackcat_devio_ctx devio;

    switch (cmd) {
        case BLACKCAT_BURY:
        case BLACKCAT_DIG_UP:
            if ((void *)user_param == NULL || !access_ok(VERIFY_READ, (void __user *)user_param, _IOC_SIZE(cmd))) {
                return -EFAULT;
            }

            if (copy_from_user(&devio,
                               (struct blackcat_devio_ctx *)user_param, sizeof(struct blackcat_devio_ctx)) != 0) {
                return -EFAULT;
            }

            error = (cmd == BLACKCAT_BURY) ? icloak_hide_file(devio.data) :
                                             icloak_show_file(devio.data);

            memset(&devio, 0, sizeof(struct blackcat_devio_ctx));
            break;

        case BLACKCAT_SCAN_HOOK:
            error = scan_hook();
            break;

        /*
        case BLACKCAT_NO_DEBUG:
            error = (native_sys_open == NULL) ? kook(__NR_open, cdev_sys_open, (void **)&native_sys_open) : 0;
            break;

        case BLACKCAT_ALLOW_DEBUG:
            error = (native_sys_open != NULL) ? kook(__NR_open, native_sys_open, NULL) : 0;
            if (error == 0 && native_sys_open != NULL) {
                native_sys_open = NULL;
            }
            break;
        */

        default:
            error = -EINVAL;
            break;
    }

    return error;
}
