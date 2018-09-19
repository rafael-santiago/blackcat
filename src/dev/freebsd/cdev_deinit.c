/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <freebsd/cdev_deinit.h>
#include <defs/types.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/systm.h>

int cdev_deinit(void) {
    if (g_cdev()->device == NULL) {
        return EFAULT;
    }

    cdev_mtx_deinit(&g_cdev()->lock);
    destroy_dev(g_cdev()->device);

    return 0;
}
