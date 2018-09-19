/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <netbsd/cdev_deinit.h>
#include <netbsd/cdev_init.h>

int cdev_deinit(void) {
    cdev_mtx_deinit(&g_cdev()->lock);
    return devsw_detach(NULL, &blackcat_cdevsw);
}
