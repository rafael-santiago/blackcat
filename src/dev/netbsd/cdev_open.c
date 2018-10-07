/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <netbsd/cdev_open.h>
#include <defs/types.h>

int cdev_open(dev_t dev __unused, int flag __unused, int mode __unused, struct lwp *lp __unused) {
    if (!cdev_mtx_trylock(&g_cdev()->lock)) {
        return EBUSY;
    }

    return 0;
}
