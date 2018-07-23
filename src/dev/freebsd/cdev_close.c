/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <freebsd/cdev_close.h>
#include <defs/types.h>

int cdev_close(struct cdev *dev __unused, int flags __unused, int devtype __unused, struct thread *td __unused) {
    cdev_mtx_unlock(&g_cdev.lock);
    return 0;
}