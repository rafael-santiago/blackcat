/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <defs/types.h>

static struct cdev_ctx g_cdev_data;

struct cdev_ctx *g_cdev(void) {
    return &g_cdev_data;
}
