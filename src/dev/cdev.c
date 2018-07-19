/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#define BLACKCAT_CDEV_VERSION "0.0.1"

#if defined(__linux__)

#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Rafael Santiago");
MODULE_DESCRIPTION("Blackcat char device");
MODULE_VERSION(BLACKCAT_CDEV_VERSION);

static int __init ini(void) {
    return 0;
}

static void __exit finis(void) {
}

module_init(ini);
module_exit(finis);

#elif defined(__NetBSD__)

#include <sys/module.h>

static int blackcat_modcmd(modcmd_t cmd, void *args) {
    int error = 0;

    switch (cmd) {
        case MODULE_CMD_INIT:
            break;

        case MODULE_CMD_FINI:
            break;

        default:
            error = EOPNOTSUPP;
            break;
    }

    return error;
}

#elif defined(__FreeBSD__)

#include <mod_quiesce.h>
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/conf.h>

static int blackcat_modevent(module_t mod __unused, int event, void *arg __unused) {
    int error = 0;

    switch (event) {
        case MOD_LOAD:
            break;

        case MOD_QUIESCE:
            break;

        case MOD_UNLOAD:
            break;

        default:
            error = EOPNOTSUPP;
            break;
    }

    return error;
}

#endif

#undef BLACKCAT_DEV_VERSION
