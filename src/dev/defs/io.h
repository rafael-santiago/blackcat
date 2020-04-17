/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_DEFS_IO_H
#define BLACKACT_DEV_DEFS_IO_H 1

#if defined(__linux__)
# include <linux/ioctl.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
# include <sys/ioccom.h>
#endif

struct blackcat_devio_ctx {
    unsigned char *data;
    size_t data_size;
};

#define BLACKCAT_IOC_MAGIC 'B'

#define BLACKCAT_BURY _IOW(BLACKCAT_IOC_MAGIC, 0, struct blackcat_devio_ctx *)
#define BLACKCAT_DIG_UP _IOW(BLACKCAT_IOC_MAGIC, 1, struct blackcat_devio_ctx *)
#define BLACKCAT_SCAN_HOOK _IO(BLACKCAT_IOC_MAGIC, 2)
#if defined(__NetBSD__)
# define BLACKCAT_MODHIDE _IO(BLACKCAT_IOC_MAGIC, 3)
#endif
#define BLACKCAT_NO_DEBUG _IO(BLACKCAT_IOC_MAGIC, 4)
#define BLACKCAT_ALLOW_DEBUG _IO(BLACKCAT_IOC_MAGIC, 5)

#endif
