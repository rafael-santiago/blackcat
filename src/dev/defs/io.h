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
#elif defined(__FreeBSD__)
# include <sys/ioccom.h>
#endif

#define BLACKCAT_IOC_MAGIC 'B'

#define BLACKCAT_BURY_FOLDER _IOW(BLACKCAT_IOC_MAGIC, 0, unsigned char *)
#define BLACKCAT_DIG_UP_FOLDER _IOW(BLACKCAT_IOC_MAGIC, 1, unsigned char *)

#endif