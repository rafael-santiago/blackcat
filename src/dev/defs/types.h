/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#ifndef BLACKCAT_DEV_DEFS_TYPES_H
#define BLACKCAT_DEV_DEFS_TYPES_H 1

#if defined(__linux__)
# include <linux/mutex.h>
  typedef struct mutex cdev_mtx;
# define cdev_mtx_init(m) mutex_init((m))
# define cdev_mtx_trylock(m) mutex_trylock((m))
# define cdev_mtx_unlock(m) mutex_unlock((m))
# define cdev_mtx_deinit(m) mutex_destroy((m))
#elif defined(__FreeBSD__)
# include <sys/lock.h>
# include <sys/mutex.h>
  typedef struct mtx cdev_mtx;
# define cdev_mtx_init(m) mtx_init((m), "BLACKCAT_CDEV", NULL, MTX_DEF)
# define cdev_mtx_trylock(m) mtx_trylock((m))
# define cdev_mtx_unlock(m) mtx_unlock((m))
# define cdev_mtx_deinit(m) mtx_destroy((m))
#elif defined(__NetBSD__)
# include <sys/mutex.h>
  typedef struct kmutex_t cdev_mtx;
# define cdev_mtx_init(m) mutex_init((m), MUTEX_DEFAULT, IPL_NONE)
# define cdev_mtx_trylock(m) mutex_tryenter((m))
# define cdev_mtx_unlock(m) mutex_exit((m))
# define cdev_mtx_deinit(m) mutex_destroy((m))
#endif

struct cdev_ctx {
#if defined(__linux__)
    int major_nr;
    struct class *device_class;
    struct device *device;
#elif defined(__FreeBSD__)
    struct cdev *device;
#endif
    cdev_mtx lock;
};

static struct cdev_ctx g_cdev;

#define CDEVNAME "blackcat"
#define CDEVCLASS "bcd"

#endif
