/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/cdev_hooks.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define has_blackcat_ref(s, se) ( (se) > (s) && (se)[0] == 'b' && (se)[1] == 'l' && (se)[2] == 'a' && (se)[3] == 'c' &&\
                                                (se)[4] == 'k' && (se)[5] == 'c' && (se)[6] == 'a' && (se)[7] == 't' )

#define has_blackcat_dev_ref(s, se) ( ((se) - 4) > (s) && (se)[-4] == 'd' && (se)[-3] == 'e' && (se)[-2] == 'v' &&\
                                                          (se)[-1] == '/' )

asmlinkage long (*native_sys_open)(const char __user *, int, umode_t) = NULL;

asmlinkage long (*native_sys_openat)(int, const char __user *, int, umode_t) = NULL;

asmlinkage long (*native_sys_creat)(const char __user *, umode_t) = NULL;

asmlinkage long (*native_sys_unlink)(const char __user *) = NULL;

asmlinkage long (*native_sys_unlinkat)(int, const char __user *, int) = NULL;

asmlinkage long (*native_sys_rename)(const char __user *, const char __user *) = NULL;

asmlinkage long (*native_sys_renameat)(int, const char __user *, int, const char __user *) = NULL;

asmlinkage long (*native_sys_renameat2)(int, const char __user *, int, const char __user *, unsigned int) = NULL;

static int deny_path_access(const char __user *path);

asmlinkage long cdev_sys_unlink(const char __user *pathname) {
    int err = -EACCES;

    if (pathname != NULL && !deny_path_access(pathname)) {
        err = native_sys_unlink(pathname);
    }

    return err;
}

asmlinkage long cdev_sys_unlinkat(int dirfd, const char __user *pathname, int flags) {
    int err = -EACCES;

    if (pathname != NULL && !deny_path_access(pathname)) {
        err = native_sys_unlinkat(dirfd, pathname, flags);
    }

    return err;
}

asmlinkage long cdev_sys_rename(const char __user *oldpath, const char __user *newpath) {
    int err = -EACCES;

    if (oldpath != NULL && !deny_path_access(oldpath) &&
        newpath != NULL && !deny_path_access(newpath)) {
        err = native_sys_rename(oldpath, newpath);
    }

    return err;
}

asmlinkage long cdev_sys_renameat(int olddirfd, const char __user *oldpath, int newdirfd, const char __user *newpath) {
    int err = -EACCES;

    if (oldpath != NULL && !deny_path_access(oldpath) &&
        newpath != NULL && !deny_path_access(newpath)) {
        err = native_sys_renameat(olddirfd, oldpath, newdirfd, newpath);
    }

    return err;
}

asmlinkage long cdev_sys_renameat2(int olddirfd, const char __user *oldpath, int newdirfd, const char __user *newpath,
                                   unsigned int flags) {
    int err = -EACCES;

    if (oldpath != NULL && !deny_path_access(oldpath) &&
        newpath != NULL && !deny_path_access(newpath)) {
        err = native_sys_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
    }

    return err;
}

asmlinkage long cdev_sys_open(const char __user *pathname, int flags, umode_t mode) {
    int fd = -EACCES;
    int deny = (pathname != NULL && deny_path_access(pathname));

    if (deny) {
        deny = (mode == 0) || (mode & (O_WRONLY|O_RDWR));
    }

    if (!deny) {
        fd = native_sys_open(pathname, flags, mode);
    }

    return fd;
}

asmlinkage long cdev_sys_openat(int dfd, const char __user *pathname, int flags, umode_t mode) {
    int fd = -EACCES;
    int deny = (pathname != NULL && deny_path_access(pathname));

    if (deny) {
        deny = (mode == 0) || (mode & (O_WRONLY|O_RDWR));
    }

    if (!deny) {
        fd = native_sys_openat(dfd, pathname, flags, mode);
    }

    return fd;
}

asmlinkage long cdev_sys_creat(const char __user *pathname, mode_t mode) {
    int fd = -EACCES;

    if (pathname != NULL && !deny_path_access(pathname)) {
        fd = native_sys_creat(pathname, mode);
    }

    return fd;
}

static int deny_path_access(const char __user *path) {
    char *kpathname = NULL;
    size_t kpathname_size;
    const char *fp_end;
    int deny = 0;

    if (path == NULL) {
        goto deny_path_access_epilogue;
    }

    fp_end = path;
    while (*fp_end != 0) {
        fp_end++;
    }

    kpathname_size = fp_end - path;

    kpathname = (char *) kmalloc(kpathname_size + 1, GFP_ATOMIC);
    if (kpathname == NULL) {
        goto deny_path_access_epilogue;
    }

    memset(kpathname, 0, kpathname_size + 1);
    memcpy(kpathname, path, kpathname_size);

    deny = has_blackcat_ref(kpathname, kpathname + kpathname_size - 8) &&
           !has_blackcat_dev_ref(kpathname, kpathname + kpathname_size - 8);

deny_path_access_epilogue:

    if (kpathname != NULL) {
        kfree(kpathname);
    }

    return deny;
}

#undef has_blackcat_ref

#undef has_blackcat_dev_ref
