/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <freebsd/cdev_hooks.h>

#define has_blackcat_ref(s, se) ( (se) > (s) && (se)[0] == 'b' && (se)[1] == 'l' && (se)[2] == 'a' && (se)[3] == 'c' &&\
                                                (se)[4] == 'k' && (se)[5] == 'c' && (se)[6] == 'a' && (se)[7] == 't' )

#define has_blackcat_dev_ref(s, se) ( ((se) - 4) > (s) && (se)[-4] == 'd' && (se)[-3] == 'e' && (se)[-2] == 'v' &&\
                                                          (se)[-1] == '/' )

int (*native_sys_open)(struct thread *td, struct open_args *uap) = NULL;

int (*native_sys_openat)(struct thread *td, struct openat_args *uap) = NULL;

int (*native_sys_rename)(struct thread *td, struct rename_args *uap) = NULL;

int (*native_sys_renameat)(struct thread *td, struct renameat_args *uap) = NULL;

int (*native_sys_unlink)(struct thread *td, struct unlink_args *uap) = NULL;

int (*native_sys_unlinkat)(struct thread *td, struct unlinkat_args *uap) = NULL;

static int deny_path_access(const char *filepath);

int cdev_sys_open(struct thread *td, struct open_args *uap) {
    int err = EACCES;

    if (deny_path_access(uap->path) && (uap->flags & (O_WRONLY|O_RDWR)) != 0) {
        err = EACCES;
    } else {
        err = native_sys_open(td, uap);
    }

    return err;
}

int cdev_sys_openat(struct thread *td, struct openat_args *uap) {
    int err = EACCES;

    if (deny_path_access(uap->path) && (uap->flag & (O_WRONLY|O_RDWR)) != 0) {
        err = EACCES;
    } else {
        err = native_sys_openat(td, uap);
    }

    return err;
}

int cdev_sys_rename(struct thread *td, struct rename_args *uap) {
    int err = EACCES;

    if (!deny_path_access(uap->from) && !deny_path_access(uap->to)) {
        err = native_sys_rename(td, uap);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_renameat(struct thread *td, struct renameat_args *uap) {
    int err = EACCES;

    if (!deny_path_access(uap->old) && !deny_path_access(uap->new)) {
        err = native_sys_renameat(td, uap);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_unlink(struct thread *td, struct unlink_args *uap) {
    int err = EACCES;

    uap = (struct unlink_args *)args;

    if (!deny_path_access(uap->path)) {
        err = native_sys_unlink(td, uap);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_unlinkat(struct thread *td, struct unlinkat_args *uap) {
    int err = EACCES;

    uap = (struct unlinkat_args *)args;

    if (!deny_path_access(uap->path)) {
        err = native_sys_unlinkat(td, uap);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

static int deny_path_access(const char *filepath) {
    int deny = 1;
    size_t temp_size;
    char temp[MAXPATHLEN];

    if (filepath == NULL || copyinstr(filepath, temp, MAXPATHLEN - 1, NULL) != 0) {
        goto deny_path_access_epilogue;
    }

    temp_size = strlen(temp);

    deny = has_blackcat_ref(temp, temp + temp_size - 8) &&
           !has_blackcat_dev_ref(temp, temp + temp_size - 8);

deny_path_access_epilogue:

    return deny;
}

#undef has_blackcat_ref

#undef has_blackcat_dev_ref
