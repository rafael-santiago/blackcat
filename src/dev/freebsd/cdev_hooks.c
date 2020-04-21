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

int (*native_sys_open)(struct thread *td, void *args) = NULL;

int (*native_sys_openat)(struct thread *td, void *args) = NULL;

int (*native_sys_rename)(struct thread *td, void *args) = NULL;

int (*native_sys_renameat)(struct thread *td, void *args) = NULL;

int (*native_sys_unlink)(struct thread *td, void *args) = NULL;

int (*native_sys_unlinkat)(struct thread *td, void *args) = NULL;

static int deny_path_access(const char *filepath);

int cdev_sys_open(struct thread *td, void *args) {
    struct open_args *uap;
    int err = EACCES;
    int deny;

    uap = (struct open_args *)args;

    deny = deny_path_access(uap->path);

    if (deny) {
        deny = (uap->flags & (O_WRONLY|O_RDWR));
    }

    if (!deny) {
        err = native_sys_open(td, args);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_openat(struct thread *td, void *args) {
    struct openat_args *uap;
    int err = EACCES;
    int deny;

    uap = (struct openat_args *)args;

    deny = deny_path_access(uap->path);

    if (deny) {
        deny = (uap->flag & (O_WRONLY|O_RDWR));
    }

    if (!deny) {
        err = native_sys_openat(td, args);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_rename(struct thread *td, void *args) {
    struct rename_args *uap;
    int err = EACCES;

    uap = (struct rename_args *)args;

    if (!deny_path_access(uap->from) && !deny_path_access(uap->to)) {
        err = native_sys_rename(td, args);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_renameat(struct thread *td, void *args) {
    struct renameat_args *uap;
    int err = EACCES;

    uap = (struct renameat_args *)args;

    if (!deny_path_access(uap->old) && !deny_path_access(uap->new)) {
        err = native_sys_renameat(td, args);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_unlink(struct thread *td, void *args) {
    struct unlink_args *uap;
    int err = EACCES;

    uap = (struct unlink_args *)args;

    if (!deny_path_access(uap->path)) {
        err = native_sys_unlink(td, args);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

int cdev_sys_unlinkat(struct thread *td, void *args) {
    struct unlinkat_args *uap;
    int err = EACCES;

    uap = (struct unlinkat_args *)args;

    if (!deny_path_access(uap->path)) {
        err = native_sys_unlinkat(td, args);
    } else {
        td->td_retval[0] = -1;
    }

    return err;
}

static int deny_path_access(const char *filepath) {
    int deny = 1;
    char *kfilepath = NULL;
    size_t kfilepath_size;

    if (filepath == NULL) {
        goto deny_path_access_epilogue;
    }

    kfilepath_size = strlen(filepath);

    kfilepath = (char *) malloc(kfilepath_size + 1, M_TEMP, M_NOWAIT);

    if (kfilepath == NULL) {
        goto deny_path_access_epilogue;
    }

    memset(kfilepath, 0, kfilepath_size);
    copyin(filepath, kfilepath, kfilepath_size);

    deny = has_blackcat_ref(kfilepath, kfilepath + kfilepath_size - 8) &&
           !has_blackcat_dev_ref(kfilepath, kfilepath + kfilepath_size - 8);

deny_path_access_epilogue:

    if (kfilepath != NULL) {
        free(kfilepath, M_TEMP);
    }

    return deny;
}

#undef has_blackcat_ref

#undef has_blackcat_dev_ref
