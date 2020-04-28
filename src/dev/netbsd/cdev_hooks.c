/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <netbsd/cdev_hooks.h>

#define has_blackcat_ref(s, se) ( (se) > (s) && (se)[0] == 'b' && (se)[1] == 'l' && (se)[2] == 'a' && (se)[3] == 'c' &&\
                                                (se)[4] == 'k' && (se)[5] == 'c' && (se)[6] == 'a' && (se)[7] == 't' )

#define has_blackcat_dev_ref(s, se) ( ((se) - 4) > (s) && (se)[-4] == 'd' && (se)[-3] == 'e' && (se)[-2] == 'v' &&\
                                                          (se)[-1] == '/' )

#define has_blackcat_kmod_ref(s, se) ( (se) > (s) && (se)[ 0] == 'b' && (se)[ 1] == 'l' && (se)[ 2] == 'a' &&\
                                                     (se)[ 3] == 'c' && (se)[ 4] == 'k' && (se)[ 5] == 'c' &&\
                                                     (se)[ 6] == 'a' && (se)[ 7] == 't' && (se)[ 8] == '.' &&\
                                                     (se)[ 9] == 'k' && (se)[10] == 'm' && (se)[11] == 'o' && (se)[12] == 'd' )


int (*native_sys_open)(struct lwp *lp, struct sys_open_args *uap, register_t *rp) = NULL;

int (*native_sys_openat)(struct lwp *lp, struct sys_openat_args *uap, register_t *rp) = NULL;

int (*native_sys_rename)(struct lwp *lp, struct sys_rename_args *uap, register_t *rp) = NULL;

int (*native_sys_renameat)(struct lwp *lp, struct sys_renameat_args *uap, register_t *rp) = NULL;

int (*native_sys_unlink)(struct lwp *lp, struct sys_unlink_args *uap, register_t *rp) = NULL;

int (*native_sys_unlinkat)(struct lwp *lp, struct sys_unlinkat_args *uap, register_t *rp) = NULL;

static int deny_path_access(const char *filepath);

int cdev_sys_open(struct lwp *lp, struct sys_open_args *uap, register_t *rp) {
    int err = EACCES;

    if (deny_path_access(SCARG(uap, path)) && (SCARG(uap, flags) & (O_WRONLY|O_RDWR)) != 0) {
        err = EACCES;
        *rp = -1;
    } else {
        err = native_sys_open(lp, uap, rp);
    }

    return err;
}

int cdev_sys_openat(struct lwp *lp, struct sys_openat_args *uap, register_t *rp) {
    int err = EACCES;

    if (deny_path_access(SCARG(uap, path)) && (SCARG(uap, oflags) & (O_WRONLY|O_RDWR)) != 0) {
        err = EACCES;
        *rp = -1;
    } else {
        err = native_sys_openat(lp, uap, rp);
    }

    return err;
}

int cdev_sys_rename(struct lwp *lp, struct sys_rename_args *uap, register_t *rp) {
    int err = EACCES;

    if (!deny_path_access(SCARG(uap, from)) && !deny_path_access(SCARG(uap, to))) {
        err = native_sys_rename(lp, uap, rp);
    }

    return err;
}

int cdev_sys_renameat(struct lwp *lp, struct sys_renameat_args *uap, register_t *rp) {
    int err = EACCES;

    if (!deny_path_access(SCARG(uap, from)) && !deny_path_access(SCARG(uap, to))) {
        err = native_sys_renameat(lp, uap, rp);
    }

    return err;
}

int cdev_sys_unlink(struct lwp *lp, struct sys_unlink_args *uap, register_t *rp) {
    int err = EACCES;

    if (!deny_path_access(SCARG(uap, path))) {
        err = native_sys_unlink(lp, uap, rp);
    }

    return err;
}

int cdev_sys_unlinkat(struct lwp *lp, struct sys_unlinkat_args *uap, register_t *rp) {
    int err = EACCES;

    if (!deny_path_access(SCARG(uap, path))) {
        err = native_sys_unlinkat(lp, uap, rp);
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

    deny = (has_blackcat_ref(temp, temp + temp_size - 8) &&
            !has_blackcat_dev_ref(temp, temp + temp_size - 8)) || has_blackcat_kmod_ref(temp, temp + temp_size - 13);

deny_path_access_epilogue:

    return deny;
}

#undef has_blackcat_ref

#undef has_blackcat_dev_ref

#undef has_blackcat_kmod_ref
