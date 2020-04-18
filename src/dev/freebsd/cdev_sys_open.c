/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <freebsd/cdev_sys_open.h>

#define has_blackcat_ref(s, se) ( (se) > (s) && (se)[0] == 'b' && (se)[1] == 'l' && (se)[2] == 'a' && (se)[3] == 'c' &&\
                                                (se)[4] == 'k' && (se)[5] == 'c' && (se)[6] == 'a' && (se)[7] == 't' )

#define has_blackcat_dev_ref(s, se) ( ((se) - 4) > (s) && (se)[-4] == 'd' && (se)[-3] == 'e' && (se)[-2] == 'v' &&\
                                                          (se)[-1] == '/' )

int (*native_sys_open)(struct thread *td, void *args) = NULL;

int (*native_sys_openat)(struct thread *td, void *args) = NULL;

int (*native_sys_readlink)(struct thread *td, void *args) = NULL;

int cdev_sys_open(struct thread *td, void *args) {
    struct open_args *uap;
    char *fp_end;
    char *file_path = NULL;
    size_t file_path_size;
    int err = EFAULT;

    td->td_retval[0] = -1;

    uap = (struct open_args *)args;

    if (native_sys_open == NULL || uap == NULL || uap->path == NULL) {
        td->td_retval[0] = -1;
        err = EFAULT;
        goto cdev_sys_open_epilogue;
    }

    if (uap->path != NULL) {
        fp_end = (char *)uap->path;

        while (*fp_end != 0) {
            fp_end++;
        }

        file_path_size = fp_end - uap->path;
        file_path = (char *) malloc(file_path_size, M_TEMP, M_NOWAIT);

        if (file_path == NULL) {
            goto cdev_sys_open_epilogue;
        }

        copyin(uap->path, file_path, file_path_size);

        fp_end = file_path + file_path_size - 8;

        if (has_blackcat_ref(file_path, fp_end) && !has_blackcat_dev_ref(file_path, fp_end)) {
            td->td_retval[0] = -1;
            err = EACCES;
            goto cdev_sys_open_epilogue;
        }
    }

    td->td_retval[0] = native_sys_open(td, args);
    err = 0;

cdev_sys_open_epilogue:

    if (file_path != NULL) {
        free(file_path, M_TEMP);
    }

    return err;

}

int cdev_sys_openat(struct thread *td, void *args) {
    struct openat_args *uap;
    char *fp_end;
    char *file_path = NULL;
    size_t file_path_size;
    int err = EFAULT;

    td->td_retval[0] = -1;

    uap = (struct openat_args *)args;

    if (native_sys_openat == NULL || uap == NULL || uap->path == NULL) {
        td->td_retval[0] = -1;
        err = EFAULT;
        goto cdev_sys_openat_epilogue;
    }

    if (uap->path != NULL) {
        fp_end = (char *)uap->path;

        while (*fp_end != 0) {
            fp_end++;
        }

        file_path_size = fp_end - uap->path;
        file_path = (char *) malloc(file_path_size, M_TEMP, M_NOWAIT);

        if (file_path == NULL) {
            goto cdev_sys_openat_epilogue;
        }

        copyin(uap->path, file_path, file_path_size);

        fp_end = file_path + file_path_size - 8;

        if (has_blackcat_ref(file_path, fp_end) && !has_blackcat_dev_ref(file_path, fp_end)) {
            td->td_retval[0] = -1;
            err = EACCES;
            goto cdev_sys_openat_epilogue;
        }
    }

    td->td_retval[0] = native_sys_openat(td, args);
    err = 0;

cdev_sys_openat_epilogue:

    if (file_path != NULL) {
        free(file_path, M_TEMP);
    }

    return err;
}

int cdev_sys_readlink(struct thread *td, void *args) {
    char *file_path = NULL;
    struct readlink_args *uap;
    int err = EFAULT;

    uap = (struct readlink_args *)args;

    if (native_sys_readlink == NULL || uap == NULL || uap->path == NULL || uap->buf == NULL) {
        goto cdev_sys_readlink_epilogue;
    }

    err = native_sys_readlink(td, args);

    if (err == 0 && td->td_retval[0] >= 8) {
        file_path = (char *) malloc(td->td_retval[0] + 1, M_TEMP, M_NOWAIT);

        if (file_path == NULL) {
            // INFO(Rafael): 'Leak and let die!'
            td->td_retval[0] = -1;
            goto cdev_sys_readlink_epilogue;
        }

        memset(file_path, 0, td->td_retval[0] + 1);

        if (copyin(uap->buf, file_path, td->td_retval[0]) != 0) {
            td->td_retval[0] = -1;
            goto cdev_sys_readlink_epilogue;
        }

        if (has_blackcat_ref(file_path, file_path + td->td_retval[0] - 8) &&
            !has_blackcat_dev_ref(file_path, file_path + td->td_retval[0] - 8)) {
            memset(file_path, 0, td->td_retval[0]);
            if (copyout(file_path, uap->buf, td->td_retval[0]) != 0) {
                // INFO(Rafael): If we cannot clear up the buffer we will stop the process by causing an error. 'Pow!' @=S
                td->td_retval[0] = -1;
            }
        }
    }

cdev_sys_readlink_epilogue:

    if (file_path != NULL) {
        free(file_path, M_TEMP);
    }

    return err;
}

#undef has_blackcat_ref

#undef has_blackcat_dev_ref
