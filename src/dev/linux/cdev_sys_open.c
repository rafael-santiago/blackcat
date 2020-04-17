/*
 *                          Copyright (C) 2020 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/cdev_sys_open.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define has_blackcat_ref(s, se) ( (se) > (s) && (se)[0] == 'b' && (se)[1] == 'l' && (se)[2] == 'a' && (se)[3] == 'c' &&\
                                                (se)[4] == 'k' && (se)[5] == 'c' && (se)[6] == 'a' && (se)[7] == 't' )

#define has_blackcat_dev_ref(s, se) ( ((se) - 4) > (s) && (se)[-4] == 'd' && (se)[-3] == 'e' && (se)[-2] == 'v' &&\
                                                          (se)[-1] == '/' )

asmlinkage long (*native_sys_open)(const char __user *, int, mode_t) = NULL;

asmlinkage long (*native_sys_readlink)(const char __user *, char __user *, size_t) = NULL;

asmlinkage long cdev_sys_open(const char __user *file, int flags, mode_t mode) {
    char *fp_end;
    char *file_path = NULL;
    size_t file_path_size;
    long fd = -1;

    if (native_sys_open == NULL || file == NULL) {
        fd = -EFAULT;
        goto cdev_sys_open_epilogue;
    }

    if (file != NULL) {
        fp_end = (char *)file;

        while (*fp_end != 0) {
            fp_end++;
        }

        file_path_size = fp_end - file;
        file_path = (char *) kmalloc(file_path_size, GFP_ATOMIC);

        if (file_path == NULL) {
            goto cdev_sys_open_epilogue;
        }

        if (copy_from_user(file_path, file, file_path_size) != 0) {
            fd = -ENOMEM;
            goto cdev_sys_open_epilogue;
        }

        fp_end = file_path + file_path_size - 8;

        if (has_blackcat_ref(file_path, fp_end) && !has_blackcat_dev_ref(file_path, fp_end)) {
            fd = -EACCES;
            goto cdev_sys_open_epilogue;
        }
    }

    fd = native_sys_open(file, flags, mode);

cdev_sys_open_epilogue:

    if (file_path != NULL) {
        kfree(file_path);
    }

    return fd;
}

asmlinkage long cdev_sys_readlink(const char __user *pathname, char __user *buf, size_t buf_size) {
    long ret_size = -1;
    char *file_path = NULL;

    if (native_sys_readlink == NULL || pathname == NULL || buf == NULL) {
        goto cdev_sys_readlink_epilogue;
    }

    ret_size = native_sys_readlink(pathname, buf, buf_size);

    if (ret_size > -1 && ret_size >= 8) {
        file_path = (char *) kmalloc(ret_size + 1, GFP_ATOMIC);

        if (file_path == NULL) {
            // INFO(Rafael): 'Leak and let die!'
            ret_size = -1;
            goto cdev_sys_readlink_epilogue;
        }

        memset(file_path, 0, ret_size + 1);

        if (copy_from_user(file_path, buf, ret_size) != 0) {
            ret_size = -1;
            goto cdev_sys_readlink_epilogue;
        }

        if (has_blackcat_ref(file_path, file_path + ret_size - 8) && !has_blackcat_dev_ref(file_path, file_path + ret_size - 8)) {
            memset(file_path, 0, ret_size);
            if (copy_to_user(buf, file_path, ret_size) != 0) {
                // INFO(Rafael): If we cannot clear up the buffer we will stop the process by causing an error. 'Pow!' @=S
                ret_size = -1;
            }
            goto cdev_sys_readlink_epilogue;
        }
    }

cdev_sys_readlink_epilogue:

    if (file_path != NULL) {
        kfree(file_path);
    }

    return ret_size;
}

#undef has_blackcat_ref
