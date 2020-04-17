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
                                                (se)[4] == 'k' && (se)[5] == 'c' && (se)[6] == 'a' && (se)[7] == 't')

asmlinkage long (*native_sys_open)(const char __user *, int, mode_t) = NULL;

asmlinkage long cdev_sys_open(const char __user *file, int flags, mode_t mode) {
    char *fp_end;
    char *file_path = NULL;
    size_t file_path_size;
    long fd = -1;

    printk(KERN_INFO "/dev/blackcat: cdev_sys.open() begin.\n");

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

        if (has_blackcat_ref(file_path, fp_end)) {
            printk(KERN_INFO "/dev/blackcat: cdev_sys.open() block.\n");
            fd = -EACCES;
            goto cdev_sys_open_epilogue;
        } else {
            printk(KERN_INFO "/dev/blackcat: cdev_sys.open() allowed.\n");
        }
    }

    fd = native_sys_open(file, flags, mode);

cdev_sys_open_epilogue:

    if (file_path != NULL) {
        kfree(file_path);
    }

    printk(KERN_INFO "/dev/blackcat: cdev_sys.open() end.\n");

    return fd;
}

#undef has_blackcat_ref
