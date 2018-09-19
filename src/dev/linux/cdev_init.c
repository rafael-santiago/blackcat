/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/cdev_init.h>
#include <linux/cdev_deinit.h>
#include <defs/types.h>
#include <icloak.h>
#include <linux/cdev_open.h>
#include <linux/cdev_ioctl.h>
#include <linux/cdev_release.h>
#include <linux/device.h>

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = cdev_open,
    .unlocked_ioctl = cdev_ioctl,
    .release = cdev_release
};

int cdev_init(void) {
    cdev_mtx_init(&g_cdev()->lock);

    g_cdev()->major_nr = register_chrdev(0, CDEVNAME, &fops);

    if (g_cdev()->major_nr < 0) {
        printk(KERN_INFO "/dev/blackcat: Error during cdev registration.\n");
        return g_cdev()->major_nr;
    }

    g_cdev()->device_class = class_create(THIS_MODULE, CDEVCLASS);

    if (IS_ERR(g_cdev()->device_class)) {
        unregister_chrdev(g_cdev()->major_nr, CDEVNAME);
        printk(KERN_INFO "/dev/blackcat: Class creation has failed.\n");
        return PTR_ERR(g_cdev()->device_class);
    }

    g_cdev()->device = device_create(g_cdev()->device_class, NULL, MKDEV(g_cdev()->major_nr, 0), NULL, CDEVNAME);

    if (IS_ERR(g_cdev()->device)) {
        class_destroy(g_cdev()->device_class);
        unregister_chrdev(g_cdev()->major_nr, CDEVNAME);
        printk(KERN_INFO "/dev/blackcat: Device file creation failure.\n");
        return PTR_ERR(g_cdev()->device);
    }

    // INFO(Rafael): Hiding the LKM.

    if (icloak_ko(CDEVNAME) != 0) {
        printk(KERN_INFO "/dev/blackcat: Unable to hide the kernel module.\n");
        cdev_deinit();
        return 1;
    }

    return 0;
}
