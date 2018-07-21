#include <linux/cdev_ioctl.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

long cdev_ioctl(struct file *fp, unsigned int cmd, unsigned long user_param) {
    return 0;
}
