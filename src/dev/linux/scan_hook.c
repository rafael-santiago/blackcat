/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <linux/scan_hook.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>

int scan_hook(void) {
    void *kallsyms_lookup_name_p;
    unsigned long **sys_ent;
    void *sys_read = NULL, *sys_write = NULL, *sys_ioctl = NULL;

    if ((kallsyms_lookup_name_p = (void *)kallsyms_lookup_name("kallsyms_lookup_name")) == NULL) {
        return 1;
    }

    if (kallsyms_lookup_name_p != (void *)kallsyms_lookup_name) {
        return 1;
    }

    sys_ent = (void *) kallsyms_lookup_name("sys_call_table");

    if (sys_ent == NULL) {
        return 1;
    }

    if ((sys_read = (void *)kallsyms_lookup_name("sys_read")) == NULL) {
        return 1;
    }

    if ((sys_write = (void *)kallsyms_lookup_name("sys_write")) == NULL) {
        return 1;
    }

    if ((sys_ioctl = (void *)kallsyms_lookup_name("sys_ioctl")) == NULL) {
        return 1;
    }

    if (sys_read  != (void *)sys_ent[__NR_read]  ||
        sys_write != (void *)sys_ent[__NR_write] ||
        sys_ioctl != (void *)sys_ent[__NR_ioctl]) {
        return 1;
    }

    return 0;
}
