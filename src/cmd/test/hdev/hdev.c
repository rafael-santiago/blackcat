/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#if defined(__linux__)
#include <linux/init.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <kook.h>

MODULE_LICENSE("GPL");

static int (*sys_write)(int fd, const void *buf, size_t count) = NULL;

//static ssize_t (*sys_read)(int fd, void *buf, size_t len) = NULL;

//static ssize_t hook_read(int fd, void *buf, size_t len);

static int hook_write(int fd, const void *buf, size_t count);

static int __init hook_ini(void) {
    //kook(__NR_read, hook_read, (void *)&sys_read);
    kook(__NR_write, hook_write, (void *)&sys_write);
    return 0;
}

static void __exit hook_finis(void) {
    //kook(__NR_read, sys_read, NULL);
    kook(__NR_write, sys_write, NULL);
}

/*static ssize_t hook_read(int fd, void *buf, size_t len) {
    return sys_read(fd, buf, len);
}*/

static int hook_write(int fd, const void *buf, size_t count) {
    return sys_write(fd, buf, count);
}

module_init(hook_ini);

module_exit(hook_finis);

#elif defined(__FreeBSD__)

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <kook.h>

void *sys_write_p = NULL, *sys_writev_p = NULL, *sys_pwrite_p = NULL,
     *sys_read_p = NULL, *sys_readv_p = NULL, *sys_pread_p = NULL;

static int hook_write(struct thread *td, void *args);

static int hook_writev(struct thread *td, void *args);

static int hook_pwrite(struct thread *td, void *args);

static int hook_read(struct thread *td, void *args);

static int hook_readv(struct thread *td, void *args);

static int hook_pread(struct thread *td, void *args);

static int ld(struct module *mod, int cmd, void *arg);

static moduledata_t hook_mod = {
    "hook",
    ld,
    NULL
};

DECLARE_MODULE(hook, hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

static int ld(struct module *mod, int cmd, void *arg) {
    int error = 0;

    switch (cmd) {
        case MOD_LOAD:
            kook(SYS_read, hook_read, &sys_read_p);
            kook(SYS_readv, hook_readv, &sys_readv_p);
            kook(SYS_pread, hook_pread, &sys_pread_p);
            kook(SYS_write, hook_write, &sys_write_p);
            kook(SYS_writev, hook_writev, &sys_writev_p);
            kook(SYS_pwrite, hook_pwrite, &sys_pwrite_p);
            break;

        case MOD_UNLOAD:
            kook(SYS_read, sys_read_p, NULL);
            kook(SYS_readv, sys_readv_p, NULL);
            kook(SYS_pread, sys_pread_p, NULL);
            kook(SYS_write, sys_write_p, NULL);
            kook(SYS_writev, sys_writev_p, NULL);
            kook(SYS_pwrite, sys_pwrite_p, NULL);
            break;

        default:
            error = EOPNOTSUPP;
            break;
    }

    return error;
}

static int hook_write(struct thread *td, void *args) {
    return sys_write(td, args);
}

static int hook_writev(struct thread *td, void *args) {
    return sys_writev(td, args);
}

static int hook_pwrite(struct thread *td, void *args) {
    return sys_pwrite(td, args);
}

static int hook_read(struct thread *td, void *args) {
    return sys_read(td, args);
}

static int hook_readv(struct thread *td, void *args) {
    return sys_readv(td, args);
}

static int hook_pread(struct thread *td, void *args) {
    return sys_pread(td, args);
}

#elif defined(__NetBSD__)

#include <sys/module.h>
#include <sys/syscall.h>
#include <sys/syscallargs.h>
#include <kook.h>

void *sys_write_p = NULL, *sys_writev_p = NULL, *sys_pwrite_p = NULL,
     *sys_read_p = NULL, *sys_readv_p = NULL, *sys_pread_p = NULL;

static int hook_write(struct lwp *lp, const void *args, register_t *rp);

static int hook_writev(struct lwp *lp, const void *args, register_t *rp);

static int hook_pwrite(struct lwp *lp, const void *args, register_t *rp);

static int hook_read(struct lwp *lp, const void *args, register_t *rp);

static int hook_readv(struct lwp *lp, const void *args, register_t *rp);

static int hook_pread(struct lwp *lp, const void *args, register_t *rp);

static int hook_modcmd(modcmd_t cmd, void *args);

MODULE(MODULE_CLASS_DRIVER, hook, NULL);

static int hook_modcmd(modcmd_t cmd, void *args) {
    int errno = 0;

    switch (cmd) {
        case MODULE_CMD_INIT:
            kook(SYS_read, hook_read, &sys_read_p);
            kook(SYS_readv, hook_readv, &sys_readv_p);
            kook(SYS_pread, hook_pread, &sys_pread_p);
            kook(SYS_write, hook_write, &sys_write_p);
            kook(SYS_writev, hook_writev, &sys_writev_p);
            kook(SYS_pwrite, hook_pwrite, &sys_pwrite_p);
            break;

        case MODULE_CMD_FINI:
            kook(SYS_read, sys_read_p, NULL);
            kook(SYS_readv, sys_readv_p, NULL);
            kook(SYS_pread, sys_pread_p, NULL);
            kook(SYS_write, sys_write_p, NULL);
            kook(SYS_writev, sys_writev_p, NULL);
            kook(SYS_pwrite, sys_pwrite_p, NULL);
            break;

        default:
            errno = EOPNOTSUPP;
            break;
    }

    return errno;
}

static int hook_write(struct lwp *lp, const void *args, register_t *rp) {
    return sys_write(lp, args, rp);
}

static int hook_writev(struct lwp *lp, const void *args, register_t *rp) {
    return sys_writev(lp, args, rp);
}

static int hook_pwrite(struct lwp *lp, const void *args, register_t *rp) {
    return sys_pwrite(lp, args, rp);
}

static int hook_read(struct lwp *lp, const void *args, register_t *rp) {
    return sys_read(lp, args, rp);
}

static int hook_readv(struct lwp *lp, const void *args, register_t *rp) {
    return sys_readv(lp, args, rp);
}

static int hook_pread(struct lwp *lp, const void *args, register_t *rp) {
    return sys_pread(lp, args, rp);
}

#endif
