/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */

#include <netbsd/scan_hook.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/syscallargs.h>

int scan_hook(void) {
    // TODO(Rafael): Find a way of verifying the sysent pointer in order to mitigate memory patching attacks.
    if (sysent[SYS_read].sy_call != (sy_call_t *)sys_read ||
        sysent[SYS_readv].sy_call != (sy_call_t *)sys_readv ||
        sysent[SYS_pread].sy_call != (sy_call_t *)sys_pread ||
        sysent[SYS_write].sy_call != (sy_call_t *)sys_write ||
        sysent[SYS_writev].sy_call != (sy_call_t *)sys_writev ||
        sysent[SYS_pwrite].sy_call != (sy_call_t *)sys_pwrite ||
        sysent[SYS_ioctl].sy_call != (sy_call_t *)sys_ioctl) {
        return 1;
    }

    return 0;
}
