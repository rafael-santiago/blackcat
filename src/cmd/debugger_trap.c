/*
 *                          Copyright (C) 2021 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/debugger_trap.h>
#include <accacia.h>
#include <stdio.h>
#include <stdlib.h>

void blackcat_debugger_trap(void *arg) {
    accacia_textcolor(AC_TCOLOR_RED);
    fprintf(stderr, "WARN: ");
    accacia_screennormalize();
    fprintf(stderr, "a debugging attempt was detected, the process will be terminated.\n");
    exit(1);
}

