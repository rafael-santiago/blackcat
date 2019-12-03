/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/version.h>
#include <stdio.h>

static char *g_blackcat_version = "1.3.0";

const char *get_blackcat_version(void) {
    return g_blackcat_version;
}

int blackcat_cmd_version(void) {
    fprintf(stdout, "blackcat-v%s\n", g_blackcat_version);
    return 0;
}
