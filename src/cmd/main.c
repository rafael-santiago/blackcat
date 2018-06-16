/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/exec.h>
#include <cmd/options.h>

int main(int argc, char **argv) {
    int exit_code = blackcat_exec(argc, argv);
    blackcat_clear_options();
    return exit_code;
}
