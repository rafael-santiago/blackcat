/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/checkpoint.h>
#include <cmd/session.h>
#include <fs/bcrepo/bcrepo.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int blackcat_checkpoint(void *args) {
    // WARN(Rafael): Since it was passed as checkpoint function we previously know that args always will be non-null.
    blackcat_exec_session_ctx *session = (blackcat_exec_session_ctx *) args;
    char temp[4096];
    int no_error = bcrepo_write(bcrepo_catalog_file(temp, sizeof(temp),
                                session->rootpath), session->catalog, session->key[0], session->key_size[0]);
    if (no_error != 1) {
        fprintf(stderr, "ERROR: Unable to update the catalog file.\n");
        exit(EFAULT);
    }

    return no_error;
}
