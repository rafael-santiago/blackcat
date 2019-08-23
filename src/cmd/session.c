/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/session.h>
#include <cmd/options.h>
#include <ctx/ctx.h>
#include <fs/bcrepo/bcrepo.h>
#include <kryptos_memory.h>
#include <accacia.h>
#include <stdio.h>
#include <errno.h>

int new_blackcat_exec_session_ctx(blackcat_exec_session_ctx **session, const int build_protlayer) {
    int exit_code = EINVAL;
    kryptos_u8_t *catalog_data = NULL;
    size_t catalog_data_size;
    char temp[4096];
    blackcat_exec_session_ctx *es = NULL;
    struct blackcat_keychain_handle_ctx handle;

    if (session == NULL) {
        return EINVAL;
    }

    es = kryptos_newseg(sizeof(blackcat_exec_session_ctx));
    es->key[0] = es->key[1] = NULL;
    es->key_size[0] = es->key_size[1] = 0;
    es->catalog = NULL;
    es->rootpath = NULL;
    es->rootpath_size = 0;

    (*session) = NULL;

    if (es == NULL) {
        fprintf(stderr, "ERROR: Unable to allocate a new execution session.\n");
        exit_code = ENOMEM;
        goto new_blackcat_exec_session_ctx_epilogue;
    }

    es->rootpath = bcrepo_get_rootpath();

    if (es->rootpath == NULL) {
        fprintf(stderr, "ERROR: You are not in a blackcat repo.\n");
        goto new_blackcat_exec_session_ctx_epilogue;
    }

    es->rootpath_size = strlen(es->rootpath);

    es->catalog = new_bfs_catalog_ctx();

    if (es->catalog == NULL) {
        fprintf(stderr, "ERROR: Unable to allocate memory for the repo's catalog.\n");
        exit_code = ENOMEM;
        goto new_blackcat_exec_session_ctx_epilogue;
    }

    catalog_data = bcrepo_read(bcrepo_catalog_file(temp, sizeof(temp), es->rootpath), es->catalog, &catalog_data_size);

    if (catalog_data == NULL) {
        fprintf(stderr, "ERROR: Unable to read the repo's catalog file.\n");
        exit_code = EFAULT;
        goto new_blackcat_exec_session_ctx_epilogue;
    }

    accacia_savecursorposition();

    fprintf(stdout, "Password: ");
    es->key[0] = blackcat_getuserkey(&es->key_size[0]);

    if (es->key[0] == NULL) {
        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);
        fprintf(stderr, "ERROR: Null key.\n");
        goto new_blackcat_exec_session_ctx_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();
    fflush(stdout);

    if (bcrepo_stat(&es->catalog, es->key[0], es->key_size[0], &catalog_data, &catalog_data_size) == 0) {
        fprintf(stderr, "ERROR: While trying to access the catalog data.\n");
        exit_code = EACCES;
        goto new_blackcat_exec_session_ctx_epilogue;
    }

    if (build_protlayer) {
        if (bcrepo_validate_key(es->catalog, es->key[0], es->key_size[0]) == 0) {
            accacia_savecursorposition();

            fprintf(stdout, "Second password: ");
            es->key[1] = blackcat_getuserkey(&es->key_size[1]);

            if (es->key[1] == NULL) {
                accacia_restorecursorposition();
                accacia_delline();
                fflush(stdout);
                fprintf(stderr, "ERROR: Null key.\n");
                goto new_blackcat_exec_session_ctx_epilogue;
            }

            accacia_restorecursorposition();
            accacia_delline();
            fflush(stdout);

            if (bcrepo_validate_key(es->catalog, es->key[1], es->key_size[1]) == 0) {
                fprintf(stderr, "ERROR: Wrong key.\n");
                exit_code = EACCES;
                goto new_blackcat_exec_session_ctx_epilogue;
            }
        } else {
            es->key[1] = (kryptos_u8_t *) kryptos_newseg(es->key_size[0]);

            if (es->key[1] == NULL) {
                accacia_restorecursorposition();
                accacia_delline();
                fflush(stdout);
                fprintf(stderr, "ERROR: Null key.\n");
                goto new_blackcat_exec_session_ctx_epilogue;
            }

            memcpy(es->key[1], es->key[0], es->key_size[0]);
            es->key_size[1] = es->key_size[0];
        }

        // INFO(Rafael): We need the protection layer because some removed files may be encrypted and
        //               they will be decrypted before being actually removed from the catalog.

        handle.hash = es->catalog->protlayer_key_hash_algo;
        handle.kdf_clockwork = NULL;

        es->catalog->protlayer = add_composite_protlayer_to_chain(es->catalog->protlayer,
                                                                  es->catalog->protection_layer, &es->key[1], &es->key_size[1],
                                                                  &handle, es->catalog->encoder);

        handle.hash = NULL;
        handle.kdf_clockwork = NULL;

        if (es->catalog->protlayer == NULL) {
            fprintf(stderr, "ERROR: While building the protection layer.\n");
            exit_code = EFAULT;
            goto new_blackcat_exec_session_ctx_epilogue;
        }
    }

    (*session) = es;
    exit_code = 0;

new_blackcat_exec_session_ctx_epilogue:

    if ((*session) != es) {
        del_blackcat_exec_session_ctx(es);
    }

    if (catalog_data != NULL) {
        kryptos_freeseg(catalog_data, catalog_data_size);
        catalog_data_size = 0;
    }

    return exit_code;
}
