/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/init.h>
#include <fs/bcrepo/bcrepo.h>
#include <cmd/options.h>
#include <cmd/version.h>
#include <keychain/ciphering_schemes.h>
#include <ctx/ctx.h>
#include <fs/ctx/fsctx.h>
#include <kryptos.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_init(void) {
    char *catalog_hash, *key_hash, *protection_layer_hash, *protection_layer;
    int keyed_alike;
    int exit_code = EINVAL;
    blackcat_hash_processor key_hash_proc, protlayer_hash_proc, catalog_hash_proc;
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *catalog_key = NULL, *protlayer_key = NULL, *temp_key;
    size_t catalog_key_size, protlayer_key_size, temp_key_size;
    kryptos_task_ctx t, *ktask = &t;
    char *info = NULL;

    BLACKCAT_GET_OPTION_OR_DIE(catalog_hash, "catalog-hash", blackcat_cmd_init_epilogue);

    if ((catalog_hash_proc = get_hash_processor(catalog_hash)) == NULL) {
        fprintf(stderr, "ERROR: Unknown hash algorithm supplied in 'catalog-hash'.\n");
        goto blackcat_cmd_init_epilogue;
    }

    BLACKCAT_GET_OPTION_OR_DIE(key_hash, "key-hash", blackcat_cmd_init_epilogue);

    if ((key_hash_proc = get_hash_processor(key_hash)) == NULL) {
        fprintf(stderr, "ERROR: Unknown hash algorithm supplied in 'key-hash'.\n");
        goto blackcat_cmd_init_epilogue;
    }

    BLACKCAT_GET_OPTION_OR_DIE(protection_layer_hash, "protection-layer-hash", blackcat_cmd_init_epilogue);

    if ((protlayer_hash_proc = get_hash_processor(protection_layer_hash)) == NULL) {
        fprintf(stderr, "ERROR: Unknown hash algorithm supplied in 'protection-layer-hash'.\n");
        goto blackcat_cmd_init_epilogue;
    }

    if (is_weak_hash_funcs_usage(key_hash_proc, protlayer_hash_proc)) {
        fprintf(stderr, "ERROR: The combination of %s and %s is not a good one, try again with another.\n",
                       key_hash, protection_layer_hash);
        goto blackcat_cmd_init_epilogue;
    }

    BLACKCAT_GET_OPTION_OR_DIE(protection_layer, "protection-layer", blackcat_cmd_init_epilogue);

    keyed_alike = blackcat_get_bool_option("keyed-alike", 0);

    // INFO(Rafael): Reading the user's master key or first and second layers keys.

    if (keyed_alike) {
        info = "master key";
    } else {
        info = "first layer key";
    }

    fprintf(stdout, "Type the %s: ", info);
    if ((catalog_key = blackcat_getuserkey(&catalog_key_size)) == NULL) {
        fprintf(stdout, "ERROR: Unable to get the user's key.\n");
        goto blackcat_cmd_init_epilogue;
    }

    fprintf(stdout, "Confirm the %s: ", info);
    if ((temp_key = blackcat_getuserkey(&temp_key_size)) == NULL) {
        fprintf(stdout, "ERROR: Unable to get the user's key.\n");
        goto blackcat_cmd_init_epilogue;
    }

    if (temp_key_size != catalog_key_size || memcmp(catalog_key, temp_key, catalog_key_size) != 0) {
        fprintf(stdout, "ERROR: The keys do not match.\n");
        goto blackcat_cmd_init_epilogue;
    }

    kryptos_freeseg(temp_key, temp_key_size);
    temp_key_size = 0;

    if (keyed_alike) {
        protlayer_key = catalog_key;
        protlayer_key_size = catalog_key_size;
    } else {
        // INFO(Rafael): This will not be protected with a single master key, we need to get the second layer key.

        fprintf(stdout, "Type the second layer key: ");
        if ((protlayer_key = blackcat_getuserkey(&protlayer_key_size)) == NULL) {
            fprintf(stdout, "ERROR: Unable to get the user's key.\n");
            goto blackcat_cmd_init_epilogue;
        }

        fprintf(stdout, "Confirm the second layer key: ");
        if ((temp_key = blackcat_getuserkey(&temp_key_size)) == NULL) {
            fprintf(stdout, "ERROR: Unable to get the user's key.\n");
            goto blackcat_cmd_init_epilogue;
        }

        if (temp_key_size != catalog_key_size || memcmp(protlayer_key, temp_key, catalog_key_size) != 0) {
            fprintf(stdout, "ERROR: The keys do not match.\n");
            goto blackcat_cmd_init_epilogue;
        }
    }

    catalog = new_bfs_catalog_ctx();

    if (catalog == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        exit_code = ENOMEM;
        goto blackcat_cmd_init_epilogue;
    }

    temp_key = (kryptos_u8_t *) kryptos_newseg(protlayer_key_size);

    if (temp_key == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        exit_code = ENOMEM;
        goto blackcat_cmd_init_epilogue;
    }

    memcpy(temp_key, protlayer_key, protlayer_key_size);

    temp_key_size = protlayer_key_size;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          protection_layer, &temp_key, &temp_key_size,
                                                          protlayer_hash_proc);

    if (catalog->protlayer == NULL) {
        goto blackcat_cmd_init_epilogue;
    }

    del_protlayer_chain_ctx(catalog->protlayer);
    catalog->protlayer = NULL;

    // WARN(Rafael): catalog->hmac_scheme will be random at each catalog writing task. There is no
    //               reason for picking one HMAC scheme at this point.

    catalog->bc_version = (char *) get_blackcat_version();
    catalog->catalog_key_hash_algo = catalog_hash_proc;
    catalog->key_hash_algo = key_hash_proc;
    catalog->key_hash_algo_size = get_hash_size(key_hash);

    kryptos_task_init_as_null(ktask);

    ktask->in = protlayer_key;
    ktask->in_size = protlayer_key_size;

    // WARN(Rafael): This is not hash with binary output it must be hexadecimal.

    catalog->key_hash_algo(&ktask, 1);

    if (kryptos_last_task_succeed(ktask) == 0) {
        fprintf(stderr, "ERROR: While trying to hash the user key.\n");
        goto blackcat_cmd_init_epilogue;
    }

    catalog->key_hash = ktask->out;
    catalog->key_hash_size = ktask->out_size;

    // WARN(Rafael): No problem in set ktask->out to NULL it will be freed indirectly when freeing the entire catalog.

    ktask->in  = ktask->out = NULL;
    ktask->in_size = ktask->out_size = 0;

    catalog->protlayer_key_hash_algo = protlayer_hash_proc;
    catalog->protlayer_key_hash_algo_size = get_hash_size(protection_layer_hash);
    catalog->protection_layer = protection_layer;

    if (bcrepo_init(catalog, catalog_key, catalog_key_size)) {
        exit_code = 0;
    }

blackcat_cmd_init_epilogue:

    if (catalog != NULL) {
        catalog->bc_version = NULL;
        del_bfs_catalog_ctx(catalog);
    }

    if (temp_key != NULL) {
        kryptos_freeseg(temp_key, temp_key_size);
        temp_key_size = 0;
    }

    if (protlayer_key != NULL && protlayer_key != catalog_key) {
        kryptos_freeseg(protlayer_key, protlayer_key_size);
        protlayer_key_size = 0;
    }

    if (catalog_key != NULL) {
        kryptos_freeseg(catalog_key, catalog_key_size);
        catalog_key_size = 0;
    }

    return exit_code;
}

int blackcat_cmd_init_help(void) {
    fprintf(stdout, "use: blackcat init --catalog-hash=<hash> --key-hash=<hash> --protection-layer-hash=<hash>\n"
                    "                   --protection-layer=<algorithm layers> [--keyed-alike]\n");
}

