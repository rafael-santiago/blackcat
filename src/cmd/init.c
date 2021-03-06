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
#include <keychain/keychain.h>
#include <ctx/ctx.h>
#include <fs/ctx/fsctx.h>
#include <accacia.h>
#include <kryptos.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_init(void) {
    char *catalog_hash, *key_hash, *protection_layer_hash, *protection_layer, *encoder, *bcrypt_cost;
    int keyed_alike;
    int exit_code = EINVAL;
    blackcat_hash_processor key_hash_proc, protlayer_hash_proc, catalog_hash_proc;
    blackcat_encoder encoder_proc = NULL;
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *catalog_key = NULL, *protlayer_key = NULL, *temp_key = NULL;
    size_t catalog_key_size, protlayer_key_size, temp_key_size;
    kryptos_task_ctx t, *ktask = &t;
    char *info = NULL;
    char *rootpath = NULL;
    char *kdf = NULL;
    void *key_hash_algo_args = NULL;
    int cost;
    struct blackcat_keychain_handle_ctx handle;

    if ((rootpath = bcrepo_get_rootpath()) != NULL) {
        fprintf(stderr, "ERROR: This is already a blackcat repo.\n");
        goto blackcat_cmd_init_epilogue;
    }

    BLACKCAT_GET_OPTION_OR_DIE(catalog_hash, "catalog-hash", blackcat_cmd_init_epilogue);

    if ((catalog_hash_proc = get_hash_processor(catalog_hash)) == NULL) {
        fprintf(stderr, "ERROR: Unknown hash algorithm supplied in 'catalog-hash'.\n");
        goto blackcat_cmd_init_epilogue;
    }

    if (is_pht(catalog_hash_proc)) {
        fprintf(stderr, "ERROR: You cannot use '%s' as catalog hash. Choose another one.\n", catalog_hash);
        goto blackcat_cmd_init_epilogue;
    }

    BLACKCAT_GET_OPTION_OR_DIE(key_hash, "key-hash", blackcat_cmd_init_epilogue);

    if ((key_hash_proc = get_hash_processor(key_hash)) == NULL) {
        fprintf(stderr, "ERROR: Unknown hash algorithm supplied in 'key-hash'.\n");
        goto blackcat_cmd_init_epilogue;
    }

    if (key_hash_proc == blackcat_bcrypt) {
        BLACKCAT_GET_OPTION_OR_DIE(bcrypt_cost, "bcrypt-cost", blackcat_cmd_init_epilogue);
        if (!blackcat_is_dec(bcrypt_cost, strlen(bcrypt_cost))) {
            fprintf(stderr, "ERROR: The option 'bcrypt-cost' has invalid data.\n");
            goto blackcat_cmd_init_epilogue;
        }

        cost = atoi(bcrypt_cost);

        if (cost < 4 || cost > 31) {
            fprintf(stderr, "ERROR: The option 'bcrypt-cost' requires a value between 4 and 31.\n");
            goto blackcat_cmd_init_epilogue;
        }

        key_hash_algo_args = &cost;
    }

    BLACKCAT_GET_OPTION_OR_DIE(protection_layer_hash, "protection-layer-hash", blackcat_cmd_init_epilogue);

    if ((protlayer_hash_proc = get_hash_processor(protection_layer_hash)) == NULL) {
        fprintf(stderr, "ERROR: Unknown hash algorithm supplied in 'protection-layer-hash'.\n");
        goto blackcat_cmd_init_epilogue;
    }

    if (is_pht(protlayer_hash_proc)) {
        fprintf(stderr, "ERROR: You cannot use '%s' in protection layer. Choose another one.\n", protection_layer_hash);
        goto blackcat_cmd_init_epilogue;
    }

    if (is_weak_hash_funcs_usage(key_hash_proc, protlayer_hash_proc)) {
        fprintf(stderr, "ERROR: The combination of %s and %s is not a good one, try again with another.\n",
                       key_hash, protection_layer_hash);
        goto blackcat_cmd_init_epilogue;
    }

    BLACKCAT_GET_OPTION_OR_DIE(protection_layer, "protection-layer", blackcat_cmd_init_epilogue);

    encoder = blackcat_get_option("encoder", NULL);

    if (encoder != NULL) {
        if ((encoder_proc = get_encoder(encoder)) == NULL) {
            fprintf(stderr, "ERROR: Unknown encoder supplied in 'encoder'.\n");
            goto blackcat_cmd_init_epilogue;
        }
    }

    keyed_alike = blackcat_get_bool_option("keyed-alike", 0);

    // INFO(Rafael): Reading the user's master key or first and second layers keys.

    if (keyed_alike) {
        info = "master key";
    } else {
        info = "first layer key";
    }

    accacia_savecursorposition();

    fprintf(stdout, "Type the %s: ", info);
#if defined(_WIN32)
        fflush(stdout);
#endif
    if ((catalog_key = blackcat_getuserkey(&catalog_key_size)) == NULL) {
        fprintf(stderr, "ERROR: Unable to get the user's key.\n");
        goto blackcat_cmd_init_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();

    fprintf(stdout, "Confirm the %s: ", info);
#if defined(_WIN32)
        fflush(stdout);
#endif
    if ((temp_key = blackcat_getuserkey(&temp_key_size)) == NULL) {
        fprintf(stderr, "ERROR: Unable to get the user's key.\n");
        goto blackcat_cmd_init_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();

    if (temp_key_size != catalog_key_size || memcmp(catalog_key, temp_key, catalog_key_size) != 0) {
        fflush(stdout);
        fprintf(stderr, "ERROR: The keys do not match.\n");
        goto blackcat_cmd_init_epilogue;
    }

    kryptos_freeseg(temp_key, temp_key_size);
    temp_key_size = 0;
    temp_key = NULL;

    if (wrap_user_key_with_tokens(&catalog_key, &catalog_key_size) == 0) {
        fprintf(stderr, "ERROR: While trying to mix user token data with first layer key.\n");
        goto blackcat_cmd_init_epilogue;
    }

    if (keyed_alike) {
        protlayer_key = catalog_key;
        protlayer_key_size = catalog_key_size;
    } else {
        // INFO(Rafael): This will not be protected with a single master key, we need to get the second layer key.

        fprintf(stdout, "Type the second layer key: ");
#if defined(_WIN32)
        fflush(stdout);
#endif
        if ((protlayer_key = blackcat_getuserkey(&protlayer_key_size)) == NULL) {
            fprintf(stderr, "ERROR: Unable to get the user's key.\n");
            goto blackcat_cmd_init_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();

        fprintf(stdout, "Confirm the second layer key: ");
#if defined(_WIN32)
        fflush(stdout);
#endif
        if ((temp_key = blackcat_getuserkey(&temp_key_size)) == NULL) {
            fflush(stdout);
            fprintf(stderr, "ERROR: Unable to get the user's key.\n");
            goto blackcat_cmd_init_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();

        if (temp_key_size != protlayer_key_size || memcmp(protlayer_key, temp_key, protlayer_key_size) != 0) {
            fflush(stdout);
            fprintf(stderr, "ERROR: The keys do not match.\n");
            goto blackcat_cmd_init_epilogue;
        }

        if (wrap_user_key_with_tokens(&protlayer_key, &protlayer_key_size) == 0) {
            fprintf(stderr, "ERROR: While trying to mix user token data with second layer key.\n");
            goto blackcat_cmd_init_epilogue;
        }
    }

    fflush(stdout);

    if (key_hash_proc == blackcat_bcrypt && protlayer_key_size > 72) {
        fprintf(stderr, "ERROR: The protection layer key exceeds its limit of 72 bytes (you chose bcrypt, didn't you?).\n");
        goto blackcat_cmd_init_epilogue;
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

    handle.hash = protlayer_hash_proc;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          protection_layer,
                                                          strlen(protection_layer),
                                                          &temp_key, &temp_key_size,
                                                          &handle, catalog->encoder);

    handle.hash = NULL;
    handle.kdf_clockwork = NULL;

    if (catalog->protlayer == NULL) {
        goto blackcat_cmd_init_epilogue;
    }

    del_protlayer_chain_ctx(catalog->protlayer);
    catalog->protlayer = NULL;

    // WARN(Rafael): catalog->hmac_scheme will be random at each catalog writing task. There is no
    //               reason for picking one HMAC scheme at this point.

    catalog->bc_version = (char *) bcrepo_metadata_version();
    catalog->catalog_key_hash_algo = catalog_hash_proc;
    catalog->catalog_key_hash_algo_size = get_hash_size(catalog_hash);
    catalog->key_hash_algo = key_hash_proc;
    catalog->key_hash_algo_size = get_hash_size(key_hash);

    catalog->key_hash = bcrepo_hash_key(protlayer_key, protlayer_key_size,
                                        catalog->key_hash_algo, key_hash_algo_args, &catalog->key_hash_size);

    // WARN(Rafael): No problem in set ktask->out to NULL it will be freed indirectly when freeing the entire catalog.

    ktask->in  = ktask->out = NULL;
    ktask->in_size = ktask->out_size = 0;

    catalog->protlayer_key_hash_algo = protlayer_hash_proc;
    catalog->protlayer_key_hash_algo_size = get_hash_size(protection_layer_hash);
    catalog->protection_layer = protection_layer;
    catalog->protection_layer_size = strlen(protection_layer);

    catalog->encoder = encoder_proc;

    catalog->otp = blackcat_get_bool_option("otp", 0);

    catalog->kdf_params = blackcat_get_kdf_usr_params_from_cmdline(&catalog->kdf_params_size);

    if (catalog->kdf_params == NULL && (kdf = blackcat_get_option("kdf", NULL)) != NULL) {
        if (get_kdf(kdf) == NULL) {
            fprintf(stderr, "ERROR: Unknown KDF was passed : '%s'.\n", kdf);
        }
        exit_code = EINVAL;
        goto blackcat_cmd_init_epilogue;
    }

    if (bcrepo_init(catalog, catalog_key, catalog_key_size)) {
        exit_code = 0;
    }

blackcat_cmd_init_epilogue:

    if (rootpath != NULL) {
        kryptos_freeseg(rootpath, strlen(rootpath));
    }

    if (catalog != NULL) {
        catalog->bc_version = NULL;
        catalog->protection_layer = NULL;
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
    fprintf(stdout, "use: blackcat init\n"
                    "              --catalog-hash=<hash>\n"
                    "              --key-hash=<hash>\n"
                    "              --protection-layer-hash=<hash>\n"
                    "              --protection-layer=<algorithm layers>\n"
                    "              [--keyed-alike\n"
                    "               --encoder=<encoder>\n"
                    "               --kdf=<kdf algorithm>\n"
                    "               <specific kdf algorithm options>\n"
                    "               --soft-token=<file path 0>,...,<file path n>\n"
                    "               --otp]\n");
    return 0;
}
