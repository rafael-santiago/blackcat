/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cmd/setkey.h>
#include <cmd/options.h>
#include <cmd/session.h>
#include <cmd/checkpoint.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/keychain.h>
#include <ctx/ctx.h>
#include <fs/bcrepo/bcrepo.h>
#include <kryptos.h>
#include <accacia.h>
#include <stdio.h>
#include <errno.h>

int blackcat_cmd_setkey(void) {
    int exit_code = EINVAL;
    char *catalog_hash, *key_hash, *protection_layer_hash, *encoder, *protection_layer, *bcrypt_cost;
    blackcat_exec_session_ctx *session = NULL;
    int keyed_alike;
    blackcat_hash_processor catalog_hash_proc, key_hash_proc, protection_layer_hash_proc;
    blackcat_encoder encoder_proc;
    kryptos_u8_t *new_key[3] = { NULL, NULL, NULL };
    size_t new_key_size[3] = { 0, 0, 0 };
    char *prompt;
    blackcat_protlayer_chain_ctx *p_layer = NULL;
    void *key_hash_algo_args = NULL;
    int cost;

    if ((exit_code = new_blackcat_exec_session_ctx(&session, 1)) != 0) {
        goto blackcat_cmd_setkey_epilogue;
    }

    exit_code = EINVAL;

#define GET_PROCESSOR(v, o, p, c, f, g, e) {\
    if (((v) = blackcat_get_option((o), NULL)) == NULL) {\
        (p) = (c)->f;\
    } else if (((p) = g((v))) == NULL) {\
        fprintf(stderr, "ERROR: %s.\n", (e));\
        goto blackcat_cmd_setkey_epilogue;\
    }\
}

    GET_PROCESSOR(catalog_hash, "catalog-hash", catalog_hash_proc,
                  session->catalog, catalog_key_hash_algo, get_hash_processor,
                  "Unknown hash algorithm supplied in 'catalog-hash'")

    GET_PROCESSOR(key_hash, "key-hash", key_hash_proc,
                  session->catalog, key_hash_algo, get_hash_processor,
                  "Unknown hash algorithm supplied in 'key-hash'")

    GET_PROCESSOR(protection_layer_hash, "protection-layer-hash", protection_layer_hash_proc,
                  session->catalog, protlayer_key_hash_algo, get_hash_processor,
                  "Unknown hash algorithm supplied in 'protection-layer-hash'")

    GET_PROCESSOR(encoder, "encoder", encoder_proc,
                  session->catalog, encoder, get_encoder,
                  "Unknown encoding algorithm supplied in 'encoder'")

#undef GET_PROCESSOR

    if (is_pht(catalog_hash_proc)) {
        fprintf(stderr, "ERROR: You cannot use '%s' as catalog hash. Choose another one.\n", catalog_hash);
        goto blackcat_cmd_setkey_epilogue;
    }

    if (is_pht(protection_layer_hash_proc)) {
        fprintf(stderr, "ERROR: You cannot use '%s' in protection layer. Choose another one.\n", protection_layer_hash);
        goto blackcat_cmd_setkey_epilogue;
    }

    if (key_hash_proc == blackcat_bcrypt) {
        BLACKCAT_GET_OPTION_OR_DIE(bcrypt_cost, "bcrypt-cost", blackcat_cmd_setkey_epilogue);
        if (!blackcat_is_dec(bcrypt_cost, strlen(bcrypt_cost))) {
            fprintf(stderr, "ERROR: The option 'bcrypt-cost' has invalid data.\n");
            goto blackcat_cmd_setkey_epilogue;
        }

        cost = atoi(bcrypt_cost);

        if (cost < 4 || cost > 31) {
            fprintf(stderr, "ERROR: The option 'bcrypt-cost' requires a value between 4 and 31.\n");
            goto blackcat_cmd_setkey_epilogue;
        }

        key_hash_algo_args = &cost;
    }

    if (is_weak_hash_funcs_usage(key_hash_proc, protection_layer_hash_proc)) {
        fprintf(stderr, "ERROR: The combination of %s and %s is not a good one, try again with another.\n",
                         key_hash, protection_layer_hash);
        goto blackcat_cmd_setkey_epilogue;
    }

    protection_layer = blackcat_get_option("protection-layer", NULL);

    keyed_alike = blackcat_get_bool_option("keyed-alike", 0);

    if (keyed_alike) {
        prompt = "new master key";
    } else {
        prompt = "new first layer key";
    }

    accacia_savecursorposition();

    fprintf(stdout, "Type the %s: ", prompt);
    if ((new_key[0] = blackcat_getuserkey(&new_key_size[0])) == NULL) {
        exit_code = EFAULT;
        fprintf(stderr, "ERROR: Unable to get the user's key.\n");
        goto blackcat_cmd_setkey_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();

    fprintf(stdout, "Confirm the %s: ", prompt);
    if ((new_key[2] = blackcat_getuserkey(&new_key_size[2])) == NULL) {
        exit_code = EFAULT;
        fprintf(stderr, "ERROR: Unable to get the user's key.\n");
        goto blackcat_cmd_setkey_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();
    fflush(stdout);

    if (new_key_size[0] != new_key_size[2] || memcmp(new_key[0], new_key[2], new_key_size[0]) != 0) {
        exit_code = EFAULT;
        fprintf(stderr, "ERROR: The supplied keys do not match.\n");
        goto blackcat_cmd_setkey_epilogue;
    }

    kryptos_freeseg(new_key[2], new_key_size[2]);
    new_key[2] = NULL;
    new_key_size[2] = 0;

    if (keyed_alike) {
        new_key[1] = (kryptos_u8_t *)kryptos_newseg(new_key_size[0]);

        if (new_key[1] == NULL) {
            exit_code = EFAULT;
            fprintf(stdout, "ERROR: Not enough memory.\n");
            goto blackcat_cmd_setkey_epilogue;
        }

        new_key_size[1] = new_key_size[0];
        memcpy(new_key[1], new_key[0], new_key_size[0]);
    } else {
        prompt = "new second layer key";

        fprintf(stdout, "Type the %s: ", prompt);
        if ((new_key[1] = blackcat_getuserkey(&new_key_size[1])) == NULL) {
            exit_code = EFAULT;
            fprintf(stderr, "ERROR: Unable to get the user's key.\n");
            goto blackcat_cmd_setkey_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();

        fprintf(stdout, "Confirm the %s: ", prompt);
        if ((new_key[2] = blackcat_getuserkey(&new_key_size[2])) == NULL) {
            exit_code = EFAULT;
            fprintf(stderr, "ERROR: Unable to get the user's key.\n");
            goto blackcat_cmd_setkey_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        if (new_key_size[1] != new_key_size[2] || memcmp(new_key[1], new_key[2], new_key_size[1]) != 0) {
            exit_code = EFAULT;
            fprintf(stderr, "ERROR: The supplied keys do not match.\n");
            goto blackcat_cmd_setkey_epilogue;
        }

        kryptos_freeseg(new_key[2], new_key_size[2]);
        new_key[2] = NULL;
        new_key_size[2] = 0;
    }

    new_key[2] = (kryptos_u8_t *)kryptos_newseg(4);

    if (new_key[2] == NULL) {
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto blackcat_cmd_setkey_epilogue;
    }

    if (protection_layer != NULL) {
        new_key_size[2] = 4;
        memcpy(new_key[2], "meow", 4);

        p_layer = add_composite_protlayer_to_chain(p_layer,
                                                   protection_layer, &new_key[2], &new_key_size[2],
                                                   protection_layer_hash_proc, encoder_proc);

        if (p_layer == NULL) {
            fprintf(stderr, "ERROR: Invalid protection layer.\n");
            goto blackcat_cmd_setkey_epilogue;
        }

        new_key[2] = NULL;

        del_protlayer_chain_ctx(p_layer);
        p_layer = NULL;
    }

    if (bcrepo_reset_repo_settings(&session->catalog,
                                   session->rootpath, session->rootpath_size,
                                   new_key[0], new_key_size[0], &new_key[1], &new_key_size[1],
                                   protection_layer,
                                   catalog_hash_proc, key_hash_proc, key_hash_algo_args, protection_layer_hash_proc,
                                   encoder_proc,
                                   blackcat_checkpoint,
                                   session) != 1) {
        exit_code = EFAULT;
        goto blackcat_cmd_setkey_epilogue;
    }

    exit_code = 0;

blackcat_cmd_setkey_epilogue:

    prompt = NULL;

    if (p_layer != NULL) {
        del_protlayer_chain_ctx(p_layer);
    }

    if (new_key[0] != NULL) {
        kryptos_freeseg(new_key[0], new_key_size[0]);
        new_key_size[0] = 0;
    }

    if (new_key[1] != NULL) {
        kryptos_freeseg(new_key[1], new_key_size[1]);
        new_key_size[1] = 0;
    }

    if (new_key[2] != NULL) {
        kryptos_freeseg(new_key[2], new_key_size[2]);
        new_key_size[2] = 0;
    }

    if (session != NULL) {
        del_blackcat_exec_session_ctx(session);
    }

    catalog_hash_proc = key_hash_proc = protection_layer_hash_proc = NULL;

    return exit_code;
}

int blackcat_cmd_setkey_help(void) {
    fprintf(stdout, "use: blackcat setkey [--keyed-alike --catalog-hash=<hash> "
                    "--key-hash=<hash> --protection-layer-hash=<hash> --encoder=<encoder> "
                    "--protection-layer=<algorithm layers>]\n");
    return 0;
}
