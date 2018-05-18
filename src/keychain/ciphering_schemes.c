/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/ciphering_schemes.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void blackcat_NULL(kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer) {
    printf("PANIC: Hi there! You have hit a NULL cipher processor there is nothing beyond here.\n"
           "       If you are seeing this message it means that a pretty stupid developer screwed up something.\n"
           "       Please report this error to someone smarter (if possible) telling what version you are using and\n"
           "       cross your fingers.\n"
           "       Thanks!\n");
    exit(1);
}

int blackcat_NULL_args(const char *algo_params,
                       void **args, const size_t args_nr,
                       kryptos_u8_t *key, const size_t key_size,
                       size_t *argc, char *err_msg) {
    printf("PANIC: Hi there! You have hit a NULL cipher args reader there is nothing beyond here.\n"
           "       If you are seeing this message it means that a pretty stupid developer screwed up something.\n"
           "       Please report this error to someone smarter (if possible) telling what version you are using and\n"
           "       cross your fingers.\n"
           "       Thanks!\n");
    exit(1);
    return 1;
}

ssize_t get_algo_index(const char *algo_params) {
    ssize_t a;

    if (algo_params == NULL) {
        return -1;
    }

    for (a = 0; a < g_blackcat_ciphering_schemes_nr; a++) {
        if (strstr(algo_params, g_blackcat_ciphering_schemes[a].name) == algo_params) {
            return a;
        }
    }

    return -1;
}
