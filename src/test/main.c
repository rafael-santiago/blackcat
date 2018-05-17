/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <cutest.h>
#include <memory/memory.h>
#include <ctx/ctx.h>
#include <string.h>

CUTE_DECLARE_TEST_CASE(memory_tests);

CUTE_DECLARE_TEST_CASE(ctx_tests);

CUTE_DECLARE_TEST_CASE(blackcat_derive_key_tests);

CUTE_TEST_CASE(blackcat_base_tests_entry)
    CUTE_RUN_TEST(memory_tests);
    CUTE_RUN_TEST(ctx_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(blackcat_base_tests_entry)

CUTE_TEST_CASE(blackcat_derive_key_tests)
    
CUTE_TEST_CASE_END

CUTE_TEST_CASE(memory_tests)
    void *data;
    size_t data_size = 1024;

    data = blackcat_getseg(1024);
    CUTE_ASSERT(data != NULL);
    memset(data, 1, 1024);
    blackcat_free(data, NULL);

    data = blackcat_getseg(data_size);
    CUTE_ASSERT(data != NULL);
    memset(data, 1, data_size);
    blackcat_free(data, &data_size);
    CUTE_ASSERT(data_size == 0);

    blackcat_free(NULL, NULL);
    blackcat_free(NULL, &data_size);
    // WARN(Rafael): The libcutest memory leak check system will catch any non well freed memory area.
CUTE_TEST_CASE_END

CUTE_TEST_CASE(ctx_tests)
    blackcat_protlayer_chain_ctx *pchain = NULL;

    pchain = add_protlayer_to_chain(pchain, "hmac-aes-256-cbc", "envious", 7);

    CUTE_ASSERT(pchain == NULL);

    pchain = add_protlayer_to_chain(pchain, "seal/2-156-293", "password", 8);

    CUTE_ASSERT(pchain != NULL);

    CUTE_ASSERT(pchain->head == pchain);
    CUTE_ASSERT(pchain->tail == pchain);
    //CUTE_ASSERT(pchain->key == NULL);
    //CUTE_ASSERT(pchain->key_size == 0);
    CUTE_ASSERT(pchain->last == NULL);
    CUTE_ASSERT(pchain->next == NULL);

    pchain = add_protlayer_to_chain(pchain, "hmac-sha224-aes-256-cbc", "envious", 7);

    CUTE_ASSERT(pchain != NULL);

    CUTE_ASSERT(pchain->head == pchain);
    CUTE_ASSERT(pchain->tail == pchain->next);
    CUTE_ASSERT(pchain->last == NULL);
    CUTE_ASSERT(pchain->next != NULL);

    CUTE_ASSERT(pchain->next->head == NULL);
    CUTE_ASSERT(pchain->next->tail == NULL);
    //CUTE_ASSERT(pchain->next->key == NULL);
    //CUTE_ASSERT(pchain->next->key_size == 0);
    CUTE_ASSERT(pchain->next->last == pchain);
    CUTE_ASSERT(pchain->next->next == NULL);

    del_protlayer_chain_ctx(pchain);
CUTE_TEST_CASE_END
