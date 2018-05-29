/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <string.h>
#include <ctx/fsctx.h>
#include <bcrepo/bcrepo.h>
#include <keychain/ciphering_schemes.h>
#include <kryptos_pem.h>
#include <stdio.h>

#define BCREPO_DATA "bcrepo.data"

CUTE_DECLARE_TEST_CASE(fs_tests);
CUTE_DECLARE_TEST_CASE(relpath_ctx_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_write_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_read_tests);

CUTE_MAIN(fs_tests);

CUTE_TEST_CASE(fs_tests)
    CUTE_RUN_TEST(relpath_ctx_tests);
    CUTE_RUN_TEST(bcrepo_write_tests);
    CUTE_RUN_TEST(bcrepo_read_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_read_tests)
    bfs_catalog_ctx catalog;
    kryptos_u8_t *data;
    size_t data_size;
    kryptos_u8_t *hmac_algo;
    size_t hmac_algo_size;

    data = bcrepo_read(BCREPO_DATA, &catalog, &data_size);

    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != 0);

    hmac_algo = kryptos_pem_get_data("BCREPO HMAC SCHEME", data, data_size, &hmac_algo_size);
    printf(" Current HMAC scheme['%s']\n", hmac_algo);

    CUTE_ASSERT(hmac_algo != NULL);

    CUTE_ASSERT(catalog.hmac_scheme == get_hmac_catalog_scheme(hmac_algo));

    kryptos_freeseg(data);
    kryptos_freeseg(hmac_algo);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_write_tests)
    bfs_catalog_ctx catalog;
    bfs_catalog_relpath_ctx files;

    remove(BCREPO_DATA);

    catalog.bc_version = "0.0.1";
    catalog.hmac_scheme = get_hmac_catalog_scheme("hmac-sha3-256-tea-ofb");
    catalog.key_hash_algo = get_hash_processor("sha224");
    catalog.key_hash_algo_size = get_hash_size("sha224");
    catalog.protlayer_key_hash_algo = get_hash_processor("sha3-384");
    catalog.protlayer_key_hash_algo_size = get_hash_size("sha3-384");
    catalog.key_hash = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    catalog.key_hash_size = 48;
    catalog.protection_layer = "aes-256-ctr|hmac-whirlpool-cast5-cbc";
    catalog.files = &files;

    files.head = &files;
    files.tail = &files;
    files.path = "a/b/c.txt";
    files.path_size = strlen("a/b/c.txt");
    files.status = 'U';
    sprintf(files.timestamp, "%s", "123456789");
    files.last = NULL;
    files.next = NULL;

    CUTE_ASSERT(bcrepo_write(BCREPO_DATA, &catalog, "parangaricutirimirruaru", strlen("parangaricutirimirruaru")) == 1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(relpath_ctx_tests)
    bfs_catalog_relpath_ctx *relpath = NULL, *p;

    relpath = add_file_to_relpath_ctx(relpath, "a/b/c.txt", strlen("a/b/c.txt"), 'U', NULL);

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->tail == relpath);
    CUTE_ASSERT(relpath->last == NULL);

    CUTE_ASSERT(relpath->path != NULL);
    CUTE_ASSERT(strcmp(relpath->path, "a/b/c.txt") == 0);
    CUTE_ASSERT(relpath->status == 'U');
    CUTE_ASSERT(relpath->timestamp != NULL);

    relpath = add_file_to_relpath_ctx(relpath, "a/b/c.txt", strlen("a/b/c.txt"), 'U', NULL);

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->tail == relpath);
    CUTE_ASSERT(relpath->last == NULL);

    relpath = add_file_to_relpath_ctx(relpath, "a/b/d.txt", strlen("a/b/d.txt"), 'U', "123456789");

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->next != NULL);
    CUTE_ASSERT(relpath->tail == relpath->next);

    CUTE_ASSERT(relpath->next->last == relpath);
    CUTE_ASSERT(relpath->next->path != NULL);
    CUTE_ASSERT(strcmp(relpath->next->path, "a/b/d.txt") == 0);
    CUTE_ASSERT(relpath->next->status == 'U');
    CUTE_ASSERT(relpath->next->timestamp != NULL);
    CUTE_ASSERT(strcmp(relpath->next->timestamp, "123456789") == 0);

    relpath = add_file_to_relpath_ctx(relpath, "a/b/e.txt", strlen("a/b/e.txt"), 'U', NULL);

    CUTE_ASSERT(relpath != NULL);
    CUTE_ASSERT(relpath->head == relpath);
    CUTE_ASSERT(relpath->next->next != NULL);
    CUTE_ASSERT(relpath->tail == relpath->next->next);

    CUTE_ASSERT(relpath->next->next->last == relpath->next);
    CUTE_ASSERT(relpath->next->next->path != NULL);
    CUTE_ASSERT(strcmp(relpath->next->next->path, "a/b/e.txt") == 0);
    CUTE_ASSERT(relpath->next->next->status == 'U');
    CUTE_ASSERT(relpath->next->next->timestamp != NULL);

    p = relpath;
    relpath = del_file_from_relpath_ctx(relpath, "a/b/z.txt");
    CUTE_ASSERT(relpath == p);

    p = relpath;
    relpath = del_file_from_relpath_ctx(relpath, "a/b/e.txt");
    CUTE_ASSERT(relpath == p);
    CUTE_ASSERT(relpath->next != NULL);
    CUTE_ASSERT(relpath->next->next == NULL);
    CUTE_ASSERT(relpath->head == p);
    CUTE_ASSERT(relpath->tail == relpath->next);

    p = relpath->next;
    relpath = del_file_from_relpath_ctx(relpath, "a/b/c.txt");
    CUTE_ASSERT(relpath == p);
    CUTE_ASSERT(relpath->next == NULL);
    CUTE_ASSERT(relpath->head == p);
    CUTE_ASSERT(relpath->tail == p);

    relpath = del_file_from_relpath_ctx(relpath, "a/b/d.txt");
    CUTE_ASSERT(relpath == NULL);

    // INFO(Rafael): If this function is failing the memory leak check system will detect this malfunction for us.
    //               This function is internally called by del_file_from_relpath_ctx().
    del_bfs_catalog_relpath_ctx(relpath);
CUTE_TEST_CASE_END
