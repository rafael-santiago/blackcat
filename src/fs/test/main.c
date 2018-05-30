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
#include <sys/stat.h>
#include <sys/types.h>

#define BCREPO_DATA "bcrepo.data"

CUTE_DECLARE_TEST_CASE(fs_tests);
CUTE_DECLARE_TEST_CASE(relpath_ctx_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_write_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_read_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_stat_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_validate_key_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_get_rootpath_tests);

CUTE_MAIN(fs_tests);

CUTE_TEST_CASE(fs_tests)
    remove(BCREPO_DATA);
    CUTE_RUN_TEST(relpath_ctx_tests);
    CUTE_RUN_TEST(bcrepo_write_tests);
    CUTE_RUN_TEST(bcrepo_read_tests);
    CUTE_RUN_TEST(bcrepo_stat_tests);
    CUTE_RUN_TEST(bcrepo_validate_key_tests);
    remove(BCREPO_DATA);
    CUTE_RUN_TEST(bcrepo_get_rootpath_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_get_rootpath_tests)
    // WARN(Rafael): This test can't be ran inside of a "repo".
    char *rootpath;
    char cwd[4096];
    rmdir(".bcrepo");
    rmdir("../.bcrepo");

    getcwd(cwd, sizeof(cwd));

    rootpath = bcrepo_get_rootpath();
    CUTE_ASSERT(rootpath == NULL);

    mkdir(".bcrepo", 0666);

    rootpath = bcrepo_get_rootpath();
    CUTE_ASSERT(rootpath != NULL);
    CUTE_ASSERT(strcmp(rootpath, cwd) == 0);

    kryptos_freeseg(rootpath);
    rmdir(".bcrepo");

    chdir("..");

    getcwd(cwd, sizeof(cwd));

    rmdir(".bcrepo");
    mkdir(".bcrepo", 0666);
    chdir("test");

    rootpath = bcrepo_get_rootpath();
    CUTE_ASSERT(rootpath != NULL);
    CUTE_ASSERT(strcmp(rootpath, cwd) == 0);

    kryptos_freeseg(rootpath);
    rmdir(".bcrepo");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_validate_key_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *repo_key = "parangaricutirimirruaru";
    kryptos_u8_t *key = "the suits, the law & the uniform"; // btw, a wrong key.
    kryptos_u8_t *data = NULL;
    size_t data_size;

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    data = bcrepo_read(BCREPO_DATA, catalog, &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);

    CUTE_ASSERT(bcrepo_stat(&catalog, repo_key, strlen(repo_key), &data, &data_size) == 1);

    CUTE_ASSERT(bcrepo_validate_key(catalog, repo_key, strlen(repo_key)) == 0);
    CUTE_ASSERT(bcrepo_validate_key(catalog, key, strlen(key)) == 0);

    key = "Goliath";

    CUTE_ASSERT(bcrepo_validate_key(catalog, key, strlen(key)) == 1);

    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_stat_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *data = NULL;
    size_t data_size;
    // INFO(Rafael): 'Goliath' hashed with SHA-224.
    kryptos_u8_t *protlayer_key_hash = "DE5F31A972D8EF1BFD1045E6299AD2B0F8EC2E85454D38A4D7252430";

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    data = bcrepo_read(BCREPO_DATA, catalog, &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size > 0);

    CUTE_ASSERT(bcrepo_stat(&catalog, "parangaricutirimirruaru", strlen("parangaricutirimirruaru"), &data, &data_size) == 1);

    CUTE_ASSERT(data == NULL);
    CUTE_ASSERT(data_size == 0);

    CUTE_ASSERT(catalog->bc_version != NULL);
    CUTE_ASSERT(strcmp(catalog->bc_version, "0.0.1") == 0);

    // INFO(Rafael): If it was correctly read for sure that the hmac_scheme must match.
    //               Test it would be a little bit stupid.

    CUTE_ASSERT(catalog->key_hash_algo == get_hash_processor("sha224"));
    CUTE_ASSERT(catalog->key_hash_algo_size == get_hash_size("sha224"));
    CUTE_ASSERT(catalog->protlayer_key_hash_algo == get_hash_processor("sha3-384"));
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size == get_hash_size("sha3-384"));

    CUTE_ASSERT(catalog->key_hash != NULL);
    // TIP(Rafael): This hash is stored in hexadecimal format.
    CUTE_ASSERT(catalog->key_hash_size == (catalog->key_hash_algo_size() << 1));
    // INFO(Rafael): This repo has a secondary (protection layer) key, that is 'Goliath' not 'parangaricutirimirruaru'.
    //               The real validation of it is tested in 'bcrepo_validate_key_tests'.
    CUTE_ASSERT(memcmp(catalog->key_hash, protlayer_key_hash, strlen(protlayer_key_hash)) == 0);

    CUTE_ASSERT(catalog->protection_layer != NULL);
    CUTE_ASSERT(strcmp(catalog->protection_layer, "aes-256-ctr|hmac-whirlpool-cast5-cbc") == 0);

    CUTE_ASSERT(catalog->files != NULL);

    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files);
    CUTE_ASSERT(catalog->files->next == NULL); // INFO(Rafael): I meant, only one item.

    CUTE_ASSERT(catalog->files->last == NULL);
    CUTE_ASSERT(catalog->files->path != NULL);
    CUTE_ASSERT(strcmp(catalog->files->path, "a/b/c.txt") == 0);
    CUTE_ASSERT(catalog->files->path_size == strlen(catalog->files->path));
    CUTE_ASSERT(catalog->files->status == 'U');
    CUTE_ASSERT(strcmp(catalog->files->timestamp, "123456789") == 0);

    del_bfs_catalog_ctx(catalog);

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    data = bcrepo_read(BCREPO_DATA, catalog, &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size > 0);

    CUTE_ASSERT(bcrepo_stat(&catalog, "wrong password", strlen("wrong password"), &data, &data_size) == 0);

    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size > 0);

    kryptos_freeseg(data);

    del_bfs_catalog_ctx(catalog);
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
    printf(" Current HMAC-scheme['%s']\n", hmac_algo);

    CUTE_ASSERT(hmac_algo != NULL);

    CUTE_ASSERT(catalog.hmac_scheme == get_hmac_catalog_scheme(hmac_algo));

    kryptos_freeseg(data);
    kryptos_freeseg(hmac_algo);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_write_tests)
    bfs_catalog_ctx catalog;
    bfs_catalog_relpath_ctx files;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "Goliath";

    catalog.bc_version = "0.0.1";
    catalog.hmac_scheme = get_hmac_catalog_scheme("hmac-sha3-256-tea-ofb");
    catalog.key_hash_algo = get_hash_processor("sha224");
    catalog.key_hash_algo_size = get_hash_size("sha224");
    catalog.protlayer_key_hash_algo = get_hash_processor("sha3-384");
    catalog.protlayer_key_hash_algo_size = get_hash_size("sha3-384");

    ktask->in = key;
    ktask->in_size = strlen(key);
    catalog.key_hash_algo(&ktask, 1);

    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    catalog.key_hash = ktask->out;
    catalog.key_hash_size = ktask->out_size;
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

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
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
