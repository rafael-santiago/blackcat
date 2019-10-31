/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <string.h>
#include <base/test/huge_protchain.h>
#include <ctx/fsctx.h>
#include <ctx/ctx.h>
#include <bcrepo/bcrepo.h>
#include <bcrepo/config.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/processor.h>
#include <keychain/kdf/kdf_utils.h>
#include <fs/strglob.h>
#include <kryptos_pem.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BCREPO_DATA "bcrepo.data"

char *g_fs_test_protlayer = NULL;

CUTE_DECLARE_TEST_CASE(fs_tests);
CUTE_DECLARE_TEST_CASE(relpath_ctx_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_write_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_read_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_stat_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_validate_key_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_get_rootpath_tests);
CUTE_DECLARE_TEST_CASE(strglob_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_init_deinit_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_add_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_rm_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_lock_unlock_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_catalog_file_tests);
CUTE_DECLARE_TEST_CASE(remove_go_ups_from_path_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_pack_unpack_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_reset_repo_settings_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_restore_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_decoy_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_incompatibility_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_detach_attach_metainfo_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_untouch_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_config_module_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_config_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_metadata_version_tests);

struct checkpoint_ctx {
    bfs_catalog_ctx *catalog;
    kryptos_u8_t *rootpath;
    size_t rootpath_size;
    size_t key_size;
    kryptos_u8_t *key;
};

int save_text(const char *data, const size_t data_size, const char *filepath);
char *open_text(const char *filepath, size_t *data_size);
int checkpoint(void *args);

CUTE_MAIN(fs_tests);

CUTE_TEST_CASE(fs_tests)
    g_fs_test_protlayer = get_test_protlayer(1, 3);
    CUTE_ASSERT(g_fs_test_protlayer != NULL);
    CUTE_RUN_TEST(bcrepo_metadata_version_tests);
    CUTE_RUN_TEST(bcrepo_incompatibility_tests);
    CUTE_ASSERT(save_text("aes", 3, "o/aes.o") == 1);
    CUTE_ASSERT(save_text("des", 3, "o/des.o") == 1);
    CUTE_ASSERT(save_text("mars", 4, "o/mars.o") == 1);
    CUTE_ASSERT(save_text("...", 3, "o/ciphering_schemes.o") == 1);
    CUTE_RUN_TEST(remove_go_ups_from_path_tests);
    remove(".bcrepo/CATALOG");
    remove(".bcrepo/rescue");
    rmdir(".bcrepo");
    rmdir("../.bcrepo");
    remove(BCREPO_DATA);
    CUTE_RUN_TEST(relpath_ctx_tests);
    CUTE_RUN_TEST(bcrepo_write_tests);
    CUTE_RUN_TEST(bcrepo_read_tests);
    CUTE_RUN_TEST(bcrepo_stat_tests);
    CUTE_RUN_TEST(bcrepo_validate_key_tests);
    remove(BCREPO_DATA);
    CUTE_RUN_TEST(bcrepo_get_rootpath_tests);
    CUTE_RUN_TEST(bcrepo_catalog_file_tests);
    CUTE_RUN_TEST(strglob_tests);
    CUTE_RUN_TEST(bcrepo_init_deinit_tests);
    CUTE_RUN_TEST(bcrepo_add_tests);
    CUTE_RUN_TEST(bcrepo_lock_unlock_tests);
    CUTE_RUN_TEST(bcrepo_rm_tests);
    CUTE_RUN_TEST(bcrepo_pack_unpack_tests);
    CUTE_RUN_TEST(bcrepo_reset_repo_settings_tests);
    CUTE_RUN_TEST(bcrepo_restore_tests);
    remove("o/aes.o");
    remove("o/des.o");
    remove("o/mars.o");
    remove("o/ciphering_schemes.o");
    CUTE_RUN_TEST(bcrepo_decoy_tests);
    CUTE_RUN_TEST(bcrepo_detach_attach_metainfo_tests);
    CUTE_RUN_TEST(bcrepo_untouch_tests);
    CUTE_RUN_TEST(bcrepo_config_module_tests);
    CUTE_RUN_TEST(bcrepo_config_tests);
    free(g_fs_test_protlayer);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_metadata_version_tests)
    const char *version = bcrepo_metadata_version();
    CUTE_ASSERT(version != NULL);
    CUTE_ASSERT(strcmp(version, BCREPO_METADATA_VERSION) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_config_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "live2win";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    //kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    char *config_data = "default-args:\n"
                        "\t--no-swap\n\n";
    struct checkpoint_ctx ckpt;
    struct blackcat_keychain_handle_ctx handle;

    // INFO(Rafael): The painful handmade bootstrapping arrrgh!

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->otp = 0;
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("tiger");
    catalog->key_hash_algo_size = get_hash_size("tiger");
    catalog->protlayer_key_hash_algo = get_hash_processor("whirlpool");
    catalog->protlayer_key_hash_algo_size = get_hash_size("whirlpool");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 1);

    protkey = (kryptos_u8_t *) kryptos_newseg(15);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "ready to forget", 15);
    protkey_size = 15;

    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    ckpt.catalog = catalog;
    ckpt.rootpath = rootpath;
    ckpt.rootpath_size = rootpath_size;
    ckpt.key = key;
    ckpt.key_size = strlen(key);

    CUTE_ASSERT(save_text(config_data, strlen(config_data), ".bcrepo/CONFIG") == 1);
    CUTE_ASSERT(bcrepo_config_update(&catalog, rootpath, rootpath_size, checkpoint, &ckpt) == 1);
    CUTE_ASSERT(bcrepo_check_config_integrity(catalog, rootpath, rootpath_size) == 1);
    CUTE_ASSERT(save_text("boo", 3, ".bcrepo/CONFIG") == 1);
    CUTE_ASSERT(bcrepo_check_config_integrity(catalog, rootpath, rootpath_size) == 0);
    CUTE_ASSERT(bcrepo_config_update(&catalog, rootpath, rootpath_size, checkpoint, &ckpt) == 1);
    CUTE_ASSERT(bcrepo_check_config_integrity(catalog, rootpath, rootpath_size) == 1);
    CUTE_ASSERT(bcrepo_config_remove(&catalog, rootpath, rootpath_size, checkpoint, &ckpt) == 1);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    kryptos_freeseg(rootpath, rootpath_size);

    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_config_module_tests)
    char *config = "default-opts:\nword0 word1 word2\n\n"
                   "hello:\ncommand line 0\ncommand line 1\ncommand line 2\n\n";
    FILE *fp;
    struct bcrepo_config_ctx *cfg;

    cfg = bcrepo_ld_config();
    CUTE_ASSERT(cfg == NULL);

#if defined(__unix__)
    CUTE_ASSERT(mkdir(".bcrepo", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir(".bcrepo") == 0);
#else
# error Some code wanted.
#endif

    fp = fopen(".bcrepo/CONFIG", "wb");
    CUTE_ASSERT(fp != NULL);
    fprintf(fp, "%s", config);
    fclose(fp);

    cfg = bcrepo_ld_config();

    CUTE_ASSERT(cfg != NULL);

    CUTE_ASSERT(bcrepo_config_get_section(cfg, "unknown-section") == 0);
    CUTE_ASSERT(bcrepo_config_get_section(cfg, "DEFAULT-OPTS") == 0);
    CUTE_ASSERT(bcrepo_config_get_section(cfg, "default-opts") == 1);
    CUTE_ASSERT(bcrepo_config_get_section(cfg, "Hello") == 0);
    CUTE_ASSERT(bcrepo_config_get_section(cfg, "hello") == 1);

    CUTE_ASSERT(bcrepo_config_get_section(cfg, "hello") == 1);
    CUTE_ASSERT(bcrepo_config_get_next_line(cfg) == 1);
    CUTE_ASSERT(memcmp(cfg->line, "command line 0", cfg->line_end - cfg->line) == 0);
    CUTE_ASSERT(bcrepo_config_get_next_line(cfg) == 1);
    CUTE_ASSERT(memcmp(cfg->line, "command line 1", cfg->line_end - cfg->line) == 0);
    CUTE_ASSERT(bcrepo_config_get_next_line(cfg) == 1);
    CUTE_ASSERT(memcmp(cfg->line, "command line 2", cfg->line_end - cfg->line) == 0);
    CUTE_ASSERT(bcrepo_config_get_next_line(cfg) == 0);
    CUTE_ASSERT(cfg->line == NULL && cfg->line_end == NULL);

    CUTE_ASSERT(bcrepo_config_get_section(cfg, "default-opts") == 1);
    CUTE_ASSERT(bcrepo_config_get_next_word(cfg) == 1);
    CUTE_ASSERT(memcmp(cfg->word, "word0", cfg->word_end - cfg->word) == 0);
    CUTE_ASSERT(bcrepo_config_get_next_word(cfg) == 1);
    CUTE_ASSERT(memcmp(cfg->word, "word1", cfg->word_end - cfg->word) == 0);
    CUTE_ASSERT(bcrepo_config_get_next_word(cfg) == 1);
    CUTE_ASSERT(memcmp(cfg->word, "word2", cfg->word_end - cfg->word) == 0);
    CUTE_ASSERT(bcrepo_config_get_next_word(cfg) == 0);
    CUTE_ASSERT(cfg->word == NULL && cfg->word_end == NULL);

    bcrepo_release_config(cfg);

    CUTE_ASSERT(remove(".bcrepo/CONFIG") == 0);

    CUTE_ASSERT(rmdir(".bcrepo") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_untouch_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "nao, sei... so sei que foi assim";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;
    const char *sensitive = "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Looking in my own eyes \"hello\"\n"
                            "I can't find the love I want\n"
                            "Someone better slap me\n"
                            "Before I start to rust\n"
                            "Before I start to decompose\n"
                            "Looking in my rear view mirror\n"
                            "I can make it disappear\n"
                            "I can make it disappear \"have no fear\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Sitting in my kitchen hey girl\n"
                            "I'm turning into dust again\n"
                            "My melancholy baby\n"
                            "The star of mazzy must\n"
                            "Push her voice inside of me\n"
                            "I'm overcoming gravity\n"
                            "I'm overcoming gravity\n"
                            "It's easy when you're sad to be\n"
                            "It's easy when you're sad \"said 'bout me\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "Just one note\n"
                            "Could make me float\n"
                            "Could make me float away\n"
                            "One note from\n"
                            "The song she wrote\n"
                            "Could fuck me where I lay\n"
                            "Just one note\n"
                            "Could make me choke\n"
                            "One note that's\n"
                            "Not a lie\n"
                            "Just one note\n"
                            "Could cut my throat\n"
                            "One could make me die\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n";
    const char *plain = "A new day yesteday.";
    char *data;
    size_t data_size;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    char oldcwd[4096];
    FILE *fp;
    struct stat st_old, st_curr, etc_old, etc_curr, bcrepo_old, bcrepo_curr;
    struct blackcat_keychain_handle_ctx handle;
    char str_time[100];

    // INFO(Rafael): Bootstrapping the test repo.

    remove("untouch-test/.bcrepo/CATALOG");
    remove("untouch-test/.bcrepo/rescue");
    remove("untouch-test/etc/sensitive.txt");
    remove("untouch-test/plain.txt");
    remove("untouch-test/.get_test_protlayer");
    rmdir("untouch-test/.bcrepo");
    rmdir("untouch-test/etc");
    rmdir("untouch-test");

#if defined(__unix__)
    CUTE_ASSERT(mkdir("untouch-test", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("untouch-test") == 0);
#endif

    CUTE_ASSERT(chdir("untouch-test") == 0);

#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#endif

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->catalog_key_hash_algo = get_hash_processor("sha-384");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-384");
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha-512");
    catalog->key_hash_algo_size = get_hash_size("sha-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");
    catalog->encoder = get_encoder("uuencode");
    catalog->otp = 0;
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);
    CUTE_ASSERT(catalog->encoder != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 5);

    protkey = (kryptos_u8_t *) kryptos_newseg(9);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "aeroplane", 9);
    protkey_size = 9;

    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "etc/sensitive.txt") == 1);
    CUTE_ASSERT(save_text(plain, strlen(plain), "plain.txt") == 1);

    pattern = "etc/sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "plain.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next);

    CUTE_ASSERT(stat(".bcrepo", &bcrepo_old) == 0);

    CUTE_ASSERT(stat("etc", &etc_old) == 0);

    CUTE_ASSERT(stat("etc/sensitive.txt", &st_old) == 0);

    CUTE_ASSERT(bcrepo_untouch(catalog, rootpath, rootpath_size, "etc/sensitive.txt", 13, 0) == 1);

    CUTE_ASSERT(stat("etc/sensitive.txt", &st_curr) == 0);

    CUTE_ASSERT(stat("etc", &etc_curr) == 0);

#if defined(__unix__)
    CUTE_ASSERT(memcmp(&st_curr.st_atime, &st_old.st_atim, sizeof(st_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_atim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_mtim, &st_old.st_mtim, sizeof(st_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_mtim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_ctim, &st_old.st_ctim, sizeof(st_old.st_ctime)) == 0);
    CUTE_ASSERT(memcmp(&etc_curr.st_atim, &etc_old.st_atim, sizeof(etc_old.st_atime)) == 0);
    CUTE_ASSERT(memcmp(&etc_curr.st_mtim, &etc_old.st_atim, sizeof(etc_old.st_mtime)) == 0);
    CUTE_ASSERT(memcmp(&etc_curr.st_ctim, &etc_old.st_ctim, sizeof(etc_old.st_ctime)) == 0);

    CUTE_ASSERT(bcrepo_untouch(catalog, rootpath, rootpath_size, "etc/sensitive.txt", 13, 1) == 1);

    CUTE_ASSERT(stat("etc/sensitive.txt", &st_curr) == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_atim, &st_old.st_atim, sizeof(st_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_atim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_mtim, &st_old.st_mtim, sizeof(st_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_mtim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_ctim, &st_old.st_ctim, sizeof(st_old.st_ctime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_ctim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(stat("etc", &etc_curr) == 0);

    CUTE_ASSERT(memcmp(&etc_curr.st_atim, &etc_old.st_atim, sizeof(etc_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&etc_curr.st_atim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&etc_curr.st_mtim, &etc_old.st_mtim, sizeof(etc_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&etc_curr.st_mtim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(stat(".bcrepo", &bcrepo_curr) == 0);

    CUTE_ASSERT(memcmp(&bcrepo_curr.st_atim, &bcrepo_old.st_atim, sizeof(bcrepo_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&bcrepo_curr.st_atim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&bcrepo_curr.st_mtim, &bcrepo_old.st_mtim, sizeof(bcrepo_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&bcrepo_curr.st_mtim.tv_sec));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(memcmp(&st_curr.st_atime, &st_old.st_atime, sizeof(st_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_atime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_mtime, &st_old.st_mtime, sizeof(st_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_mtime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_ctime, &st_old.st_ctime, sizeof(st_old.st_ctime)) == 0);
    CUTE_ASSERT(memcmp(&etc_curr.st_atime, &etc_old.st_atime, sizeof(etc_old.st_atime)) == 0);
    CUTE_ASSERT(memcmp(&etc_curr.st_mtime, &etc_old.st_atime, sizeof(etc_old.st_mtime)) == 0);
    CUTE_ASSERT(memcmp(&etc_curr.st_ctime, &etc_old.st_ctime, sizeof(etc_old.st_ctime)) == 0);

    CUTE_ASSERT(bcrepo_untouch(catalog, rootpath, rootpath_size, "etc/sensitive.txt", 13, 1) == 1);

    CUTE_ASSERT(stat("etc/sensitive.txt", &st_curr) == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_atime, &st_old.st_atime, sizeof(st_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_atime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_mtime, &st_old.st_mtime, sizeof(st_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_mtime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&st_curr.st_ctime, &st_old.st_ctime, sizeof(st_old.st_ctime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&st_curr.st_ctime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(stat("etc", &etc_curr) == 0);

    CUTE_ASSERT(memcmp(&etc_curr.st_atime, &etc_old.st_atime, sizeof(etc_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&etc_curr.st_atime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&etc_curr.st_mtime, &etc_old.st_mtime, sizeof(etc_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&etc_curr.st_mtime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(stat(".bcrepo", &bcrepo_curr) == 0);

    CUTE_ASSERT(memcmp(&bcrepo_curr.st_atime, &bcrepo_old.st_atime, sizeof(bcrepo_old.st_atime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&bcrepo_curr.st_atime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);

    CUTE_ASSERT(memcmp(&bcrepo_curr.st_mtime, &bcrepo_old.st_mtime, sizeof(bcrepo_old.st_mtime)) != 0);

    g_cute_leak_check = !g_cute_leak_check;
    strftime(str_time, sizeof(str_time), "%Y", localtime(&bcrepo_curr.st_mtime));
    g_cute_leak_check = !g_cute_leak_check;

    CUTE_ASSERT(strcmp(str_time, "1970") == 0);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    remove("etc/sensitive.txt");
    remove("plain.txt");
    remove("metainfo.txt");
    remove(".get_test_protlayer");
    rmdir("etc");

    CUTE_ASSERT(chdir("..") == 0);

    CUTE_ASSERT(rmdir("untouch-test") == 0);

    kryptos_freeseg(rootpath, rootpath_size);
    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_detach_attach_metainfo_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "nao, sei... so sei que foi assim";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;
    const char *sensitive = "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Looking in my own eyes \"hello\"\n"
                            "I can't find the love I want\n"
                            "Someone better slap me\n"
                            "Before I start to rust\n"
                            "Before I start to decompose\n"
                            "Looking in my rear view mirror\n"
                            "I can make it disappear\n"
                            "I can make it disappear \"have no fear\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Sitting in my kitchen hey girl\n"
                            "I'm turning into dust again\n"
                            "My melancholy baby\n"
                            "The star of mazzy must\n"
                            "Push her voice inside of me\n"
                            "I'm overcoming gravity\n"
                            "I'm overcoming gravity\n"
                            "It's easy when you're sad to be\n"
                            "It's easy when you're sad \"said 'bout me\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "Just one note\n"
                            "Could make me float\n"
                            "Could make me float away\n"
                            "One note from\n"
                            "The song she wrote\n"
                            "Could fuck me where I lay\n"
                            "Just one note\n"
                            "Could make me choke\n"
                            "One note that's\n"
                            "Not a lie\n"
                            "Just one note\n"
                            "Could cut my throat\n"
                            "One could make me die\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n";
    const char *plain = "A new day yesteday.";
    char *data;
    size_t data_size;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    char oldcwd[4096];
    FILE *fp;
    struct stat st;
    struct blackcat_keychain_handle_ctx handle;

    // INFO(Rafael): Bootstrapping the test repo.

    remove(".bcrepo/CATALOG");
    remove(".bcrepo/rescue");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->catalog_key_hash_algo = get_hash_processor("sha-384");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-384");
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha-512");
    catalog->key_hash_algo_size = get_hash_size("sha-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");
    catalog->encoder = get_encoder("uuencode");
    catalog->otp = 0;
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);
    CUTE_ASSERT(catalog->encoder != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 5);

    protkey = (kryptos_u8_t *) kryptos_newseg(9);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "aeroplane", 9);
    protkey_size = 9;

    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "sensitive.txt") == 1);
    CUTE_ASSERT(save_text(plain, strlen(plain), "plain.txt") == 1);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "plain.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next);

    CUTE_ASSERT(bcrepo_detach_metainfo("metainfo.txt", 12) == 1);

    CUTE_ASSERT(stat(".bcrepo", &st) != 0);

    CUTE_ASSERT(bcrepo_attach_metainfo("metainfo.txt", 12) == 1);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    remove("sensitive.txt");
    remove("plain.txt");
    remove("metainfo.txt");

    kryptos_freeseg(rootpath, rootpath_size);
    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_incompatibility_tests)
    bfs_catalog_ctx catalog, *cp;
    bfs_catalog_relpath_ctx files;
    kryptos_u8_t *key = "Goliath";
    kryptos_u8_t *data = NULL;
    size_t data_size;
    struct test_ctx {
        char *version;
        int stat_return;
    };
    struct test_ctx tests[] = {
        { "0.0.1", 0 },
        { "1.0.0", 1 },
        { "1.1.0", 1 },
        { "1.2.0", 1 }
    };
    size_t tests_nr = sizeof(tests) / sizeof(tests[0]), t;

    for (t = 0; t < tests_nr; t++) {
        catalog.bc_version = tests[t].version;
        catalog.otp = 0;
        catalog.catalog_key_hash_algo = get_hash_processor("whirlpool");
        catalog.catalog_key_hash_algo_size = get_hash_size("whirlpool");
        catalog.hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
        catalog.key_hash_algo = get_hash_processor("sha-224");
        catalog.key_hash_algo_size = get_hash_size("sha-224");
        catalog.protlayer_key_hash_algo = get_hash_processor("sha3-384");
        catalog.protlayer_key_hash_algo_size = get_hash_size("sha3-384");
        catalog.encoder = get_encoder("uuencode");
        catalog.encrypt_data = blackcat_encrypt_data;
        catalog.decrypt_data = blackcat_decrypt_data;
        catalog.kdf_params = NULL;
        catalog.kdf_params_size = 0;
        catalog.salt = NULL;
        catalog.salt_size = 0;

        catalog.key_hash = bcrepo_hash_key(key, strlen(key), catalog.key_hash_algo, NULL, &catalog.key_hash_size);
        CUTE_ASSERT(catalog.key_hash != NULL);

        catalog.protection_layer = get_test_protlayer(0, 2);
        catalog.files = &files;

        files.head = &files;
        files.tail = &files;
        files.path = "a/b/c.txt";
        files.path_size = strlen("a/b/c.txt");
        files.status = 'U';
        files.seed = "\x00\x11\x22\x33\x44\x55\x66\x77";
        files.seed_size = 8;
        sprintf(files.timestamp, "%s", "123456789");
        files.last = NULL;
        files.next = NULL;

        CUTE_ASSERT(bcrepo_write(BCREPO_DATA, &catalog, "parangaricutirimirruaru", strlen("parangaricutirimirruaru")) == 1);

        kryptos_freeseg(catalog.key_hash, catalog.key_hash_size);

        cp = new_bfs_catalog_ctx();

        CUTE_ASSERT(cp != NULL);

        data = bcrepo_read(BCREPO_DATA, cp, &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size > 0);

        CUTE_ASSERT(bcrepo_stat(&cp, "parangaricutirimirruaru", strlen("parangaricutirimirruaru"),
                                &data, &data_size) == tests[t].stat_return);

        CUTE_ASSERT(data == NULL);
        CUTE_ASSERT(data_size == 0);
        del_bfs_catalog_ctx(cp);
        remove(BCREPO_DATA);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_decoy_tests)
    char *data;
    size_t data_size;
    int otp;

    remove("decoy.sqn");
    remove("decoy.txt");

    for (otp = 0; otp < 2; otp++) {
        CUTE_ASSERT(bcrepo_decoy(NULL, 108, NULL, otp, 0) == 0);
        CUTE_ASSERT(bcrepo_decoy("decoy.sqn", 0, NULL, otp, 0) == 0);
        CUTE_ASSERT(bcrepo_decoy("decoy.txt", 108, NULL, otp, 0) == 1);

        if (!otp) {
            data = open_text("decoy.sqn", &data_size);
            CUTE_ASSERT(data == NULL);
            data = open_text("decoy.txt", &data_size);
            CUTE_ASSERT(data != NULL && data_size == 108);
            kryptos_freeseg(data, data_size);
        }

        CUTE_ASSERT(bcrepo_decoy("decoy.txt", 8, NULL, otp, 0) == 0);

        if (!otp) {
            data = open_text("decoy.txt", &data_size);
            CUTE_ASSERT(data != NULL && data_size == 108);
            kryptos_freeseg(data, data_size);
        } else {
            data = open_text("decoy.txt", &data_size);
            CUTE_ASSERT(data != NULL && strstr(data, BLACKCAT_OTP_D) != NULL);
            kryptos_freeseg(data, data_size);
        }

        CUTE_ASSERT(bcrepo_decoy("decoy.txt", 8, NULL, otp, 1) == 1);

        if (!otp) {
            data = open_text("decoy.txt", &data_size);
            CUTE_ASSERT(data != NULL && data_size == 8);
            kryptos_freeseg(data, data_size);
        } else {
            data = open_text("decoy.txt", &data_size);
            CUTE_ASSERT(data != NULL && strstr(data, BLACKCAT_OTP_D) != NULL);
            kryptos_freeseg(data, data_size);
        }

        CUTE_ASSERT(bcrepo_decoy("decoy.txt", 1024, get_encoder("base64"), otp, 1) == 1);
        data = open_text("decoy.txt", &data_size);
        CUTE_ASSERT(data != NULL);

        if (otp) {
            CUTE_ASSERT(strstr(data, BLACKCAT_OTP_D) == NULL);
        }

        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(bcrepo_decoy("decoy.txt", 4096, get_encoder("uuencode"), otp, 1) == 1);
        data = open_text("decoy.txt", &data_size);
        CUTE_ASSERT(data != NULL);

        if (otp) {
            CUTE_ASSERT(strstr(data, BLACKCAT_OTP_D) == NULL);
        }

        kryptos_freeseg(data, data_size);

        remove("decoy.sqn");
        remove("decoy.txt");
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_restore_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "nao, sei... so sei que foi assim";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;
    const char *sensitive = "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Looking in my own eyes \"hello\"\n"
                            "I can't find the love I want\n"
                            "Someone better slap me\n"
                            "Before I start to rust\n"
                            "Before I start to decompose\n"
                            "Looking in my rear view mirror\n"
                            "I can make it disappear\n"
                            "I can make it disappear \"have no fear\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Sitting in my kitchen hey girl\n"
                            "I'm turning into dust again\n"
                            "My melancholy baby\n"
                            "The star of mazzy must\n"
                            "Push her voice inside of me\n"
                            "I'm overcoming gravity\n"
                            "I'm overcoming gravity\n"
                            "It's easy when you're sad to be\n"
                            "It's easy when you're sad \"said 'bout me\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "Just one note\n"
                            "Could make me float\n"
                            "Could make me float away\n"
                            "One note from\n"
                            "The song she wrote\n"
                            "Could fuck me where I lay\n"
                            "Just one note\n"
                            "Could make me choke\n"
                            "One note that's\n"
                            "Not a lie\n"
                            "Just one note\n"
                            "Could cut my throat\n"
                            "One could make me die\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n";
    const char *plain = "A new day yesteday.";
    char *data;
    size_t data_size;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    char oldcwd[4096];
    FILE *fp;
    struct blackcat_keychain_handle_ctx handle;

    // INFO(Rafael): Bootstrapping the test repo.

    remove(".bcrepo/CATALOG");
    remove(".bcrepo/rescue");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->otp = 0;
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha-512");
    catalog->key_hash_algo_size = get_hash_size("sha-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");
    catalog->encoder = get_encoder("uuencode");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);
    CUTE_ASSERT(catalog->encoder != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 6);

    protkey = (kryptos_u8_t *) kryptos_newseg(9);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "aeroplane", 9);
    protkey_size = 9;

    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "sensitive.txt") == 1);
    CUTE_ASSERT(save_text(plain, strlen(plain), "plain.txt") == 1);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "plain.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next);

    fp = fopen(".bcrepo/rescue", "wb");
    CUTE_ASSERT(fp != NULL);
    fprintf(fp, "%s/malicious-alien-101.txt,3\nboo", rootpath);
    fclose(fp);

    CUTE_ASSERT(bcrepo_restore(catalog, rootpath, rootpath_size) == 0);
    fp = fopen(".bcrepo/rescue", "rb");
    CUTE_ASSERT(fp == NULL);

    fp = fopen(".bcrepo/rescue", "wb");
    CUTE_ASSERT(fp != NULL);
    fprintf(fp, "%s/sensitive.txt,3\nboo", rootpath);
    fclose(fp);

    CUTE_ASSERT(bcrepo_restore(catalog, rootpath, rootpath_size) == 1);

    data = open_text("sensitive.txt", &data_size);
    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(data_size != strlen(sensitive) && data_size == 3);
    CUTE_ASSERT(memcmp(data, sensitive, data_size) != 0 && memcmp(data, "boo", 3) == 0);
    kryptos_freeseg(data, data_size);

    fp = fopen(".bcrepo/rescue", "rb");
    CUTE_ASSERT(fp == NULL);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    remove("sensitive.txt");
    remove("plain.txt");

    kryptos_freeseg(rootpath, rootpath_size);
    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_reset_repo_settings_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "nao, sei... so sei que foi assim";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;
    const char *sensitive = "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Looking in my own eyes \"hello\"\n"
                            "I can't find the love I want\n"
                            "Someone better slap me\n"
                            "Before I start to rust\n"
                            "Before I start to decompose\n"
                            "Looking in my rear view mirror\n"
                            "I can make it disappear\n"
                            "I can make it disappear \"have no fear\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Sitting in my kitchen hey girl\n"
                            "I'm turning into dust again\n"
                            "My melancholy baby\n"
                            "The star of mazzy must\n"
                            "Push her voice inside of me\n"
                            "I'm overcoming gravity\n"
                            "I'm overcoming gravity\n"
                            "It's easy when you're sad to be\n"
                            "It's easy when you're sad \"said 'bout me\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "Just one note\n"
                            "Could make me float\n"
                            "Could make me float away\n"
                            "One note from\n"
                            "The song she wrote\n"
                            "Could fuck me where I lay\n"
                            "Just one note\n"
                            "Could make me choke\n"
                            "One note that's\n"
                            "Not a lie\n"
                            "Just one note\n"
                            "Could cut my throat\n"
                            "One could make me die\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n";
    const char *plain = "A new day yesteday.";
    char *data;
    size_t data_size;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    char oldcwd[4096];
    kryptos_u8_t *new_key;
    size_t new_key_size;
    kryptos_u8_t *new_protlayer_key;
    size_t new_protlayer_key_size;
    int otp = 0;
    struct blackcat_keychain_handle_ctx handle;

    do {
        CUTE_ASSERT(otp >= 0 && otp <= 1);

        // INFO(Rafael): Bootstrapping the test repo.

        remove(".bcrepo/CATALOG");
        rmdir(".bcrepo");

        catalog = new_bfs_catalog_ctx();

        CUTE_ASSERT(catalog != NULL);

        //catalog->bc_version = BCREPO_METADATA_VERSION;
        catalog->bc_version = (char *) kryptos_newseg(strlen("0.0.0") + 1);
        CUTE_ASSERT(catalog->bc_version != NULL);
        memset(catalog->bc_version, 0, strlen("0.0.0") + 1);
        memcpy(catalog->bc_version, "1.2.0", 5);
        catalog->otp = otp;
        catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
        catalog->key_hash_algo = get_hash_processor("sha-512");
        catalog->key_hash_algo_size = get_hash_size("sha-512");
        catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
        catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");
        catalog->encoder = get_encoder("uuencode");
        catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
        catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");

        if (catalog->otp == 0) {
            catalog->encrypt_data = blackcat_encrypt_data;
            catalog->decrypt_data = blackcat_decrypt_data;
        } else {
            catalog->encrypt_data = blackcat_otp_encrypt_data;
            catalog->decrypt_data = blackcat_otp_decrypt_data;
        }

        CUTE_ASSERT(catalog->key_hash_algo != NULL);
        CUTE_ASSERT(catalog->key_hash_algo_size != NULL);
        CUTE_ASSERT(catalog->encoder != NULL);

        CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
        CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

        catalog->key_hash = bcrepo_hash_key(key, strlen(key),
                                            catalog->key_hash_algo, NULL, &catalog->key_hash_size);

        catalog->protection_layer = get_test_protlayer(0, 6);

        protkey = (kryptos_u8_t *) kryptos_newseg(9);
        CUTE_ASSERT(protkey != NULL);
        memcpy(protkey, "aeroplane", 9);
        protkey_size = 9;


        handle.hash = catalog->protlayer_key_hash_algo;
        handle.kdf_clockwork = NULL;

        catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                              catalog->protection_layer,
                                                              &protkey, &protkey_size, &handle,
                                                              catalog->encoder);

        CUTE_ASSERT(protkey == NULL);
        CUTE_ASSERT(protkey_size == 0);

        CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

        rootpath = bcrepo_get_rootpath();

        CUTE_ASSERT(rootpath != NULL);

        rootpath_size = strlen(rootpath);

        CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "sensitive.txt") == 1);
        CUTE_ASSERT(save_text(plain, strlen(plain), "plain.txt") == 1);

        pattern = "sensitive.txt";
        CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

        CUTE_ASSERT(catalog->files != NULL);
        CUTE_ASSERT(catalog->files->head == catalog->files);
        CUTE_ASSERT(catalog->files->tail == catalog->files->head);

        pattern = "plain.txt";
        CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

        CUTE_ASSERT(catalog->files != NULL);
        CUTE_ASSERT(catalog->files->head == catalog->files);
        CUTE_ASSERT(catalog->files->tail == catalog->files->next);

        // INFO(Rafael): The files must be decrypted and re-encrypted with the new key setting.
        CUTE_ASSERT(bcrepo_lock(&catalog, rootpath, rootpath_size, "*", 1, NULL, NULL) == 1);

        new_key_size = strlen("Sham time");
        new_key = (kryptos_u8_t *)kryptos_newseg(new_key_size);
        CUTE_ASSERT(new_key != NULL);
        memcpy(new_key, "Sham time", new_key_size);

        new_protlayer_key_size = strlen("That mother fucker always spiked with pain");
        new_protlayer_key = (kryptos_u8_t *)kryptos_newseg(new_protlayer_key_size);
        CUTE_ASSERT(new_protlayer_key != NULL);
        memcpy(new_protlayer_key, "That mother fucker always spiked with pain", new_protlayer_key_size);

        catalog->otp = !catalog->otp;

        CUTE_ASSERT(bcrepo_reset_repo_settings(&catalog, rootpath, rootpath_size,
                                               new_key, new_key_size,
                                               &new_protlayer_key, &new_protlayer_key_size,
                                               get_test_protlayer(0, 6),
                                               NULL, 0,
                                               get_hash_processor("whirlpool"),
                                               get_hash_processor("sha3-512"),
                                               NULL,
                                               get_hash_processor("sha-384"),
                                               get_encoder("base64"), NULL, NULL) == 1);

        // INFO(Rafael): When a bcrepo_reset occurs it overwrites the prior bc_version to the current BCREPO_METADATA_VERSION.

        CUTE_ASSERT(catalog->bc_version != NULL);
        CUTE_ASSERT(strcmp(catalog->bc_version, bcrepo_metadata_version()) == 0);

        // INFO(Rafael): We reset the catalog's key for paranoia issues.

        CUTE_ASSERT(memcmp(new_key, "Sham time", new_key_size) != 0);

        kryptos_freeseg(new_protlayer_key, 0);

        data = open_text("sensitive.txt", &data_size);
        CUTE_ASSERT(data != NULL);

        CUTE_ASSERT(data_size != strlen(sensitive));
        CUTE_ASSERT(memcmp(data, sensitive, strlen(sensitive)) != 0);

        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(bcrepo_unlock(&catalog, rootpath, rootpath_size, "*", 1, NULL, NULL) == 1);

        data = open_text("sensitive.txt", &data_size);
        CUTE_ASSERT(data != NULL);

        CUTE_ASSERT(data_size == strlen(sensitive));
        CUTE_ASSERT(memcmp(data, sensitive, data_size) == 0);

        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) != 1);

        memcpy(new_key, "Sham time", new_key_size);
        CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, new_key, new_key_size) == 1);

        kryptos_freeseg(new_key, new_key_size);

        remove("sensitive.txt");
        remove("plain.txt");

        kryptos_freeseg(rootpath, rootpath_size);
        del_bfs_catalog_ctx(catalog);
    } while (++otp < 2);

    // INFO(Rafael): Testing all dynamics of changing and removing a (pre-)configured KDF.

    // INFO(Rafael): Bootstrapping the test repo.

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = (char *) kryptos_newseg(strlen("0.0.0") + 1);
    CUTE_ASSERT(catalog->bc_version != NULL);
    memset(catalog->bc_version, 0, strlen("0.0.0") + 1);
    memcpy(catalog->bc_version, "1.2.0", 5);
    catalog->otp = 0;
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha-512");
    catalog->key_hash_algo_size = get_hash_size("sha-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");
    catalog->encoder = get_encoder("uuencode");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");

    catalog->kdf_params = (char *) kryptos_newseg(100);
    CUTE_ASSERT(catalog->kdf_params != NULL);
    strncpy(catalog->kdf_params, "pbkdf2:blake2b-512:Zm9vYmFy:10", 99);
    catalog->kdf_params_size = strlen(catalog->kdf_params);

    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);
    CUTE_ASSERT(catalog->encoder != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key),
                                        catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 6);

    protkey = (kryptos_u8_t *) kryptos_newseg(9);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "aeroplane", 9);
    protkey_size = 9;


    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = get_kdf_clockwork(catalog->kdf_params, catalog->kdf_params_size, NULL);
    CUTE_ASSERT(handle.kdf_clockwork != NULL);

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    del_blackcat_kdf_clockwork_ctx(handle.kdf_clockwork);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "sensitive.txt") == 1);
    CUTE_ASSERT(save_text(plain, strlen(plain), "plain.txt") == 1);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "plain.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next);

    // INFO(Rafael): The files must be decrypted and re-encrypted with the new key setting.
    CUTE_ASSERT(bcrepo_lock(&catalog, rootpath, rootpath_size, "*", 1, NULL, NULL) == 1);

    new_key_size = strlen("Sham time");
    new_key = (kryptos_u8_t *)kryptos_newseg(new_key_size);
    CUTE_ASSERT(new_key != NULL);
    memcpy(new_key, "Sham time", new_key_size);

    new_protlayer_key_size = strlen("That mother fucker always spiked with pain");
    new_protlayer_key = (kryptos_u8_t *)kryptos_newseg(new_protlayer_key_size);
    CUTE_ASSERT(new_protlayer_key != NULL);
    memcpy(new_protlayer_key, "That mother fucker always spiked with pain", new_protlayer_key_size);

    catalog->otp = 1;

    CUTE_ASSERT(bcrepo_reset_repo_settings(&catalog, rootpath, rootpath_size,
                                           new_key, new_key_size,
                                           &new_protlayer_key, &new_protlayer_key_size,
                                           get_test_protlayer(0, 6),
                                           NULL, 0, // INFO(Rafael): It will remove the configured KDF.
                                           get_hash_processor("whirlpool"),
                                           get_hash_processor("sha3-512"),
                                           NULL,
                                           get_hash_processor("sha-384"),
                                           get_encoder("base64"), NULL, NULL) == 1);

    // INFO(Rafael): When a bcrepo_reset occurs it overwrites the prior bc_version to the current BCREPO_METADATA_VERSION.

    CUTE_ASSERT(catalog->bc_version != NULL);
    CUTE_ASSERT(strcmp(catalog->bc_version, bcrepo_metadata_version()) == 0);

    // INFO(Rafael): Now KDF must be NULL. The key derivation is indirectly tested by unlocking files. Notice that
    //               not only the password has changed but also the internal method of how it is derived.
    CUTE_ASSERT(catalog->kdf_params == NULL && catalog->kdf_params_size == 0);

    // INFO(Rafael): We reset the catalog's key for paranoia issues.

    CUTE_ASSERT(memcmp(new_key, "Sham time", new_key_size) != 0);

    kryptos_freeseg(new_protlayer_key, 0);

    data = open_text("sensitive.txt", &data_size);
    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(data_size != strlen(sensitive));
    CUTE_ASSERT(memcmp(data, sensitive, strlen(sensitive)) != 0);

    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(bcrepo_unlock(&catalog, rootpath, rootpath_size, "*", 1, NULL, NULL) == 1);

    data = open_text("sensitive.txt", &data_size);
    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(data_size == strlen(sensitive));
    CUTE_ASSERT(memcmp(data, sensitive, data_size) == 0);

    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) != 1);

    memcpy(new_key, "Sham time", new_key_size);
    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, new_key, new_key_size) == 1);

    kryptos_freeseg(new_key, new_key_size);

    remove("sensitive.txt");
    remove("plain.txt");

    kryptos_freeseg(rootpath, rootpath_size);
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_pack_unpack_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "nao, sei... so sei que foi assim";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;
    const char *sensitive = "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Looking in my own eyes \"hello\"\n"
                            "I can't find the love I want\n"
                            "Someone better slap me\n"
                            "Before I start to rust\n"
                            "Before I start to decompose\n"
                            "Looking in my rear view mirror\n"
                            "I can make it disappear\n"
                            "I can make it disappear \"have no fear\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "That mother fucker always spiked with pain\n"
                            "Sitting in my kitchen hey girl\n"
                            "I'm turning into dust again\n"
                            "My melancholy baby\n"
                            "The star of mazzy must\n"
                            "Push her voice inside of me\n"
                            "I'm overcoming gravity\n"
                            "I'm overcoming gravity\n"
                            "It's easy when you're sad to be\n"
                            "It's easy when you're sad \"said 'bout me\"\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n"
                            "Just one note\n"
                            "Could make me float\n"
                            "Could make me float away\n"
                            "One note from\n"
                            "The song she wrote\n"
                            "Could fuck me where I lay\n"
                            "Just one note\n"
                            "Could make me choke\n"
                            "One note that's\n"
                            "Not a lie\n"
                            "Just one note\n"
                            "Could cut my throat\n"
                            "One could make me die\n"
                            "I like pleasure spiked with pain\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Songbird sweet and sour Jane\n"
                            "And music is my aeroplane\n"
                            "It's my aeroplane\n"
                            "Pleasure spiked with pain\n";
    const char *plain = "p l a i n... duh!";
    char *data;
    size_t data_size;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    char oldcwd[4096];
    const char *config_data = ".default-options:\n--no-swap\n\n";
    struct blackcat_keychain_handle_ctx handle;

    // INFO(Rafael): Bootstrapping the test repo.

    remove(".bcrepo/CATALOG");
    remove(".bcrepo/CONFIG");
    rmdir(".bcrepo");
    remove("../bow/unroll/sensitive.txt");
    remove("../bow/unroll/plain.txt");
    remove("../bow/unrolll/.bcrepo/CATALOG");
    rmdir("../bow/unroll/.bcrepo");
    rmdir("../bow/unroll");
    rmdir("../bow/");
    remove("../repo.bow");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->otp = 0;
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha-512");
    catalog->key_hash_algo_size = get_hash_size("sha-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");
    catalog->encoder = get_encoder("uuencode");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);
    CUTE_ASSERT(catalog->encoder != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 5);

    protkey = (kryptos_u8_t *) kryptos_newseg(9);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "aeroplane", 9);
    protkey_size = 9;

    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    CUTE_ASSERT(save_text(config_data, strlen(config_data), ".bcrepo/CONFIG") == 1);
    CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "sensitive.txt") == 1);
    CUTE_ASSERT(save_text(plain, strlen(plain), "plain.txt") == 1);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "plain.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next);

    getcwd(oldcwd, sizeof(oldcwd) - 1);

    CUTE_ASSERT(bcrepo_pack(&catalog, rootpath, rootpath_size, "../repo.bow", NULL, NULL) == 1);

    CUTE_ASSERT(chdir("..") == 0);

    CUTE_ASSERT(bcrepo_unpack("repo.bow", "bow/unroll") == 1);

    data = open_text("bow/unroll/sensitive.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size > strlen(sensitive));
    CUTE_ASSERT(memcmp(data, sensitive, strlen(sensitive)) != 0);
    kryptos_freeseg(data, data_size);

    data = open_text("bow/unroll/plain.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = open_text("bow/unroll/.bcrepo/CONFIG", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(config_data));
    CUTE_ASSERT(memcmp(data, config_data, data_size) == 0);
    kryptos_freeseg(data, data_size);

    remove("bow/unroll/sensitive.txt");
    remove("bow/unroll/plain.txt");
    remove("bow/unroll/.bcrepo/CATALOG");
    remove("bow/unroll/.bcrepo/CONFIG");
    rmdir("bow/unroll/.bcrepo");
    rmdir("bow/unroll");
    rmdir("bow/");

    CUTE_ASSERT(chdir(oldcwd) == 0);

    CUTE_ASSERT(bcrepo_unpack("../repo.bow", NULL) == 0);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    remove("sensitive.txt");
    remove("plain.txt");

    CUTE_ASSERT(bcrepo_unpack("../repo.bow", NULL) == 1);

    remove("../repo.bow");

    data = open_text("sensitive.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size > strlen(sensitive));
    CUTE_ASSERT(memcmp(data, sensitive, strlen(sensitive)) != 0);
    kryptos_freeseg(data, data_size);

    data = open_text("plain.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    remove("sensitive.txt");
    remove("plain.txt");

    kryptos_freeseg(rootpath, rootpath_size);
    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(remove_go_ups_from_path_tests)
    char cwd[4096];
    char path[4096];
    char exp_path[4096];
    CUTE_ASSERT(getcwd(cwd, sizeof(cwd) - 1) != NULL);
    CUTE_ASSERT(chdir("../../") == 0);
    CUTE_ASSERT(getcwd(path, sizeof(path) - 1) != NULL);
    strncpy(exp_path, path, sizeof(exp_path) - 1);
#if defined(__unix__)
    strcat(path, "../../");
#elif defined(_WIN32)
    strcat(path, "/../../");
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(chdir(cwd) == 0);
    CUTE_ASSERT(remove_go_ups_from_path(path, sizeof(path)) == &path[0]);
    CUTE_ASSERT(strcmp(path, exp_path) == 0);
    sprintf(exp_path, "//encore break//");
    sprintf(path, "//encore break//");
    CUTE_ASSERT(remove_go_ups_from_path(path, sizeof(path)) == &path[0]);
    CUTE_ASSERT(strcmp(path, exp_path) == 0);
    sprintf(exp_path, "the-fun-machine-took-a-shit-and-died-exactly-here");
    sprintf(path, "./the-fun-machine-took-a-shit-and-died-exactly-here");
    CUTE_ASSERT(remove_go_ups_from_path(path, sizeof(path)) == &path[0]);
    CUTE_ASSERT(strcmp(path, exp_path) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_catalog_file_tests)
    char temp[4096];
    char *retval;
#if defined(__unix__)
    char *expect = "/root/alk/crosscut-saw/.bcrepo/CATALOG";
    retval = bcrepo_catalog_file(temp, sizeof(temp), "/root/alk/crosscut-saw");
#elif defined(_WIN32)
    char *expect = "\\root\\alk\\crosscut-saw\\.bcrepo\\CATALOG";
    retval = bcrepo_catalog_file(temp, sizeof(temp), "\\root\\alk\\crosscut-saw");
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(retval == &temp[0]);
    CUTE_ASSERT(memcmp(temp, expect, strlen(expect)) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_lock_unlock_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "nao, sei... so sei que foi assim";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;
    const char *sensitive = "I was paralyzed\n"
                            "As I opened up my bloodshot eyes\n"
                            "Do I really want to know\n"
                            "Where I've been\n"
                            "Or where I've put my nose\n"
                            "I'm in a rut\n"
                            "Keep kicking myself in the nuts\n"
                            "In a stairwell I seek\n"
                            "The lair where I stuck my dirty beak\n"
                            "So I'm back again it's OK\n"
                            "Well be that as it may\n"
                            "Over and over away\n"
                            "Into the fires unknown\n"
                            "Into oblivion\n"
                            "Through sticks and stones\n"
                            "Pick up the phone\n"
                            "My jacks are all blown\n"
                            "Oh these nights out alone\n"
                            "Come carry me home\n"
                            "A habit hard to break\n"
                            "Take me home, good lord\n"
                            "For heaven's sake\n"
                            "The doctor's not in\n"
                            "Got no cure for the medicine\n"
                            "So I'm back again it's OK\n"
                            "Well be that as it may\n"
                            "Over and over away\n"
                            "Into the fires unknown\n"
                            "Into oblivion\n"
                            "Through sticks and stones\n"
                            "Pick up the phone\n"
                            "Listen to me moan\n"
                            "Oh these nights out alone\n"
                            "Come carry me home\n"
                            "Every time I make the round\n"
                            "I turn around\n"
                            "I'm put upon the rack\n"
                            "Every time I stand up\n"
                            "I fall flat on my face\n"
                            "And break my back\n"
                            "Tombstoned and chicken shacked\n";
    const char *plain = "If you like to gamble, I tell you I'm your man\n"
                        "You win some, lose some, all the same to me\n"
                        "The pleasure is to play, makes no difference what you say\n"
                        "I don't share your greed, the only card I need is the Ace of Spades\n"
                        "The Ace of Spades\n"
                        "Playing for the high one, dancing with the devil\n"
                        "Going with the flow, it's all a game to me\n"
                        "Seven or eleven, snake eyes watching you\n"
                        "Double up or quit, double stake or split, the Ace of Spades\n"
                        "The Ace of Spades\n"
                        "You know I'm born to lose, and gambling's for fools\n"
                        "But that's the way I like it baby\n"
                        "I don't wanna live for ever\n"
                        "And don't forget the joker!\n"
                        "Pushing up the ante, I know you gotta see me\n"
                        "Read 'em and weep, the dead man's hand again\n"
                        "I see it in your eyes, take one look and die\n"
                        "The only thing you see, you know it's gonna be the Ace of Spades\n"
                        "The Ace of Spades\n";
    char *data;
    size_t data_size;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    struct blackcat_keychain_handle_ctx handle;

    // INFO(Rafael): Bootstrapping the test repo.

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->otp = 0;
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha-512");
    catalog->key_hash_algo_size = get_hash_size("sha-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");
    catalog->encoder = get_encoder("uuencode");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);
    CUTE_ASSERT(catalog->encoder != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 5);

    protkey = (kryptos_u8_t *) kryptos_newseg(11);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "mumbo gumbo", 11);
    protkey_size = 11;

    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "sensitive.txt") == 1);
    CUTE_ASSERT(save_text(plain, strlen(plain), "plain.txt") == 1);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "plain.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next);

    pattern = "*";
    CUTE_ASSERT(bcrepo_lock(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), NULL, NULL) == 1);

    CUTE_ASSERT(catalog->files->status == kBfsFileStatusLocked);
    CUTE_ASSERT(catalog->files->next->status == kBfsFileStatusPlain);

    data = open_text("sensitive.txt", &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    CUTE_ASSERT(data_size > strlen(sensitive));
    CUTE_ASSERT(memcmp(data, sensitive, strlen(sensitive)) != 0);
    free(data);

    data = open_text("plain.txt", &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    free(data);

    pattern = "*";
    CUTE_ASSERT(bcrepo_unlock(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), NULL, NULL) == 1);

    data = open_text("sensitive.txt", &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    CUTE_ASSERT(data_size == strlen(sensitive));
    CUTE_ASSERT(memcmp(data, sensitive, data_size) == 0);
    free(data);

    data = open_text("plain.txt", &data_size);
    CUTE_ASSERT(data != NULL && data_size > 0);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    free(data);

    remove("sensitive.txt");
    remove("plain.txt");
    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);
    kryptos_freeseg(rootpath, rootpath_size);
    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_rm_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "you're not the only one with mixed emotions,"
                        "you're not the only ship adrift on this ocean.";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;
    char *sensitive = "You know you can't be hurt\n"
                      "You gotta believe in your star\n"
                      "They'll always treat you like dirt\n"
                      "They can only push you so far\n"
                      "They can't take it away\n"
                      "If they've got something to say\n"
                      "They might try and fence you in\n"
                      "But you've only gotta live to win\n"
                      "Know it's hard, a natural drag\n"
                      "It's a hassle to fight\n"
                      "If you don't want to be a slag\n"
                      "If you believe you're right\n"
                      "They've got the power, now\n"
                      "But soon it's our hour, now\n"
                      "We all know where we been\n"
                      "We only live to win\n"
                      "You mustn't shout it out loud\n"
                      "Don't create a scene\n"
                      "Nobody told you being proud\n"
                      "It only feeds the scheme\n"
                      "And break down the wall\n"
                      "Live it up, it's their time to fall\n"
                      "Anarchy is coming in\n"
                      "If you know we live to win\n";
    char *data = NULL;
    size_t data_size;
    kryptos_u8_t *protkey;
    size_t protkey_size;
    struct blackcat_keychain_handle_ctx handle;

    // INFO(Rafael): The painful handmade bootstrapping arrrgh!

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->otp = 0;
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("tiger");
    catalog->key_hash_algo_size = get_hash_size("tiger");
    catalog->protlayer_key_hash_algo = get_hash_processor("whirlpool");
    catalog->protlayer_key_hash_algo_size = get_hash_size("whirlpool");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 1);

    protkey = (kryptos_u8_t *) kryptos_newseg(15);
    CUTE_ASSERT(protkey != NULL);
    memcpy(protkey, "ready to forget", 15);
    protkey_size = 15;

    handle.hash = catalog->protlayer_key_hash_algo;
    handle.kdf_clockwork = NULL;

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          &protkey, &protkey_size, &handle,
                                                          catalog->encoder);

    CUTE_ASSERT(protkey == NULL);
    CUTE_ASSERT(protkey_size == 0);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    CUTE_ASSERT(save_text(sensitive, strlen(sensitive), "sensitive.txt") == 1);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_lock(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), NULL, NULL) == 1);

    pattern = "main.c";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail != catalog->files->head);

    pattern = "o/*.o";
    o_files_nr = bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0);
    CUTE_ASSERT(o_files_nr > 1);

    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail != catalog->files->head);

    pattern = "main.c";
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    pattern = "i_sat_by_the_ocean.txt";
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 0);

    pattern = "o/*.o";
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == o_files_nr);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    data = open_text("sensitive.txt", &data_size);

    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive));
    CUTE_ASSERT(memcmp(data, sensitive, data_size) == 0);

    pattern = "sensitive.txt";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);
    remove("sensitive.txt");

    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 0);
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    kryptos_freeseg(rootpath, rootpath_size);

    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
    kryptos_freeseg(data, data_size);
    remove("sensitive.txt");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_add_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "better living through chemistry";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_u8_t *pattern = NULL;

    // INFO(Rafael): Repo bootstrapping.

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->otp = 0;
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha3-512");
    catalog->key_hash_algo_size = get_hash_size("sha3-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha-256");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha-256");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 1);

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    // INFO(Rafael): Bootstrapping done.

    pattern = "main.c";

    CUTE_ASSERT(bcrepo_add(NULL, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 0);

    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->tail == catalog->files);
    CUTE_ASSERT(strcmp(catalog->files->path, "main.c") == 0);
    CUTE_ASSERT(catalog->files->status == kBfsFileStatusUnlocked);
    CUTE_ASSERT(catalog->files->timestamp[0] != 0);

    pattern = "Forgefile.*";

    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next);
    CUTE_ASSERT(strcmp(catalog->files->next->path, "Forgefile.hsl") == 0);
    CUTE_ASSERT(catalog->files->next->status == kBfsFileStatusUnlocked);
    CUTE_ASSERT(catalog->files->next->timestamp[0] != 0);

    pattern = "o/main.o";

    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next->next);
    CUTE_ASSERT(strcmp(catalog->files->next->next->path, "o/main.o") == 0);
    CUTE_ASSERT(catalog->files->next->next->status == kBfsFileStatusUnlocked);
    CUTE_ASSERT(catalog->files->next->next->timestamp[0] != 0);

    pattern = "o/aes.*";

    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next->next->next);
    CUTE_ASSERT(strcmp(catalog->files->next->next->next->path, "o/aes.o") == 0);
    CUTE_ASSERT(catalog->files->next->next->next->status == kBfsFileStatusUnlocked);
    CUTE_ASSERT(catalog->files->next->next->next->timestamp[0] != 0);

    CUTE_ASSERT(chdir("o") == 0);

    pattern = "des.o";

    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next->next->next->next);
    CUTE_ASSERT(strcmp(catalog->files->next->next->next->next->path, "o/des.o") == 0);
    CUTE_ASSERT(catalog->files->next->next->next->next->status == kBfsFileStatusUnlocked);
    CUTE_ASSERT(catalog->files->next->next->next->next->timestamp[0] != 0);

    pattern = "mars.*";

    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next->next->next->next->next);
    CUTE_ASSERT(strcmp(catalog->files->next->next->next->next->next->path, "o/mars.o") == 0);
    CUTE_ASSERT(catalog->files->next->next->next->next->next->status == kBfsFileStatusUnlocked);
    CUTE_ASSERT(catalog->files->next->next->next->next->next->timestamp[0] != 0);

    CUTE_ASSERT(chdir("..") == 0);

    pattern = "o/ciphering_schemes.o";

    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 1) == 1);

    CUTE_ASSERT(catalog->files != NULL);
    CUTE_ASSERT(catalog->files->tail == catalog->files->next->next->next->next->next->next);
    CUTE_ASSERT(strcmp(catalog->files->next->next->next->next->next->next->path, "o/ciphering_schemes.o") == 0);
    CUTE_ASSERT(catalog->files->next->next->next->next->next->next->status == kBfsFileStatusPlain);
    CUTE_ASSERT(catalog->files->next->next->next->next->next->next->timestamp[0] != 0);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    kryptos_freeseg(rootpath, rootpath_size);

    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_init_deinit_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "d34d m4n t311 n0 t4135";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    int otp = 0;

    do {
        CUTE_ASSERT(otp >= 0 && otp <= 1);
        remove(".bcrepo/CATALOG");
        rmdir(".bcrepo");
        rmdir("../.bcrepo");

        catalog = new_bfs_catalog_ctx();

        CUTE_ASSERT(catalog != NULL);

        catalog->bc_version = BCREPO_METADATA_VERSION;
        catalog->otp = otp;
        catalog->catalog_key_hash_algo = get_hash_processor("sha-384");
        catalog->catalog_key_hash_algo_size = get_hash_size("sha-384");
        catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
        catalog->key_hash_algo = get_hash_processor("sha3-512");
        catalog->key_hash_algo_size = get_hash_size("sha3-512");
        catalog->protlayer_key_hash_algo = get_hash_processor("sha-256");
        catalog->protlayer_key_hash_algo_size = get_hash_size("sha-256");
        catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
        catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
        if (catalog->otp == 0) {
            catalog->encrypt_data = blackcat_encrypt_data;
            catalog->decrypt_data = blackcat_decrypt_data;
        } else {
            catalog->encrypt_data = blackcat_otp_encrypt_data;
            catalog->decrypt_data = blackcat_otp_decrypt_data;
        }

        CUTE_ASSERT(catalog->key_hash_algo != NULL);
        CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

        CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
        CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

        catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

        catalog->protection_layer = get_test_protlayer(0, 4);

        // INFO(Rafael): An init attempt inside previously initialized repos must fail.

#if defined(__unix__)
        CUTE_ASSERT(mkdir(".bcrepo", 0666) == 0);
#elif defined(_WIN32)
        CUTE_ASSERT(mkdir(".bcrepo") == 0);
#else
# error Some code wanted.
#endif
        CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 0);
        CUTE_ASSERT(rmdir(".bcrepo") == 0);

        // INFO(Rafael): It does not matter if you are at the toplevel or anywhere else. Inside a previously initialized repo
        //                a bcrepo_init() call will fail.

#if defined(__unix__)
        CUTE_ASSERT(mkdir("../.bcrepo", 0666) == 0);
#elif defined(_WIN32)
        CUTE_ASSERT(mkdir("../.bcrepo") == 0);
#else
# error Some code wanted.
#endif
        CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 0);
        CUTE_ASSERT(rmdir("../.bcrepo") == 0);

        // INFO(Rafael): Cute cases where everything is marvelously perfect. Wow!

        CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

        rootpath = bcrepo_get_rootpath();

        CUTE_ASSERT(rootpath != NULL);

        rootpath_size = strlen(rootpath);

        // INFO(Rafael): The correct master key must match, otherwise it will fail.

        CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, "sp4c3 c4d3t", strlen("sp4c3 c4d3t")) == 0);

        CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

        kryptos_freeseg(rootpath, rootpath_size);

        rootpath = bcrepo_get_rootpath();

        CUTE_ASSERT(rootpath == NULL); // INFO(Rafael): This is not a repo anymore.

        catalog->bc_version = catalog->protection_layer = NULL;
        del_bfs_catalog_ctx(catalog);
    } while (++otp < 2);

    // INFO(Rafael): Initializing/Deinitializing a repo which uses a KDF

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");
    rmdir("../.bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = BCREPO_METADATA_VERSION;
    catalog->otp = 0;
    catalog->catalog_key_hash_algo = get_hash_processor("sha-384");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-384");
    catalog->hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog->key_hash_algo = get_hash_processor("sha3-512");
    catalog->key_hash_algo_size = get_hash_size("sha3-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha-256");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha-256");
    catalog->catalog_key_hash_algo = get_hash_processor("sha-256");
    catalog->catalog_key_hash_algo_size = get_hash_size("sha-256");
    catalog->encrypt_data = blackcat_encrypt_data;
    catalog->decrypt_data = blackcat_decrypt_data;
    catalog->kdf_params = "argon2i:Zm9vYmFy:32:38:Zm9v:YmFy";
    catalog->kdf_params_size = strlen(catalog->kdf_params);

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    catalog->key_hash = bcrepo_hash_key(key, strlen(key), catalog->key_hash_algo, NULL, &catalog->key_hash_size);

    catalog->protection_layer = get_test_protlayer(0, 4);

    // INFO(Rafael): An init attempt inside previously initialized repos must fail.

#if defined(__unix__)
    CUTE_ASSERT(mkdir(".bcrepo", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir(".bcrepo") == 0);
#else
# error Some error wanted.
#endif
    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 0);
    CUTE_ASSERT(rmdir(".bcrepo") == 0);

    // INFO(Rafael): It does not matter if you are at the toplevel or anywhere else. Inside a previously initialized repo
    //                a bcrepo_init() call will fail.

#if defined(__unix__)
    CUTE_ASSERT(mkdir("../.bcrepo", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("../.bcrepo") == 0);
#else
# error Some error wanted.
#endif
    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 0);
    CUTE_ASSERT(rmdir("../.bcrepo") == 0);

    // INFO(Rafael): Cute cases where everything is marvelously perfect. Wow!

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    // INFO(Rafael): The correct master key must match, otherwise it will fail.

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, "sp4c3 c4d3t", strlen("sp4c3 c4d3t")) == 0);

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    kryptos_freeseg(rootpath, rootpath_size);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath == NULL); // INFO(Rafael): This is not a repo anymore.

    catalog->kdf_params_size = 0;
    catalog->bc_version = catalog->protection_layer = catalog->kdf_params = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(strglob_tests)
    struct strglob_tests_ctx {
        const char *str;
        const char *pattern;
        int result;
    };
    struct strglob_tests_ctx tests[] = {
        { NULL,                         NULL                                                       , 0 },
        { "abc",                        "abc"                                                      , 1 },
        { "abc",                        "ab"                                                       , 0 },
        { "abc",                        "a?c"                                                      , 1 },
        { "abc",                        "ab[abdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.c]", 1 },
        { "abc",                        "ab[abdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.?]", 0 },
        { "ab*",                        "ab[c*]"                                                   , 1 },
        { "ab*",                        "ab[*c]"                                                   , 1 },
        { "abc",                        "ab*"                                                      , 1 },
        { "abc",                        "abc*"                                                     , 1 },
        { "strglob.c",                  "strglo*.c"                                                , 1 },
        { "parangaricutirimirruaru!!!", "*"                                                        , 1 },
        { "parangaritititero",          "?"                                                        , 0 },
        { "parangaritititero",          "?*"                                                       , 1 },
        { "parangaricutirimirruaru",    "paran*"                                                   , 1 },
        { "parangaricutirimirruaru",    "parruari"                                                 , 0 },
        { "parangaricutirimirruaru",    "paran*garicuti"                                           , 0 },
        { "parangaricutirimirruaru",    "paran*garicutirimirruaru"                                 , 1 },
        { "parangaricutirimirruaru",    "paran*ru"                                                 , 1 },
        { "hell yeah!",                 "*yeah!"                                                   , 1 }
    };
    size_t tests_nr = sizeof(tests) / sizeof(tests[0]), t;

    for (t = 0; t < tests_nr; t++) {
        CUTE_ASSERT(strglob(tests[t].str, tests[t].pattern) == tests[t].result);
    }
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

#if defined(__unix__)
    mkdir(".bcrepo", 0666);
#elif defined(_WIN32)
    mkdir(".bcrepo");
#else
# error Some error wanted.
#endif

    rootpath = bcrepo_get_rootpath();
    CUTE_ASSERT(rootpath != NULL);
    CUTE_ASSERT(strcmp(rootpath, cwd) == 0);

    kryptos_freeseg(rootpath, strlen(rootpath));
    rmdir(".bcrepo");

    chdir("..");

    getcwd(cwd, sizeof(cwd));

    rmdir(".bcrepo");
#if defined(__unix__)
    mkdir(".bcrepo", 0666);
#elif defined(_WIN32)
    mkdir(".bcrepo");
#else
# error Some error wanted.
#endif
    chdir("test");

    rootpath = bcrepo_get_rootpath();
    CUTE_ASSERT(rootpath != NULL);
    CUTE_ASSERT(strcmp(rootpath, cwd) == 0);

    kryptos_freeseg(rootpath, strlen(rootpath));
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

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    data = bcrepo_read(BCREPO_DATA, catalog, &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size > 0);

    CUTE_ASSERT(bcrepo_stat(&catalog, "parangaricutirimirruaru", strlen("parangaricutirimirruaru"), &data, &data_size) == 1);

    CUTE_ASSERT(data == NULL);
    CUTE_ASSERT(data_size == 0);

    CUTE_ASSERT(catalog->bc_version != NULL);
    CUTE_ASSERT(strcmp(catalog->bc_version, BCREPO_METADATA_VERSION) == 0);

    CUTE_ASSERT(catalog->otp == 0);

    // INFO(Rafael): If it was correctly read for sure that the hmac_scheme must match.
    //               Test it would be a little bit stupid.

    CUTE_ASSERT(catalog->key_hash_algo == get_hash_processor("sha-224"));
    CUTE_ASSERT(catalog->key_hash_algo_size == get_hash_size("sha-224"));
    CUTE_ASSERT(catalog->protlayer_key_hash_algo == get_hash_processor("sha3-384"));
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size == get_hash_size("sha3-384"));

    CUTE_ASSERT(catalog->key_hash != NULL);
    // TIP(Rafael): This hash is stored in hexadecimal format with a salt having the same size of the hash.
    CUTE_ASSERT(catalog->key_hash_size == (catalog->key_hash_algo_size() << 2));

    CUTE_ASSERT(catalog->protection_layer != NULL);
    CUTE_ASSERT(strcmp(catalog->protection_layer, g_fs_test_protlayer) == 0);

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

    kryptos_freeseg(data, data_size);

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

    CUTE_ASSERT(catalog.encoder == get_encoder("uuencode"));

    kryptos_freeseg(data, data_size);
    kryptos_freeseg(hmac_algo, strlen(hmac_algo));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_write_tests)
    bfs_catalog_ctx catalog;
    bfs_catalog_relpath_ctx files;
    kryptos_u8_t *key = "Goliath";

    memset(&catalog, 0, sizeof(catalog));

    catalog.bc_version = BCREPO_METADATA_VERSION;
    catalog.otp = 0;
    catalog.catalog_key_hash_algo = get_hash_processor("whirlpool");
    catalog.catalog_key_hash_algo_size = get_hash_size("whirlpool");
    catalog.hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog.key_hash_algo = get_hash_processor("sha-224");
    catalog.key_hash_algo_size = get_hash_size("sha-224");
    catalog.protlayer_key_hash_algo = get_hash_processor("sha3-384");
    catalog.protlayer_key_hash_algo_size = get_hash_size("sha3-384");
    catalog.encoder = get_encoder("uuencode");
    catalog.kdf_params = NULL;
    catalog.kdf_params_size = 0;
    catalog.salt = NULL;
    catalog.salt_size = 0;

    catalog.key_hash = bcrepo_hash_key(key, strlen(key), catalog.key_hash_algo, NULL, &catalog.key_hash_size);
    CUTE_ASSERT(catalog.key_hash != NULL);

    catalog.protection_layer = g_fs_test_protlayer;
    catalog.files = &files;

    files.head = &files;
    files.tail = &files;
    files.path = "a/b/c.txt";
    files.path_size = strlen("a/b/c.txt");
    files.status = 'U';
    files.seed = "\x00\x11\x22\x33\x44\x55\x66\x77";
    files.seed_size = 8;
    sprintf(files.timestamp, "%s", "123456789");
    files.last = NULL;
    files.next = NULL;

    CUTE_ASSERT(bcrepo_write(BCREPO_DATA, &catalog, "parangaricutirimirruaru", strlen("parangaricutirimirruaru")) == 1);

    kryptos_freeseg(catalog.key_hash, catalog.key_hash_size);

    // INFO(Rafael): Let's test a repo which uses a KDF (HKDF).

    catalog.bc_version = BCREPO_METADATA_VERSION;
    catalog.otp = 0;
    catalog.catalog_key_hash_algo = get_hash_processor("whirlpool");
    catalog.catalog_key_hash_algo_size = get_hash_size("whirlpool");
    catalog.hmac_scheme = get_hmac_catalog_scheme(get_test_hmac(0));
    catalog.key_hash_algo = get_hash_processor("sha-224");
    catalog.key_hash_algo_size = get_hash_size("sha-224");
    catalog.protlayer_key_hash_algo = get_hash_processor("sha3-384");
    catalog.protlayer_key_hash_algo_size = get_hash_size("sha3-384");
    catalog.encoder = get_encoder("uuencode");
    catalog.kdf_params = "hkdf:sha-384:Zm9vYmFy:Zm9v";
    catalog.kdf_params_size = 26;

    catalog.key_hash = bcrepo_hash_key(key, strlen(key), catalog.key_hash_algo, NULL, &catalog.key_hash_size);
    CUTE_ASSERT(catalog.key_hash != NULL);

    catalog.protection_layer = g_fs_test_protlayer;
    catalog.files = &files;

    files.head = &files;
    files.tail = &files;
    files.path = "a/b/c.txt";
    files.path_size = strlen("a/b/c.txt");
    files.status = 'U';
    files.seed = "\x00\x11\x22\x33\x44\x55\x66\x77";
    files.seed_size = 8;
    sprintf(files.timestamp, "%s", "123456789");
    files.last = NULL;
    files.next = NULL;

    CUTE_ASSERT(bcrepo_write(BCREPO_DATA, &catalog, "parangaricutirimirruaru", strlen("parangaricutirimirruaru")) == 1);

    kryptos_freeseg(catalog.key_hash, catalog.key_hash_size);
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

int save_text(const char *data, const size_t data_size, const char *filepath) {
    FILE *fp;

    if ((fp = fopen(filepath, "wb")) == NULL) {
        return 0;
    }

    fwrite(data, 1, data_size, fp);
    fclose(fp);

    return 1;
}

char *open_text(const char *filepath, size_t *data_size) {
    FILE *fp;
    size_t dsize;
    char *data = NULL;

    if ((fp = fopen(filepath, "rb")) == NULL) {
        return NULL;
    }

    fseek(fp, 0L, SEEK_END);
    dsize = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    data = (char *) malloc(dsize + 1);

    if (data == NULL) {
        return NULL;
    }

    memset(data, 0, dsize + 1);
    fread(data, 1, dsize, fp);

    fclose(fp);

    if (data_size != NULL) {
        *data_size = dsize;
    }

    return data;
}

int checkpoint(void *args) {
    struct checkpoint_ctx *ckpt = (struct checkpoint_ctx *) args;
    char temp[4096];
    int no_error = bcrepo_write(bcrepo_catalog_file(temp, sizeof(temp),
                                ckpt->rootpath), ckpt->catalog, ckpt->key, ckpt->key_size);
    if (no_error != 1) {
        fprintf(stderr, "ERROR: Unable to update the catalog file.\n");
    }

    return no_error;
}
