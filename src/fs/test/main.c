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
#include <ctx/ctx.h>
#include <bcrepo/bcrepo.h>
#include <keychain/ciphering_schemes.h>
#include <fs/strglob.h>
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
CUTE_DECLARE_TEST_CASE(strglob_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_init_deinit_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_add_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_rm_tests);
CUTE_DECLARE_TEST_CASE(bcrepo_lock_unlock_tests);

int save_text(const char *data, const size_t data_size, const char *filepath);
char *open_text(const char *filepath, size_t *data_size);

CUTE_MAIN(fs_tests);

CUTE_TEST_CASE(fs_tests)
    remove(".bcrepo/CATALOG");
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
    CUTE_RUN_TEST(strglob_tests);
    CUTE_RUN_TEST(bcrepo_init_deinit_tests);
    CUTE_RUN_TEST(bcrepo_add_tests);
    CUTE_RUN_TEST(bcrepo_lock_unlock_tests);
    CUTE_RUN_TEST(bcrepo_rm_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_lock_unlock_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "nao, sei... so sei que foi assim";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_task_ctx t, *ktask = &t;
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

    // INFO(Rafael): Bootstrapping the test repo.

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = "0.0.1";
    catalog->hmac_scheme = get_hmac_catalog_scheme("hmac-sha384-mars-256-cbc");
    catalog->key_hash_algo = get_hash_processor("sha512");
    catalog->key_hash_algo_size = get_hash_size("sha512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha3-512");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha3-512");

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    ktask->in = key;
    ktask->in_size = strlen(key);
    catalog->key_hash_algo(&ktask, 1);

    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    catalog->key_hash = ktask->out;
    catalog->key_hash_size = ktask->out_size;
    catalog->protection_layer = "hmac-sha224-blowfish-ctr|mars-192-ctr|xtea-ofb|hmac-sha3-512-shacal2-cbc";

    catalog->protlayer = add_composite_protlayer_to_chain(catalog->protlayer,
                                                          catalog->protection_layer,
                                                          "mumbo gumbo", 11, catalog->protlayer_key_hash_algo);

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
    CUTE_ASSERT(bcrepo_lock(&catalog, rootpath, rootpath_size, pattern, strlen(pattern)) == 1);

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
    CUTE_ASSERT(bcrepo_unlock(&catalog, rootpath, rootpath_size, pattern, strlen(pattern)) == 1);

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
    kryptos_freeseg(rootpath);
    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_rm_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "you're not the only one with mixed emotions,"
                        "you're not the only one ship adrift on this ocean.";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *pattern = NULL;
    int o_files_nr = 0;

    // INFO(Rafael): The painful handmade bootstrapping arrrgh!

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = "0.0.1";
    catalog->hmac_scheme = get_hmac_catalog_scheme("hmac-whirlpool-camellia-192-ctr");
    catalog->key_hash_algo = get_hash_processor("tiger");
    catalog->key_hash_algo_size = get_hash_size("tiger");
    catalog->protlayer_key_hash_algo = get_hash_processor("whirlpool");
    catalog->protlayer_key_hash_algo_size = get_hash_size("whirlpool");

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    ktask->in = key;
    ktask->in_size = strlen(key);
    catalog->key_hash_algo(&ktask, 1);

    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    catalog->key_hash = ktask->out;
    catalog->key_hash_size = ktask->out_size;
    catalog->protection_layer = "aes-128";

    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 1);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath != NULL);

    rootpath_size = strlen(rootpath);

    pattern = "main.c";
    CUTE_ASSERT(bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0) == 1);

    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail == catalog->files->head);

    pattern = "o/*.o";
    o_files_nr = bcrepo_add(&catalog, rootpath, rootpath_size, pattern, strlen(pattern), 0);
    CUTE_ASSERT(o_files_nr > 1);

    CUTE_ASSERT(catalog->files->head == catalog->files);
    CUTE_ASSERT(catalog->files->tail != catalog->files->head);

    pattern = "main.c";
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern)) == 1);

    pattern = "i_sat_by_the_ocean.txt";
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern)) == 0);

    pattern = "o/*.o";
    CUTE_ASSERT(bcrepo_rm(&catalog, rootpath, rootpath_size, pattern, strlen(pattern)) == o_files_nr);

    // TODO(Rafael): Test the locked file removing case.

    CUTE_ASSERT(bcrepo_deinit(rootpath, rootpath_size, key, strlen(key)) == 1);

    kryptos_freeseg(rootpath);

    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_add_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "better living through chemistry";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *pattern = NULL;

    // INFO(Rafael): Repo bootstrapping.

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = "0.0.1";
    catalog->hmac_scheme = get_hmac_catalog_scheme("hmac-tiger-aes-256-cbc");
    catalog->key_hash_algo = get_hash_processor("sha3-512");
    catalog->key_hash_algo_size = get_hash_size("sha3-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha256");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha256");

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    ktask->in = key;
    ktask->in_size = strlen(key);
    catalog->key_hash_algo(&ktask, 1);

    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    catalog->key_hash = ktask->out;
    catalog->key_hash_size = ktask->out_size;
    catalog->protection_layer = "hmac-sha3-512-rc6-192-cbc/48";

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

    kryptos_freeseg(rootpath);

    catalog->protection_layer = catalog->bc_version = NULL;
    del_bfs_catalog_ctx(catalog);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(bcrepo_init_deinit_tests)
    bfs_catalog_ctx *catalog = NULL;
    kryptos_u8_t *key = "d34d m4n t311 n0 t4135";
    kryptos_u8_t *rootpath = NULL;
    size_t rootpath_size;
    kryptos_task_ctx t, *ktask = &t;

    remove(".bcrepo/CATALOG");
    rmdir(".bcrepo");
    rmdir("../.bcrepo");

    catalog = new_bfs_catalog_ctx();

    CUTE_ASSERT(catalog != NULL);

    catalog->bc_version = "0.0.1";
    catalog->hmac_scheme = get_hmac_catalog_scheme("hmac-tiger-aes-256-cbc");
    catalog->key_hash_algo = get_hash_processor("sha3-512");
    catalog->key_hash_algo_size = get_hash_size("sha3-512");
    catalog->protlayer_key_hash_algo = get_hash_processor("sha256");
    catalog->protlayer_key_hash_algo_size = get_hash_size("sha256");

    CUTE_ASSERT(catalog->key_hash_algo != NULL);
    CUTE_ASSERT(catalog->key_hash_algo_size != NULL);

    CUTE_ASSERT(catalog->protlayer_key_hash_algo != NULL);
    CUTE_ASSERT(catalog->protlayer_key_hash_algo_size != NULL);

    ktask->in = key;
    ktask->in_size = strlen(key);
    catalog->key_hash_algo(&ktask, 1);

    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    catalog->key_hash = ktask->out;
    catalog->key_hash_size = ktask->out_size;
    catalog->protection_layer = "hmac-sha3-512-camellia-192-cbc|des-cbc|mars-128-ctr|shacal1-cbc|hmac-tiger-aes-128-cbc";

    // INFO(Rafael): An init attempt inside previously initialized repos must fail.

    CUTE_ASSERT(mkdir(".bcrepo", 0666) == 0);
    CUTE_ASSERT(bcrepo_init(catalog, key, strlen(key)) == 0);
    CUTE_ASSERT(rmdir(".bcrepo") == 0);

    // INFO(Rafael): It does not matter if you are at the toplevel or anywhere else. Inside a previously initialized repo
    //                a bcrepo_init() call will fail.

    CUTE_ASSERT(mkdir("../.bcrepo", 0666) == 0);
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

    kryptos_freeseg(rootpath);

    rootpath = bcrepo_get_rootpath();

    CUTE_ASSERT(rootpath == NULL); // INFO(Rafael): This is not a repo anymore.

    catalog->bc_version = catalog->protection_layer = NULL;
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
