/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <base/test/huge_protchain.h>
#include <cmd/options.h>
#include <cmd/version.h>
#include <cmd/levenshtein_distance.h>
#include <fs/bcrepo/config.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#if !defined(_WIN32)
# include <unistd.h>
# include <fcntl.h>
#endif

static int create_file(const char *filepath, const unsigned char *data, const size_t data_size);

unsigned char *get_file_data(const char *filepath, size_t *data_size);

static int blackcat(const char *command, const unsigned char *p1, const unsigned char *p2);

static int blackcat_nowait(const char *command, const unsigned char *p1, const unsigned char *p2);

static int check_blackcat_lkm_hiding(void);

static int try_unload_blackcat_lkm(void);

static int file_is_hidden(const char *filepath);

static int test_env_housekeeping(void);

static int syshook(void);

static int clear_syshook(void);

static int has_tcpdump(void);

static char hkdf_path[] = "";
static char hkdf_cmd[] = "meow";
static char hkdf_arg2[] = "--kdf=hkdf";
static char hkdf_arg3[] = "--hkdf-salt=foobar";
static char hkdf_arg4[] = "--hkdf-info=foo";
static char hkdf_arg5[] = "--protection-layer-hash=sha-384";

static char *hkdf_argv[] = {
    hkdf_path,
    hkdf_cmd,
    hkdf_arg2,
    hkdf_arg3,
    hkdf_arg4,
    hkdf_arg5
};

static int hkdf_argc = sizeof(hkdf_argv) / sizeof(hkdf_argv[0]);

static char pbkdf2_path[] = "";
static char pbkdf2_cmd[] = "meow";
static char pbkdf2_arg2[] = "--kdf=pbkdf2";
static char pbkdf2_arg3[] = "--pbkdf2-salt=foobar";
static char pbkdf2_arg4[] = "--pbkdf2-count=10";
static char pbkdf2_arg5[] = "--protection-layer-hash=blake2b-512";

static char *pbkdf2_argv[] = {
    pbkdf2_path,
    pbkdf2_cmd,
    pbkdf2_arg2,
    pbkdf2_arg3,
    pbkdf2_arg4,
    pbkdf2_arg5
};

static int pbkdf2_argc = sizeof(pbkdf2_argv) / sizeof(pbkdf2_argv[0]);

static char argon2i_path[] = "";
static char argon2i_cmd[] = "meow";
static char argon2i_arg2[] = "--kdf=argon2i";
static char argon2i_arg3[] = "--argon2i-salt=foobar";
static char argon2i_arg4[] = "--argon2i-memory=32";
static char argon2i_arg5[] = "--argon2i-iterations=38";
static char argon2i_arg6[] = "--argon2i-key=foo";
static char argon2i_arg7[] = "--argon2i-aad=bar";

static char *argon2i_argv[] = {
    argon2i_path,
    argon2i_cmd,
    argon2i_arg2,
    argon2i_arg3,
    argon2i_arg4,
    argon2i_arg5,
    argon2i_arg6,
    argon2i_arg7
};

static int argon2i_argc = sizeof(argon2i_argv) / sizeof(argon2i_argv[0]);

static char token_path[] = "";
static char token_cmd[] = "meow";
static char token_arg2[] = "--soft-token=tk.1,tk.2,etc/token.iii";
static char token_arg3[] = "--new-soft-token=ntk.1,ntk.2,etc/ntoken.iii";

static char *token_argv[] = {
    token_path,
    token_cmd,
    token_arg2,
    token_arg3
};

static int token_argc = sizeof(token_argv) / sizeof(token_argv[0]);

static char newtoken_path[] = "";
static char newtoken_cmd[] = "meow";
static char newtoken_arg2[] = "--soft-token=tk.1,tk.2,etc/token.iii";
static char newtoken_arg3[] = "--new-soft-token=ntk.1,ntk.2,etc/ntoken.iii";

static char *newtoken_argv[] = {
    newtoken_path,
    newtoken_cmd,
    newtoken_arg2,
    newtoken_arg3
};

static int newtoken_argc = sizeof(newtoken_argv) / sizeof(newtoken_argv[0]);

// INFO(Rafael): The test case 'blackcat_clear_option_tests' needs the following options
//               out from the .rodata otherwise it would cause an abnormal program termination.

static char path[] = "";
static char cmd[] = "meow";
static char arg2[] = "--foo=bar";
static char arg3[] = "--bar=foo";
static char arg4[] = "--bool";

static char path_default_args[] = "";
static char cmd_default_args[] = "meow";
static char arg2_default_args[] = "--foo=bar";
static char arg3_default_args[] = "--bar=foo";
static char arg4_default_args[] = "--bool";

static char *argv[] = {
    path,
    cmd,
    arg2,
    arg3,
    arg4
};

static int argc = sizeof(argv) / sizeof(argv[0]);

static unsigned char *sensitive1 =
                       "[1] The wrath sing, goddess, of Peleus' son, Achilles, that destructive wrath which brought "
                       "countless woes upon the Achaeans, and sent forth to Hades many valiant souls of heroes, and "
                       "made them themselves spoil for dogs and every bird; thus the plan of Zeus came to fulfillment, "
                       "[5] from the time when first they parted in strife Atreus' son, king of men, and brilliant Achilles. "
                       "Who then of the gods was it that brought these two together to contend? The son of Leto and Zeus; for "
                       "he in anger against the king roused throughout the host an evil pestilence, and the people began to "
                       "perish, [10] because upon the priest Chryses the son of Atreus had wrought dishonour. For he had come "
                       "to the swift ships of the Achaeans to free his daughter, bearing ransom past counting; and in his "
                       "hands he held the wreaths of Apollo who strikes from afar,2 on a staff of gold; and he implored all "
                       "the Achaeans, [15] but most of all the two sons of Atreus, the marshallers of the people: 'Sons of "
                       "Atreus, and other well-greaved Achaeans, to you may the gods who have homes upon Olympus grant that "
                       "you sack the city of Priam, and return safe to your homes; but my dear child release to me, and "
                       "accept the ransom [20] out of reverence for the son of Zeus, Apollo who strikes from afar.' "
                       "Then all the rest of the Achaeans shouted assent, to reverence the priest and accept the glorious "
                       "ransom, yet the thing did not please the heart of Agamemnon, son of Atreus, but he sent him away "
                       "harshly, and laid upon him a stern command: [25] 'Let me not find you, old man, by the hollow ships, "
                       "either tarrying now or coming back later, lest your staff and the wreath of the god not protect you. "
                       "Her I will not set free. Sooner shall old age come upon her in our house, in Argos, far from her "
                       "native land, [30] as she walks to and fro before the loom and serves my bed. But go, do not anger me, "
                       "that you may return the safer.'";
static unsigned char *sensitive2 =
                       "'Is that vodka?' Margarita asked weakly.\n"
                       "The cat jumped up in his seat with indignation.\n"
                       "'I beg pardon, my queen,' he rasped, 'Would I "
                       "ever allow myself to offer vodka to a lady? This is pure alcohol!'\n\n"
                       "The tongue may hide the truth but the eyes - never!\n\n"
                       "Cowardice is the most terrible of vices.\n\n"
                       "'You're not Dostoevsky,' said the citizeness, who was getting muddled by Koroviev. "
                       "Well, who knows, who knows,' he replied. 'Dostoevsky's dead,' said the citizeness, "
                       "but somehow not very confidently. 'I protest!' Behemoth exclaimed hotly. 'Dostoevsky is immortal!\n\n"
                       "manuscripts don't burn\n\n";
static unsigned char *sensitive3 = "Tears from the sky, in pools of pain... Tonight, I gonna go and dancing in the rain.\n";
static unsigned char *plain = "README\n";

CUTE_DECLARE_TEST_CASE(blackcat_cmd_tests_entry);

CUTE_DECLARE_TEST_CASE(blackcat_set_argc_argv_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_command_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_option_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_bool_option_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_argv_tests);
CUTE_DECLARE_TEST_CASE(get_blackcat_version_tests);
CUTE_DECLARE_TEST_CASE(blackcat_clear_options_tests);
CUTE_DECLARE_TEST_CASE(levenshtein_distance_tests);
CUTE_DECLARE_TEST_CASE(blackcat_dev_tests);
CUTE_DECLARE_TEST_CASE(mkargv_freeargv_tests);
CUTE_DECLARE_TEST_CASE(blackcat_set_argv_argc_with_default_args_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_kdf_usr_params_from_cmdline_tests);
CUTE_DECLARE_TEST_CASE(wrap_user_key_with_tokens_tests);
CUTE_DECLARE_TEST_CASE(wrap_user_key_with_new_tokens_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_wrong_arguments_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_show_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_help_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_init_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_add_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_status_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_lock_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_unlock_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_lock_unlock_at_once_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_rm_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_pack_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_unpack_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_setkey_cmd_tests);
CUTE_DECLARE_TEST_CASE(the_poking_machine_took_a_shit_and_die_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_undo_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_tests_decoy_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_init_cmd_by_using_bcrypt_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_attach_detach_cmds_tests);
CUTE_DECLARE_TEST_CASE(blackcat_untouch_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_config_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_do_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_repo_by_using_kdf_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_net_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_token_cmd_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poke_soft_token_usage_tests);

CUTE_DECLARE_TEST_CASE_SUITE(blackcat_poking_tests);

CUTE_MAIN(blackcat_cmd_tests_entry);

CUTE_TEST_CASE(blackcat_cmd_tests_entry)
    CUTE_RUN_TEST(blackcat_set_argc_argv_tests);
    CUTE_RUN_TEST(blackcat_get_command_tests);
    CUTE_RUN_TEST(blackcat_get_option_tests);
    CUTE_RUN_TEST(blackcat_get_bool_option_tests);
    CUTE_RUN_TEST(blackcat_get_argv_tests);
    CUTE_RUN_TEST(blackcat_clear_options_tests);
    CUTE_RUN_TEST(get_blackcat_version_tests);
    CUTE_RUN_TEST(levenshtein_distance_tests);
    CUTE_RUN_TEST(mkargv_freeargv_tests);
    CUTE_RUN_TEST(blackcat_set_argv_argc_with_default_args_tests);
    CUTE_RUN_TEST(blackcat_get_kdf_usr_params_from_cmdline_tests);
    CUTE_RUN_TEST(wrap_user_key_with_tokens_tests);
    CUTE_RUN_TEST(wrap_user_key_with_new_tokens_tests);
    // INFO(Rafael): If all is okay, time to poke this shit (a.k.a. 'system tests').
    CUTE_RUN_TEST_SUITE(blackcat_poking_tests);
    CUTE_RUN_TEST(blackcat_dev_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(wrap_user_key_with_new_tokens_tests)
    kryptos_u8_t *key = "TheWayYouUsedToDo";
    size_t key_size = 17;
    kryptos_u8_t *tk1 = "abcd";
    size_t tk1_size = 4;
    kryptos_u8_t *tk2 = "efdgijklmnop";
    size_t tk2_size = 12;
    kryptos_u8_t *tokeniii = "chewdatta";
    size_t tokeniii_size = 9;
    kryptos_u8_t *ntk1 = "NewThingFromTokenI";
    size_t ntk1_size = 18;
    kryptos_u8_t *ntk2 = "NewThingFromToken2";
    size_t ntk2_size = 18;
    kryptos_u8_t *ntokeniii = "NewThingFromTokenIII";
    size_t ntokeniii_size = 20;

    key_size = 17;
    key = (kryptos_u8_t *) kryptos_newseg(key_size);
    CUTE_ASSERT(key != NULL);

    memcpy(key, "TheWayYouUsedToDo", key_size);

    // INFO(Rafael): Without tokens the key must remain the same.

    CUTE_ASSERT(wrap_user_key_with_new_tokens(&key, &key_size) == 1);

    CUTE_ASSERT(key_size == 17);
    CUTE_ASSERT(key != NULL);
    CUTE_ASSERT(memcmp(key, "TheWayYouUsedToDo", key_size) == 0);

    // INFO(Rafael): Now with tokens it must change.

    blackcat_set_argc_argv(newtoken_argc, newtoken_argv);

    CUTE_ASSERT(create_file("tk.1", tk1, tk1_size) == 1);
    CUTE_ASSERT(create_file("tk.2", tk2, tk2_size) == 1);
#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(create_file("etc/token.iii", tokeniii, tokeniii_size) == 1);

    CUTE_ASSERT(create_file("ntk.1", ntk1, ntk1_size) == 1);
    CUTE_ASSERT(create_file("ntk.2", ntk2, ntk2_size) == 1);
    CUTE_ASSERT(create_file("etc/ntoken.iii", ntokeniii, ntokeniii_size) == 1);

    CUTE_ASSERT(wrap_user_key_with_new_tokens(&key, &key_size) == 1);

    CUTE_ASSERT(key_size == 73);
    CUTE_ASSERT(key != NULL);
    CUTE_ASSERT(memcmp(key, "NewThingFrNewThingFNewThingFTheWayYouUsedToDoromTokenIromToken2omTokenIII", key_size) == 0);

    kryptos_freeseg(key, key_size);

    remove("tk.1");
    remove("ntk.1");
    remove("tk.2");
    remove("ntk.2");
    remove("etc/token.iii");
    remove("etc/ntoken.iii");
    rmdir("etc");

    blackcat_clear_options();
CUTE_TEST_CASE_END

CUTE_TEST_CASE(wrap_user_key_with_tokens_tests)
    kryptos_u8_t *key = "TheWayYouUsedToDo";
    size_t key_size = 17;
    kryptos_u8_t *tk1 = "abcd";
    size_t tk1_size = 4;
    kryptos_u8_t *tk2 = "efdgijklmnop";
    size_t tk2_size = 12;
    kryptos_u8_t *tokeniii = "chewdatta";
    size_t tokeniii_size = 9;

    key_size = 17;
    key = (kryptos_u8_t *) kryptos_newseg(key_size);
    CUTE_ASSERT(key != NULL);

    memcpy(key, "TheWayYouUsedToDo", key_size);

    // INFO(Rafael): Without tokens the key must remain the same.

    CUTE_ASSERT(wrap_user_key_with_tokens(&key, &key_size) == 1);

    CUTE_ASSERT(key_size == 17);
    CUTE_ASSERT(key != NULL);
    CUTE_ASSERT(memcmp(key, "TheWayYouUsedToDo", key_size) == 0);

    // INFO(Rafael): Now with tokens it must change.

    blackcat_set_argc_argv(token_argc, token_argv);

    CUTE_ASSERT(create_file("tk.1", tk1, tk1_size) == 1);
    CUTE_ASSERT(create_file("tk.2", tk2, tk2_size) == 1);
#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(create_file("etc/token.iii", tokeniii, tokeniii_size) == 1);

    CUTE_ASSERT(wrap_user_key_with_tokens(&key, &key_size) == 1);

    CUTE_ASSERT(key_size == 42);
    CUTE_ASSERT(key != NULL);
    CUTE_ASSERT(memcmp(key, "chewefdgijabTheWayYouUsedToDocdklmnopdatta", key_size) == 0);

    kryptos_freeseg(key, key_size);

    remove("tk.1");
    remove("tk.2");
    remove("etc/token.iii");
    rmdir("etc");

    blackcat_clear_options();
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_get_kdf_usr_params_from_cmdline_tests)
    char *out;
    size_t out_size;

    // INFO(Rafael): Simulating HKDF user passing.

    blackcat_set_argc_argv(hkdf_argc, hkdf_argv);
    out = blackcat_get_kdf_usr_params_from_cmdline(&out_size);
    CUTE_ASSERT(out_size == 26);
    CUTE_ASSERT(memcmp(out, "hkdf:sha-384:Zm9vYmFy:Zm9v", out_size) == 0);
    kryptos_freeseg(out, out_size);
    blackcat_clear_options();

    // INFO(Rafael): Simulating PBKDF2 user passing.

    blackcat_set_argc_argv(pbkdf2_argc, pbkdf2_argv);
    out = blackcat_get_kdf_usr_params_from_cmdline(&out_size);
    CUTE_ASSERT(out_size == 30);
    CUTE_ASSERT(memcmp(out, "pbkdf2:blake2b-512:Zm9vYmFy:10", out_size) == 0);
    kryptos_freeseg(out, out_size);
    blackcat_clear_options();

    // INFO(Rafael): Simulating ARGON2I user passing.

    blackcat_set_argc_argv(argon2i_argc, argon2i_argv);
    out = blackcat_get_kdf_usr_params_from_cmdline(&out_size);
    CUTE_ASSERT(out_size == 32);
    CUTE_ASSERT(memcmp(out, "argon2i:Zm9vYmFy:32:38:Zm9v:YmFy", out_size) == 0);
    kryptos_freeseg(out, out_size);
    blackcat_clear_options();
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_set_argv_argc_with_default_args_tests)
    char *default_args_data = BCREPO_CONFIG_SECTION_DEFAULT_ARGS ":\n"
                              "\t--no-swap\t--dummy-arg  \t\t  \t  --wah-wah-wah-wah-wah=silly"
                              "\n\n";
    char *data;
    int a;

    argv[0] = path_default_args;
    argv[1] = cmd_default_args;
    argv[2] = arg2_default_args;
    argv[3] = arg3_default_args;
    argv[4] = arg4_default_args;

#if defined(__unix__)
    CUTE_ASSERT(mkdir(".bcrepo", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir(".bcrepo") == 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(create_file(".bcrepo/CONFIG", default_args_data, strlen(default_args_data)) == 1);

    blackcat_set_argc_argv(argc, argv);

    // INFO(Rafael): When default-args is defined in .bcrepo/CONFIG the options from original command line are zeroed after
    //               blackcat_set_argc_argv call.

    for (a = 0; a < argc; a++) {
        CUTE_ASSERT(strlen(argv[a]) == 0);
    }

    CUTE_ASSERT((data = blackcat_get_command()) != NULL);
    CUTE_ASSERT(memcmp(data, "meow", strlen(data)) == 0);

    CUTE_ASSERT((data = blackcat_get_option("foo", NULL)) != NULL);
    CUTE_ASSERT(memcmp(data, "bar", strlen(data)) == 0);

    CUTE_ASSERT((data = blackcat_get_option("bar", NULL)) != NULL);
    CUTE_ASSERT(memcmp(data, "foo", strlen(data)) == 0);

    CUTE_ASSERT((data = blackcat_get_option("wah-wah-wah-wah-wah", NULL)) != NULL);
    CUTE_ASSERT(memcmp(data, "silly", strlen(data)) == 0);

    CUTE_ASSERT(blackcat_get_bool_option("bool", 0) == 1);
    CUTE_ASSERT(blackcat_get_bool_option("dummy-arg", 0) == 1);
    CUTE_ASSERT(blackcat_get_bool_option("no-swap", 0) == 1);

    blackcat_clear_options(); // INFO(Rafael): If we got a leak it will break at the end of the tests.

    CUTE_ASSERT(remove(".bcrepo/CONFIG") == 0);
    CUTE_ASSERT(rmdir(".bcrepo") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(mkargv_freeargv_tests)
    char **argv = NULL;
    int argc;
    char *cmdline = "command --option1 --option=2 3";

    CUTE_ASSERT(mkargv(argv, NULL, strlen(cmdline), &argc) == NULL);
    CUTE_ASSERT(mkargv(argv, cmdline, 0, &argc) == NULL);
    CUTE_ASSERT(mkargv(argv, cmdline, strlen(cmdline), NULL) == NULL);

    argv = mkargv(argv, cmdline, strlen(cmdline), &argc);
    CUTE_ASSERT(argv != NULL);

    CUTE_ASSERT(argv[0] == NULL);
    CUTE_ASSERT(argc == 5);
    CUTE_ASSERT(memcmp(argv[1], "command", strlen("command")) == 0);
    CUTE_ASSERT(memcmp(argv[2], "--option1", strlen("--option1")) == 0);
    CUTE_ASSERT(memcmp(argv[3], "--option=2", strlen("--option=2")) == 0);
    CUTE_ASSERT(memcmp(argv[4], "3", strlen("3")) == 0);

    freeargv(NULL, argc);
    freeargv(argv, 0);
    // INFO(Rafael): If due to some reason freeargv() has failed. The memory leak checking system will warn us.
    freeargv(argv, argc);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(levenshtein_distance_tests)
    CUTE_ASSERT(levenshtein_distance("stat", "status") == 2);
    CUTE_ASSERT(levenshtein_distance("parangaritititero", "parangaricutirimirruaru") == 12);
    CUTE_ASSERT(levenshtein_distance("self", "help") == 2);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_set_argc_argv_tests)
    blackcat_set_argc_argv(0, NULL);
    blackcat_set_argc_argv(argc, argv);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_get_command_tests)
    CUTE_ASSERT(strcmp(blackcat_get_command(), "meow") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_get_option_tests)
    char *option;

    option = blackcat_get_option("foo", NULL);

    CUTE_ASSERT(option != NULL);
    CUTE_ASSERT(strcmp(option, "bar") == 0);

    option = blackcat_get_option("bar", NULL);
    CUTE_ASSERT(option != NULL);
    CUTE_ASSERT(strcmp(option, "foo") == 0);

    option = blackcat_get_option("not-found", NULL);
    CUTE_ASSERT(option == NULL);

    option = blackcat_get_option("food", "whiskas");
    CUTE_ASSERT(option != NULL);
    CUTE_ASSERT(strcmp(option, "whiskas") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_get_bool_option_tests)
    CUTE_ASSERT(blackcat_get_bool_option("bool", 0) == 1);
    CUTE_ASSERT(blackcat_get_bool_option("not-supplied", 0) == 0);
    CUTE_ASSERT(blackcat_get_bool_option("not-supplied", 1) == 1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_get_argv_tests)
    char *data;
    CUTE_ASSERT(blackcat_get_argv(-1) == NULL);
    data = blackcat_get_argv(0);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(strcmp(data, "--foo=bar") == 0);
    data = blackcat_get_argv(1);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(strcmp(data, "--bar=foo") == 0);
    data = blackcat_get_argv(2);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(strcmp(data, "--bool") == 0);
    CUTE_ASSERT(blackcat_get_argv(3) == NULL);
    CUTE_ASSERT(blackcat_get_argv(4) == NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_blackcat_version_tests)
    CUTE_ASSERT(strcmp(get_blackcat_version(), "1.2.0") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_clear_options_tests)
    int a;

    blackcat_clear_options();

    for (a = 0; a < argc; a++) {
        CUTE_ASSERT(strlen(argv[a]) == 0);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE_SUITE(blackcat_poking_tests)
    // INFO(Rafael): Just housekeeping.

    test_env_housekeeping();

    CUTE_RUN_TEST(blackcat_poke_wrong_arguments_tests);
    CUTE_RUN_TEST(blackcat_poke_show_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_help_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_init_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_add_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_status_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_lock_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_unlock_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_lock_unlock_at_once_tests);
    CUTE_RUN_TEST(blackcat_poke_rm_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_pack_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_unpack_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_setkey_cmd_tests);
    CUTE_RUN_TEST(the_poking_machine_took_a_shit_and_die_tests);
    CUTE_RUN_TEST(blackcat_poke_undo_cmd_tests);
    CUTE_RUN_TEST(blackcat_tests_decoy_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_init_cmd_by_using_bcrypt_tests);
    CUTE_RUN_TEST(blackcat_poke_attach_detach_cmds_tests);
    CUTE_RUN_TEST(blackcat_untouch_cmd_tests);
    CUTE_RUN_TEST(blackcat_config_cmd_tests);
    CUTE_RUN_TEST(blackcat_do_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_repo_by_using_kdf_tests);
    CUTE_RUN_TEST(blackcat_poke_net_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_token_cmd_tests);
    CUTE_RUN_TEST(blackcat_poke_soft_token_usage_tests);
CUTE_TEST_CASE_SUITE_END

CUTE_TEST_CASE(blackcat_poke_wrong_arguments_tests)
    // INFO(Rafael): Wrong commands.
    CUTE_ASSERT(blackcat("shew", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("self", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("adds", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("rms", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("state", "----", NULL) != 0);
    CUTE_ASSERT(blackcat("rinite", "---", NULL) != 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_show_cmd_tests)
    // INFO(Rafael): Showing the available ciphers, HMACs and hashes.
    CUTE_ASSERT(blackcat("show your-hands", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("show ciphers", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show hmacs", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show hashes", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show encoders", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show kdfs", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show hashes hmacs ciphers encoders kdfs", "---", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_help_cmd_tests)
    // INFO(Rafael): Quick help.
    CUTE_ASSERT(blackcat("help init", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help deinit", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help add", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help rm", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help status", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help lock", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help unlock", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help show", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help help", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help pack", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help unpack", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help token", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help man", "", NULL) == 0);
#if defined(__unix__)
    CUTE_ASSERT(blackcat("help paranoid", "", NULL) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(blackcat("help paranoid", "", NULL) != 0);
#else
# error Some code wanted.
#endif

#if defined(__unix__) && !defined(__OpenBSD__) && !defined(__minix__)
    CUTE_ASSERT(blackcat("help lkm", "", NULL) == 0);
#elif defined(_WIN32) || defined(__OpenBSD__) || defined(__minix__)
    CUTE_ASSERT(blackcat("help lkm", "", NULL) != 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(blackcat("help setkey", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help undo", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help decoy", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help info", "", NULL) == 0);

#if defined(__unix__)
    CUTE_ASSERT(blackcat("help net", "", NULL) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(blackcat("help net", "", NULL) != 0);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(blackcat("help not-implemented", "", NULL) != 0);
    CUTE_ASSERT(blackcat("help init deinit add rm status lock unlock show boo help pack unpack paranoid lkm setkey undo decoy info net man", "", NULL) != 0);

#if defined(__unix__) && !defined(__OpenBSD__) && !defined(__minix__)
    CUTE_ASSERT(blackcat("help init deinit add rm status lock unlock show help pack paranoid unpack lkm setkey undo decoy info net token man", "", NULL) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(blackcat("help init deinit add rm status lock unlock show help pack unpack setkey undo decoy info token man", "", NULL) == 0);
#elif defined(__OpenBSD__) || defined(__minix__)
    CUTE_ASSERT(blackcat("help init deinit add rm status lock unlock show help pack paranoid unpack setkey undo decoy info net token man", "", NULL) == 0);
#else
# error Some code wanted.
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_init_cmd_tests)
    char bcmd[65535], *protlayer;

    // INFO(Rafael): Init command general tests.
    CUTE_ASSERT(blackcat("init", "none", "none") != 0);

    protlayer = get_test_protlayer(0, 1);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Incomplete init.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike "
                                     "--encoder=OI''55", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=bcrypt "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=bcrypt "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);

    // INFO(Rafael): Valid keyed alike init.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") == 0);

    // INFO(Rafael): Init again must fail.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_add_cmd_tests)
    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    //INFO(Rafael): Adding s1 and s2 to the repo's catalog.

    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWantsss", NULL) != 0);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s1.txt", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/*.c", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add s3.txt --lock", "GiveTheMuleWhatHeWants", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_status_cmd_tests)
    // INFO(Rafael): Getting the current repo's status.
    CUTE_ASSERT(blackcat("status", "Ahhhhh", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/*.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status p.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_lock_cmd_tests)
    unsigned char *data;
    size_t data_size;

    // INFO(Rafael): Lock tests.

    CUTE_ASSERT(blackcat("lock p.txt", "GiveTheMuleWhatHeWants", NULL) != 0);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "Green Machine", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "GiveTheMuleWhatHeWants", NULL) != 0);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);
    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock p.txt", "GiveTheMuleWhatHeWants", NULL) != 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_unlock_cmd_tests)
    unsigned char *data;
    size_t data_size;

    // INFO(Rafael): Unlock tests.

    CUTE_ASSERT(blackcat("unlock s1.txt", "GiveTheMuleWhatHeWants.", NULL) != 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "GiveTheMuleWhatHeWants", NULL) != 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_lock_unlock_at_once_tests)
    unsigned char *data;
    size_t data_size;

    // INFO(Rafael): Lock and Unlock all at once.

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "GiveTheMuleWhatHeWants-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "GiveTheMuleWhatHeWants", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_rm_cmd_tests)
    unsigned char *data;
    size_t data_size;

    // INFO(Rafael): Rm test.

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "GiveTheMuleWhat?", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "GiveTheMuleWhat?", NULL) != 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Removing from catalog a unexistent/unaccessible file.

    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    remove("s1.txt");
    CUTE_ASSERT(blackcat("rm s1.txt", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("rm s1.txt --force", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_pack_cmd_tests)
    unsigned char *data;
    size_t data_size;

    // INFO(Rafael): Pack stuff.

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("pack", "GiveTheMuleWhatHeWants", NULL) != 0);

    CUTE_ASSERT(blackcat("pack test.bpack", "GIVETheMuleWhatHeWants", NULL) != 0);

    CUTE_ASSERT(blackcat("pack test.bpack", "GiveTheMuleWhatHeWants", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_unpack_cmd_tests)
    unsigned char *data;
    size_t data_size;

    // INFO(Rafael): Unpack stuff (only failures).

    CUTE_ASSERT(blackcat("unpack test.bpack", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("unpack test.bpack test/bpack", "GiveTheMuleWhatHeWants", NULL) != 0);

    // INFO(Rafael): Deinit stuff.

    CUTE_ASSERT(blackcat("deinit", "GiveTheMuleWhatHeWantS", NULL) != 0);

    CUTE_ASSERT(blackcat("deinit", "GiveTheMuleWhatHeWants", NULL) == 0);

    // INFO(Rafael): Unpack stuff.

    CUTE_ASSERT(blackcat("unpack test.bpack", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("status", "GIveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("unpack test.bpack unpack-test/bpack", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(chdir("unpack-test/bpack") == 0);

    CUTE_ASSERT(blackcat("status", "hjsdhashdhashdahsdjashjasjdahsdjajskdkjaskjdkasdkajksdkj", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("info", "GimmeTheMuleWhatHeWants", NULL) != 0);

    CUTE_ASSERT(blackcat("info", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "GiveTheMuleWhatHeWants", NULL) == 0);

    remove("etc/s2.txt");
    remove("s1.txt");
    remove("p.txt");
    remove("s3.txt");
    rmdir("etc");
    CUTE_ASSERT(chdir("../..") == 0);
    rmdir("unpack-test/bpack");
    rmdir("unpack-test");
    remove("test.bpack");
    remove("s3.txt");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_setkey_cmd_tests)
    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;

    protlayer = get_test_protlayer(0, 1);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Setkey stuff.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") == 0);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "All Along The Watchtower", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "All Along The Watchtower", NULL) == 0);

    // INFO(Rafael): Setting other parameters besides the keys.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    protlayer = get_test_protlayer(0, 4);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=sha12 "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=cha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tig3r "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=yyencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    if (isalpha(protlayer[0])) {
        protlayer[0] = toupper(protlayer[0]);
    } else {
        protlayer[1] = toupper(protlayer[1]);
    }

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    if (isalpha(protlayer[0])) {
        protlayer[0] = tolower(protlayer[0]);
    } else {
        protlayer[1] = tolower(protlayer[1]);
    }

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=bcrypt "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=bcrypt "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s --otp", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") == 0);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "All Along The Watchtower", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "All Along The Watchtower", NULL) == 0);

    // INFO(Rafael): Since we have changed the cascading type (from now on it is one-time pad) let's actually check
    //               the data from files after unlocking the whole repo.

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("deinit", "All Along The Watchtower", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(the_poking_machine_took_a_shit_and_die_tests)
    // ===============================================================================================
    // WARN(Rafael): This test is a crazy horse. Anyway, it does interesting things that could cause =
    //               bad states. Let's keep with this horse.                                         =
    // ===============================================================================================

    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;

    protlayer = get_test_protlayer(0, 1);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Setting other parameters besides the keys.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    protlayer = get_test_protlayer(0, 4);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=sha12 "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=cha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tig3r "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=yyencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    if (isalpha(protlayer[0])) {
        protlayer[0] = toupper(protlayer[0]);
    } else {
        protlayer[1] = toupper(protlayer[1]);
    }

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    if (isalpha(protlayer[0])) {
        protlayer[0] = tolower(protlayer[0]);
    } else {
        protlayer[1] = tolower(protlayer[1]);
    }

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=bcrypt "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=bcrypt "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s --otp", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") == 0);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "All Along The Watchtower", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "All Along The Watchtower", NULL) == 0);

    // INFO(Rafael): Since we have changed the cascading type (from now on it is one-time pad) let's actually check
    //               the data from files after unlocking the whole repo.

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("deinit", "All Along The Watchtower", NULL) == 0);

    protlayer = get_test_protlayer(0, 1);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Invalid keyed twice init with invalid key confirmations.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "IThinkILostMyHeadache\nIThinkILOstMyHeadache", "UntilMyHeadacheGoes\nUntilMyHeadacheGoes") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "IThinkILostMyHeadache\nIThinkILostMyHeadache", "UntilMyHeadacheGoe5\nUntilMyHeadacheGoes") != 0);

    // INFO(Rafael): Valid keyed twice init.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "IThinkILostMyHeadache\nIThinkILostMyHeadache", "UntilMyHeadacheGoes\nUntilMyHeadacheGoes") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);

    //INFO(Rafael): Adding s1 and s2 to the repo's catalog.

    CUTE_ASSERT(blackcat("add s1.txt", "IThinkILostMyHeadach", "UntilMyHeadacheGoes") != 0);
    CUTE_ASSERT(blackcat("add s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    CUTE_ASSERT(blackcat("add s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") != 0);
    CUTE_ASSERT(blackcat("add etc/s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") != 0);
    CUTE_ASSERT(blackcat("add etc/*.c", "IThinkILostMyHeadche", "UntilMyHeadacheGoes") != 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") != 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "IThinkILostMyHeadache", NULL) == 0);

    // INFO(Rafael): Getting the current repo's status.

    CUTE_ASSERT(blackcat("status", "Ahhhhh", "UntilMyHeadacheGoes") != 0);
    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    CUTE_ASSERT(blackcat("status s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    CUTE_ASSERT(blackcat("status etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    CUTE_ASSERT(blackcat("status etc/*.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    // INFO(Rafael): Lock tests.

    CUTE_ASSERT(blackcat("lock s1.txt", "IThinkILostMyHeadache", "Green Machine") != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") != 0);

    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    CUTE_ASSERT(blackcat("lock", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Plain files must be skipped anyway.

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    // INFO(Rafael): Unlock tests.

    CUTE_ASSERT(blackcat("unlock s1.txt", "IThinkILostMyHeadache", "GiveTheMuleWhatHeWants.") != 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") != 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(chdir("etc") == 0);

    // INFO(Rafael): Path with "go ups" are valid.
    CUTE_ASSERT(blackcat("unlock ../etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    CUTE_ASSERT(blackcat("lock ../etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    // INFO(Rafael): A relative path from the rootpath is also valid.
    CUTE_ASSERT(blackcat("unlock etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    CUTE_ASSERT(blackcat("lock etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);
    // INFO(Rafael): A relative path based on the cwd is also valid.
    CUTE_ASSERT(blackcat("unlock s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    CUTE_ASSERT(chdir("..") == 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    // INFO(Rafael): Lock and unlock all at once.

    CUTE_ASSERT(blackcat("lock", "IThinkILostMyHeadache", "GiveTheMuleWhatHeWants-") != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadcheGoes") == 0);

    CUTE_ASSERT(blackcat("unlock", "IThinkILostMyHeadache", "GiveTheMuleWhatHeWants-") != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    // INFO(Rafael): Rm test.

    CUTE_ASSERT(blackcat("lock", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "IThinkILostMyHeadache", "GiveTheMuleWhat?") != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "IThinkILostMyHeadache", "GiveTheMuleWhat?") != 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Shell conveniences.

    // ===================================================================================
    // = WARN(Rafael): Do not run `blackcat add *` or you can screw up the source codes  =
    // ===================================================================================

    CUTE_ASSERT(blackcat("add s1.txt etc/s2.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    CUTE_ASSERT(blackcat("status s1.txt etc/s2.txt p.txt", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    CUTE_ASSERT(blackcat("lock *", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock *", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm *", "IThinkILostMyHeadache", "UntilMyHeadacheGoes") == 0);

    CUTE_ASSERT(blackcat("deinit", "IThinkILostMyHeadache", NULL) == 0);

    remove("etc/s2.txt");
    rmdir("etc");
    remove("s1.txt");
    remove("p.txt");

    // INFO(Rafael): Valid keyed alike init with base64 encoding.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike "
                                     "--encoder=base64", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "PaperScratcher", "PaperScratcher") == 0);

    // INFO(Rafael): Init again must fail.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike "
                                     "--encoder=base64", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "PaperScratcher", "PaperScratcher") != 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);

    //INFO(Rafael): Adding s1 and s2 to the repo's catalog.

    CUTE_ASSERT(blackcat("add s1.txt", "PaperScratch3r", NULL) != 0);
    CUTE_ASSERT(blackcat("add s1.txt", "PaperScratcher", NULL) == 0);
    CUTE_ASSERT(blackcat("add s1.txt", "PaperScratcher", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s1.txt", "PaperScratcher", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/*.c", "PaperScratcher", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "PaperScratcher", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "PaperScratcher", NULL) != 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "PaperScratcher", NULL) == 0);

    // INFO(Rafael): Getting the current repo's status.

    CUTE_ASSERT(blackcat("status", "Ahhhhh", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);
    CUTE_ASSERT(blackcat("status s1.txt", "PaperScratcher", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/s2.txt", "PaperScratcher", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/*.txt", "PaperScratcher", NULL) == 0);
    CUTE_ASSERT(blackcat("status p.txt", "PaperScratcher", NULL) == 0);

    // INFO(Rafael): Lock tests.

    CUTE_ASSERT(blackcat("lock p.txt", "PaperScratcher", NULL) != 0);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "Green Machine", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "PaperScratcher", NULL) == 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "PaperScratcher", NULL) != 0);

    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "PaperScratcher", NULL) == 0);
    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);

    CUTE_ASSERT(blackcat("lock p.txt", "PaperScratcher", NULL) != 0);

    // INFO(Rafael): Unlock tests.

    CUTE_ASSERT(blackcat("unlock s1.txt", "PaperScratcher.", NULL) != 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "PaperScratcher", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "PaperScratcher", NULL) != 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock etc/s2.txt", "PaperScratcher", NULL) == 0);
    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);

    // INFO(Rafael): Lock and Unlock all at once.

    CUTE_ASSERT(blackcat("lock --no-swap", "PaperScratcher-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "PaperScratcher", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock --no-swap", "PaperScratcher-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "PaperScratcher", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);

    // INFO(Rafael): Rm test.

    CUTE_ASSERT(blackcat("lock", "PaperScratcher", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "PaperWhat?", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "PaperScratcher", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "PaperWhat?", NULL) != 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "PaperScratcher", NULL) == 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Deinit stuff.

    CUTE_ASSERT(blackcat("deinit", "PaperScratcheR", NULL) != 0);

    CUTE_ASSERT(blackcat("deinit", "PaperScratcher", NULL) == 0);

    remove("etc/s2.txt");
    rmdir("etc");
    remove("s1.txt");
    remove("p.txt");

    // INFO(Rafael): Valid keyed alike init with uuencode encoding.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike "
                                     "--encoder=uuencode", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "StoneFree", "StoneFree") == 0);

    // INFO(Rafael): Init again must fail.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike "
                                     "--encoder=uuencode", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "StoneFree", "StoneFree") != 0);


    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#endif
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);

    //INFO(Rafael): Adding s1 and s2 to the repo's catalog.

    CUTE_ASSERT(blackcat("add s1.txt", "5t0n3Fr33", NULL) != 0);
    CUTE_ASSERT(blackcat("add s1.txt", "StoneFree", NULL) == 0);
    CUTE_ASSERT(blackcat("add s1.txt", "StoneFree", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s1.txt", "StoneFree", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/*.c", "StoneFree", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "StoneFree", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "StoneFree", NULL) != 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "StoneFree", NULL) == 0);

    // INFO(Rafael): Getting the current repo's status.

    CUTE_ASSERT(blackcat("status", "Ahhhhh", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);
    CUTE_ASSERT(blackcat("status s1.txt", "StoneFree", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/s2.txt", "StoneFree", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/*.txt", "StoneFree", NULL) == 0);
    CUTE_ASSERT(blackcat("status p.txt", "StoneFree", NULL) == 0);

    // INFO(Rafael): Lock tests.

    CUTE_ASSERT(blackcat("lock p.txt", "StoneFree", NULL) != 0);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "Green Machine", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "StoneFree", NULL) == 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock s1.txt", "StoneFree", NULL) != 0);

    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "StoneFree", NULL) == 0);
    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);

    CUTE_ASSERT(blackcat("lock p.txt", "StoneFree", NULL) != 0);

    // INFO(Rafael): Unlock tests.

    CUTE_ASSERT(blackcat("unlock s1.txt", "StoneFree.", NULL) != 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "StoneFree", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock s1.txt", "StoneFree", NULL) != 0);
    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock etc/s2.txt", "StoneFree", NULL) == 0);
    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);

    // INFO(Rafael): Lock and Unlock all at once.

    CUTE_ASSERT(blackcat("lock", "-StoneFree-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "StoneFree", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "StoneFree-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "StoneFree", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);

    // INFO(Rafael): Rm test.

    CUTE_ASSERT(blackcat("lock", "StoneFree", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "StoneTree", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "StoneFree", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "StoneTree?!", NULL) != 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm etc/s2.txt", "StoneFree", NULL) == 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Deinit stuff.

    CUTE_ASSERT(blackcat("deinit", "StoneFreE", NULL) != 0);

    CUTE_ASSERT(blackcat("deinit", "StoneFree", NULL) == 0);

    // INFO(Rafael): Setkey stuff.

    protlayer = get_test_hmac(0);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nStang's Swang", "Rock-N-Roll'e\nRock-N-Roll'e") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "Stang's Swang", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "Stang's Swang", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "Stang's Swang", "Rock-N-Roll'e") == 0);
    CUTE_ASSERT(blackcat("status", "Stang's Swang", "Rock-N-Roll'e") == 0);

    CUTE_ASSERT(blackcat("setkey", "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") == 0);

    CUTE_ASSERT(blackcat("status", "Stang's Swang", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "Gardenia", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "Gardenia", "Kylie") == 0);
    CUTE_ASSERT(blackcat("lock", "Gardenia", "Kylie") == 0);

    CUTE_ASSERT(blackcat("deinit", "Gardenia", NULL) == 0);

    // INFO(Rafael): Setting other parameters besides the keys.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nStang's Swang", "Rock-N-Roll'e\nRock-N-Roll'e") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "Stang's Swang", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "Stang's Swang", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "Stang's Swang", "Rock-N-Roll'e") == 0);
    CUTE_ASSERT(blackcat("status", "Stang's Swang", NULL) == 0);

    protlayer = get_test_protlayer(0, 4);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=sha12 "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=cha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tig3r "
                                     "--encoder=uuencoder "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=yyencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    if (isalpha(protlayer[0])) {
        protlayer[0] = toupper(protlayer[0]);
    } else {
        protlayer[1] = toupper(protlayer[1]);
    }

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    if (isalpha(protlayer[0])) {
        protlayer[0] = tolower(protlayer[0]);
    } else {
        protlayer[1] = tolower(protlayer[1]);
    }

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Suang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-iN-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nArdenia\nKylie\nKylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKrylie") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                     "--catalog-hash=whirlpool "
                                     "--key-hash=sha-512 "
                                     "--protection-layer-hash=tiger "
                                     "--encoder=uuencode "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") == 0);

    CUTE_ASSERT(blackcat("status", "Stang's Swang", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "Gardenia", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "Gardenia", "Kylie") == 0);
    CUTE_ASSERT(blackcat("lock", "Gardenia", "Kylie") == 0);

    CUTE_ASSERT(blackcat("deinit", "Gardenia", NULL) == 0);

    remove("etc/s2.txt");
    rmdir("etc");
    remove("s1.txt");
    remove("p.txt");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_undo_cmd_tests)
    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;
    FILE *fp;
    char cwd[4096];

    // INFO(Rafael): undo test.

    protlayer = get_test_protlayer(0, 1);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Talking head\nTalking head", "Who knows\nWho knows") == 0);

#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "Talking head", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "Talking head", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "Talking head", "Who knows") == 0);
    CUTE_ASSERT(blackcat("status", "Talking head", NULL) == 0);

    fp = fopen(".bcrepo/rescue", "wb");
    CUTE_ASSERT(fp != NULL);

    CUTE_ASSERT(getcwd(cwd, sizeof(cwd) - 1) != NULL);
    fprintf(fp, "%s/etc/s2.txt,53\nthe quick lazy fox is fed up with this stupid phrase.", cwd);
    fclose(fp);

    CUTE_ASSERT(blackcat("undo", "Talking mad", NULL) != 0);

    CUTE_ASSERT(blackcat("undo", "Talking head", NULL) == 0);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 53);
    CUTE_ASSERT(memcmp(data, "the quick lazy fox is fed up with this stupid phrase.", 53) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("deinit", "Talking head", NULL) == 0);

    remove("s1.txt");
    remove("sd.txt");
    remove("sod.txt");
    remove("etc/s2.txt");
    remove("etc/sd.txt");
    remove("etc/sod.txt");
    rmdir("etc");
    remove("p.txt");
    remove("pd.txt");
    remove("pod.txt");

CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_tests_decoy_cmd_tests)
    char bcmd[65535], *protlayer;

    protlayer = get_test_protlayer(0, 4);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=whirlpool "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Talking head\nTalking head", "Who knows\nWho knows") == 0);

#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif
    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "Talking head", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "Talking head", NULL) == 0);

    CUTE_ASSERT(blackcat("decoy etc/sd.txt sd.txt --encoder=base64 --overwrite", "Wrong pass.", NULL) != 0);
    CUTE_ASSERT(blackcat("decoy etc/sd.txt sd.txt --fsize=8192 --encoder=base64", "Talking head", NULL) == 0);
    CUTE_ASSERT(blackcat("decoy etc/sd.txt sd.txt --fsize=8192 --encoder=uuencode", "Wrong pass.", NULL) != 0);
    CUTE_ASSERT(blackcat("decoy etc/sd.txt sd.txt --fsize=8192 --encoder=uuencode --overwrite", "Wrong pass.", NULL) != 0);
    CUTE_ASSERT(blackcat("decoy etc/sd.txt sd.txt --fsize=8192 --encoder=uuencode --overwrite", "Talking head", NULL) == 0);
    CUTE_ASSERT(blackcat("decoy pd.txt --fsize=8192", "Talking head", NULL) == 0);

    // INFO(Rafael): Let's test the otp decoy.

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike --otp "
                                     "--protection-layer=%s", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Talking head\nWho knows", "Talking head\nTalking head") == 0);

    CUTE_ASSERT(blackcat("decoy etc/sod.txt sod.txt --fsize=8192 --encoder=uuencode --overwrite", "Talking head", NULL) == 0);
    CUTE_ASSERT(blackcat("decoy pod.txt --fsize=8192", "Talking head", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "Talking head", NULL) == 0);

    remove("s1.txt");
    remove("sd.txt");
    remove("sod.txt");
    remove("etc/s2.txt");
    remove("etc/sd.txt");
    remove("etc/sod.txt");
    rmdir("etc");
    remove("p.txt");
    remove("pd.txt");
    remove("pod.txt");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_init_cmd_by_using_bcrypt_tests)
    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;

    protlayer = get_test_protlayer(0, 1);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): For people who like bcrypt with love (keyed alike init first, ok?).

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "HazeJaneII", "HazeJaneII") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=101 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "HazeJaneII", "HazeJaneII") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=6 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "HazeJaneII"
                                          "HazeJaneII"
                                          "HazeJaneII"
                                          "HazeJaneII"
                                          "HazeJaneII"
                                          "HazeJaneII"
                                          "HazeJaneII!!!", "HazeJaneII"
                                                           "HazeJaneII"
                                                           "HazeJaneII"
                                                           "HazeJaneII"
                                                           "HazeJaneII"
                                                           "HazeJaneII"
                                                           "HazeJaneII!!!") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=6 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);


    CUTE_ASSERT(blackcat(bcmd, "HazeJaneII", "HazeJaneII") == 0);

#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    //INFO(Rafael): Adding s1 and s2 to the repo's catalog.

    CUTE_ASSERT(blackcat("add s1.txt", "HazeJaneIII", NULL) != 0);
    CUTE_ASSERT(blackcat("add s1.txt", "HazeJaneII", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/*.c", "HazeJaneII", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "HazeJaneII", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "HazeJaneII", NULL) != 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "HazeJaneII", NULL) == 0);
    CUTE_ASSERT(blackcat("add s3.txt --lock", "HazeJaneII", NULL) == 0);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "HazeJaneII", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "HazeJaneII", NULL) == 0);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("deinit", "HazeJaneII", NULL) == 0);

    // INFO(Rafael): Now two-layer keys.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "HazeJaneII\nHazeJaneII", "IPutASpellOnYou\nIPutASpellOnYou") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=82 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "HazeJaneII\nHazeJaneII", "OhWee!\nOhWee!") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=6 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "HazeJaneII\nHazeJaneII", "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone\n"
                                                   "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=8 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "HazeJaneII\nHazeJaneII", "NoOneKnows\nNoOneKnows") == 0);


    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    //INFO(Rafael): Adding s1 and s2 to the repo's catalog.

    CUTE_ASSERT(blackcat("add s1.txt", "HazeJaneIII", NULL) != 0);
    CUTE_ASSERT(blackcat("add s1.txt", "HazeJaneII", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/*.c", "HazeJaneII", NULL) != 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "HazeJaneII", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "HazeJaneII", NULL) != 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "HazeJaneII", NULL) == 0);
    CUTE_ASSERT(blackcat("add s3.txt --lock", "HazeJaneII", "NoOneKnows") == 0);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "HazeJaneII", "NoUoniQuinousJeguere") != 0);

    CUTE_ASSERT(blackcat("lock", "HazeJaneII", "NoOneKnows") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "HazeJaneII", "NoOneKnows") == 0);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("deinit", "HazeJaneII", NULL) == 0);

    remove("s1.txt");
    remove("etc/s2.txt");
    remove("s3.txt");
    remove("p.txt");
    rmdir("etc");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_attach_detach_cmds_tests)
    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;

    protlayer = get_test_protlayer(0, 4);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Repo detaching & attaching tests.

    CUTE_ASSERT(blackcat("detach --dest=metainfo.yyz", "", NULL) != 0);

#if defined(__unix__)
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("etc") == 0);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=tiger "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s "
                                     "--keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "ThingsIUsedToDo", "ThingsIUsedToDo") == 0);

    CUTE_ASSERT(blackcat("add s1.txt", "ThingsIUsedToDo", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "ThingsIUsedToDo", NULL) == 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "ThingsIUsedToDo", NULL) == 0);
    CUTE_ASSERT(blackcat("add s3.txt --lock", "ThingsIUsedToDo", "NoOneKnows") == 0);

    CUTE_ASSERT(blackcat("detach", "", NULL) != 0);
    CUTE_ASSERT(blackcat("detach --dest=metainfo.yyz", "", NULL) == 0);

    CUTE_ASSERT(blackcat("status", "ThingsIUsedToDo", NULL) != 0);

    CUTE_ASSERT(blackcat("attach", "", NULL) != 0);
    CUTE_ASSERT(blackcat("attach --src=metainfo.yyz", "", NULL) == 0);

    CUTE_ASSERT(remove("metainfo.yyz") == 0);

    CUTE_ASSERT(blackcat("status", "ThingsIUsedToDo", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "ThingsIUsedToDo", NULL) == 0);

    remove("s1.txt");
    remove("etc/s2.txt");
    remove("s3.txt");
    remove("p.txt");
    rmdir("etc");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_untouch_cmd_tests)
    struct stat st_old, st_curr;
    char bcmd[65535], *protlayer;

    protlayer = get_test_protlayer(0, 6);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Untouch tests.

    remove("untouch-test/etc/s2.txt");
    remove("untouch-test/s1.txt");
    remove("untouch-test/s3.txt");
    remove("untouch-test/p.txt");
    rmdir("untouch-test/etc");
    rmdir("untouch-test");

    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // WARN(Rafael): Do not run this test outside untouch-test directory, otherwise it can recusivelly screw up!
    //               source codes file time info.                                                              !
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

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
#else
# error Some code wanted.
#endif

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=8 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s --keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Exempt\nExempt", NULL) == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    CUTE_ASSERT(blackcat("add s1.txt --lock", "Exempt", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt --lock", "Exempt", NULL) == 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "Exempt", NULL) == 0);
    CUTE_ASSERT(blackcat("add s3.txt --lock", "Exempt", NULL) == 0);

    CUTE_ASSERT(stat("etc/s2.txt", &st_old) == 0);

    CUTE_ASSERT(blackcat("untouch etc/s2.txt", "Exempt", NULL) == 0);

    CUTE_ASSERT(stat("etc/s2.txt", &st_curr) == 0);

#if defined(__unix__)
    CUTE_ASSERT(memcmp(&st_curr.st_atim, &st_old.st_atim, sizeof(st_old.st_atime)) != 0);
    CUTE_ASSERT(memcmp(&st_curr.st_mtim, &st_old.st_mtim, sizeof(st_old.st_mtime)) != 0);
#elif defined(_WIN32)
    CUTE_ASSERT(memcmp(&st_curr.st_atime, &st_old.st_atime, sizeof(st_old.st_atime)) != 0);
    CUTE_ASSERT(memcmp(&st_curr.st_mtime, &st_old.st_mtime, sizeof(st_old.st_mtime)) != 0);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(blackcat("untouch etc/s2.txt --hard", "Exempt", NULL) == 0);

    CUTE_ASSERT(stat("etc/s2.txt", &st_curr) == 0);

#if defined(__unix__)
    CUTE_ASSERT(memcmp(&st_curr.st_atim, &st_old.st_atim, sizeof(st_old.st_atime)) != 0);
    CUTE_ASSERT(memcmp(&st_curr.st_mtim, &st_old.st_mtim, sizeof(st_old.st_mtime)) != 0);
    CUTE_ASSERT(memcmp(&st_curr.st_ctim, &st_old.st_ctim, sizeof(st_old.st_ctime)) != 0);
#elif defined(_WIN32)
    CUTE_ASSERT(memcmp(&st_curr.st_atime, &st_old.st_atime, sizeof(st_old.st_atime)) != 0);
    CUTE_ASSERT(memcmp(&st_curr.st_mtime, &st_old.st_mtime, sizeof(st_old.st_mtime)) != 0);
    CUTE_ASSERT(memcmp(&st_curr.st_ctime, &st_old.st_ctime, sizeof(st_old.st_ctime)) != 0);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(blackcat("deinit", "Exempt", NULL) == 0);

    remove("s1.txt");
    remove("etc/s2.txt");
    remove("s3.txt");
    remove("p.txt");
    rmdir("etc");
    chdir("..");
    rmdir("untouch-test");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_config_cmd_tests)
    char bcmd[65535], *protlayer;

    protlayer = get_test_protlayer(0, 2);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Config tests.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=8 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s --keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Zzz\nZzz", NULL) == 0);

    CUTE_ASSERT(blackcat("config --update", "Zzz", NULL) != 0);

    CUTE_ASSERT(create_file(".bcrepo/CONFIG", "boo!!", 5) == 1);

    CUTE_ASSERT(blackcat("config --update", "Zzz!!", NULL) != 0);
    CUTE_ASSERT(blackcat("config --update", "Zzz", NULL) == 0);

    CUTE_ASSERT(blackcat("config --check-integrity", "Zzz", NULL) == 0);

    CUTE_ASSERT(blackcat("config --check-integrity", "Zzz", NULL) == 0);

    CUTE_ASSERT(create_file(".bcrepo/CONFIG", "boo!", 4) == 1);

    CUTE_ASSERT(blackcat("config --check-integrity", "Zzz", NULL) != 0);

    CUTE_ASSERT(blackcat("config --update", "Zzz", NULL) == 0);

    CUTE_ASSERT(blackcat("config --check-integrity", "Zzz", NULL) == 0);

    CUTE_ASSERT(blackcat("config --remove", "Zzza", NULL) != 0);

    CUTE_ASSERT(blackcat("config --remove", "Zzz", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "Zzz", NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_do_cmd_tests)
    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;

    protlayer = get_test_protlayer(0, 3);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Do tests.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--catalog-hash=sha3-384 "
                                     "--key-hash=bcrypt "
                                     "--bcrypt-cost=8 "
                                     "--protection-layer-hash=sha-512 "
                                     "--protection-layer=%s --keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Zzzoldar\nZzzoldar", NULL) == 0);

#if defined(__unix__)
    CUTE_ASSERT(create_file(".bcrepo/CONFIG",
                            "user-commands:\n\tlock-s1\n\tlock-s3\n\tunlock-s1\n\tunlock-s3\n\n"
                            "lock-s1:\n\t../../../bin/blackcat lock s1.txt<dummy\n\n"
                            "lock-s3:\n\t../../../bin/blackcat lock s3.txt<dummy\n\n"
                            "unlock-s1:\n\t../../../bin/blackcat unlock s1.txt<dummy\n\n"
                            "unlock-s3:\n\t../../../bin/blackcat unlock s3.txt<dummy\n\n",
                            strlen("user-commands:\n\tlock-s1\n\tlock-s3\n\tunlock-s1\n\tunlock-s3\n\n"
                                    "lock-s1:\n\t../../../bin/blackcat lock s1.txt<dummy\n\n"
                                    "lock-s3:\n\t../../../bin/blackcat lock s3.txt<dummy\n\n"
                                    "unlock-s1:\n\t../../../bin/blackcat unlock s1.txt<dummy\n\n"
                                    "unlock-s3:\n\t../../../bin/blackcat unlock s3.txt<dummy\n\n")) == 1);
#elif defined(_WIN32)
    CUTE_ASSERT(create_file(".bcrepo/CONFIG",
                            "user-commands:\n\tlock-s1\n\tlock-s3\n\tunlock-s1\n\tunlock-s3\n\n"
                            "lock-s1:\n\t..\\..\\..\\bin\\blackcat.exe lock s1.txt<dummy\n\n"
                            "lock-s3:\n\t..\\..\\..\\bin\\blackcat.exe lock s3.txt<dummy\n\n"
                            "unlock-s1:\n\t..\\..\\..\\bin\\blackcat.exe unlock s1.txt<dummy\n\n"
                            "unlock-s3:\n\t..\\..\\..\\bin\\blackcat.exe unlock s3.txt<dummy\n\n",
                            strlen("user-commands:\n\tlock-s1\n\tlock-s3\n\tunlock-s1\n\tunlock-s3\n\n"
                                    "lock-s1:\n\t..\\..\\..\\bin\\blackcat.exe lock s1.txt<dummy\n\n"
                                    "lock-s3:\n\t..\\..\\..\\bin\\blackcat.exe lock s3.txt<dummy\n\n"
                                    "unlock-s1:\n\t..\\..\\..\\bin\\blackcat.exe unlock s1.txt<dummy\n\n"
                                    "unlock-s3:\n\t..\\..\\..\\bin\\blackcat.exe unlock s3.txt<dummy\n\n")) == 1);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(blackcat("config --update", "Zzzoldar", NULL) == 0);

    CUTE_ASSERT(create_file("dummy", "Zzzoldar\n", strlen("Zzzoldar\n")) == 1);
    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    CUTE_ASSERT(blackcat("add s1.txt", "Zzzoldar", NULL) == 0);
    CUTE_ASSERT(blackcat("add s3.txt", "Zzzoldar", NULL) == 0);

    CUTE_ASSERT(blackcat("do --me-wrong", "Zzzoldar", NULL) != 0);

    CUTE_ASSERT(blackcat("do --lock-s1", "Zzzoldar", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("do --unlock-s1", "Zzzoldar!", NULL) != 0);
    CUTE_ASSERT(blackcat("do --unlock-s1", "Zzzoldar", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("do --lock-s3", "Zzzoldar", NULL) == 0);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("do --unlock-s3", "Soldar", NULL) != 0);
    CUTE_ASSERT(blackcat("do --unlock-s3", "Zzzoldar", NULL) == 0);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("deinit", "Zzzoldar", NULL) == 0);
    remove("s1.txt");
    remove("s3.txt");
    remove("dummy");

CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_repo_by_using_kdf_tests)
    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;

    protlayer = get_test_protlayer(0, 4);

    CUTE_ASSERT(protlayer != NULL);

    // INFO(Rafael): Blackcat repository with KDF usage.

    // INFO(Rafael): Invalid KDF will fail.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--key-hash=sha3-512 "
                                     "--catalog-hash=blake2s-256 "
                                     "--protection-layer-hash=sha-512 "
                                     "--kdf=BufferLowChip "
                                     "--protection-layer=%s --keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Manolete\nManolete", NULL) != 0);

    // INFO(Rafael): Now HKDF will be configured to derive protection layer keys.

    snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                     "--key-hash=sha3-512 "
                                     "--catalog-hash=blake2s-256 "
                                     "--protection-layer-hash=sha-512 "
                                     "--kdf=hkdf "
                                     "--hkdf-salt=GhostBeach "
                                     "--hkdf-info=Catamaran "
                                     "--protection-layer=%s --keyed-alike", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Manolete\nManolete", NULL) == 0);

    // INFO(Rafael): Getting repo info.

    CUTE_ASSERT(blackcat("info", "Manolete", NULL) == 0);

    // INFO(Rafael): Repository poking...

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    CUTE_ASSERT(blackcat("add s1.txt s2.txt --lock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("add s3.txt", "Manolete", NULL) == 0);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("add p.txt --plain", "MANOleTE", NULL) != 0);
    CUTE_ASSERT(blackcat("add p.txt --plain", "Manolete", NULL) == 0);
    CUTE_ASSERT(blackcat("lock", "Manolete", NULL) == 0);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Unknown KDF will fail.

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--kdf=PerpetualOyster ",
                         "Manolete\nManolete\nManolete", "") != 0);

    // INFO(Rafael): Known KDF but with null hash function will fail.

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--kdf=pbkdf2 ",
                         "Manolete\nManolete\nManolete", "") != 0);

    // INFO(Rafael): PBKDF2 with invalid count parameter will fail.

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--kdf=pbkdf2 "
                         "--pbkdf2-hash=blake2b-512 "
                         "--pbkdf2-salt=Perpetual0yster "
                         "--pbkdf2-count=1+18 ",
                         "Manolete\nManolete\nManolete", "") != 0);

    // INFO(Rafael): Finally, we will put PBKDF2 to work on.

    protlayer = get_test_protlayer(0, 2);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--protection-layer=%s "
                                     "--kdf=pbkdf2 "
                                     "--pbkdf2-hash=blake2b-512 "
                                     "--pbkdf2-salt=Perpetual0yster "
                                     "--pbkdf2-count=19 ", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Manolete\nManolete\nManolete", "") == 0);

    // INFO(Rafael): Getting info.

    CUTE_ASSERT(blackcat("info", "Manolete", NULL) == 0);

    // INFO(Rafael): Blackcat's sandbox poking...

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Now we will got ARGON2I as KDF in this repository.

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--kdf=argon2i "
                         "--argon2i-salt=IMakeWierdChoices "
                         "--argon2i-key=Maced0ni4nLines "
                         "--argon2i-iterations=20 "
                         "--argon2i-aad=SonnyBonoMemorialFreeway",
                         "Manolete\nManolete\nManolete", "") == 0);

    // INFO(Rafael): Getting info.

    CUTE_ASSERT(blackcat("info", "Manolete", NULL) == 0);

    // INFO(Rafael): Repo poking...

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): Using the internal blackcat protection layer derivation instead of some external standard KDF.

    // INFO(Rafael): Stop using the previously configured KDF.

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--no-kdf",
                         "Manolete\nManolete\nManolete", "") == 0);

    // INFO(Rafael): Try to remove a KDF without having a KDF must not explode.

    snprintf(bcmd, sizeof(bcmd) - 1, "setkey --keyed-alike "
                                     "--protection-layer=%s "
                                     "--no-kdf", protlayer);

    CUTE_ASSERT(blackcat(bcmd,
                         "Manolete\nManolete\nManolete", "") == 0);

    // INFO(Rafael): Getting some info.

    CUTE_ASSERT(blackcat("info", "Manolete", NULL) == 0);

    // INFO(Rafael): Repository poking stuff.

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("unlock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive1));
    CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive2));
    CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(sensitive3));
    CUTE_ASSERT(memcmp(data, sensitive3, data_size) == 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "Manolete", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(memcmp(data, sensitive3, strlen(sensitive3)) != 0);
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    // INFO(Rafael): We done here. All KDF stuff seems to be okay.

    CUTE_ASSERT(blackcat("deinit", "Manolete", NULL) == 0);
    remove("s1.txt");
    remove("s2.txt");
    remove("p.txt");
    remove("s3.txt");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_net_cmd_tests)
    char bcmd[65535], *protlayer;
    unsigned char *data;
    size_t data_size;
    char *ntool_out[] = {
        "write/read client",
        "send/recv client",
        "sendmsg/recvmsg client",
        "sendto/recvfrom client",
        "write/read server",
        "send/recv server",
        "sendmsg/recvmsg server",
        "sendto/recvfrom server"
    };
    size_t ntool_out_nr = sizeof(ntool_out) / sizeof(ntool_out[0]), n;

#if !defined(SKIP_NET_TESTS)

    protlayer = get_test_protlayer(0, 2);

    CUTE_ASSERT(protlayer != NULL);

    snprintf(bcmd, sizeof(bcmd) - 1, "net --add-rule --rule=ntool-rule --type=socket --hash=bcrypt "
                                     "--protection-layer=%s --db-path=ntool-test.db", protlayer);

    remove("ntool-test.db");
    remove("ntool.log");
    CUTE_ASSERT(blackcat(bcmd, "test", "test") != 0);

    snprintf(bcmd, sizeof(bcmd) - 1, "net --add-rule --rule=ntool-rule --type=socket --hash=whirlpool "
                                     "--protection-layer=%s --db-path=ntool-test.db", protlayer);

    CUTE_ASSERT(blackcat(bcmd, "test", "test") == 0);

    if (has_tcpdump()) {
#if defined(__linux__)
        CUTE_ASSERT(system("tcpdump -i lo -A -c 20 > ntool-traffic.log &") == 0);
#elif defined(__NetBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 20 > ntool-traffic.log &") == 0);
#elif defined(__FreeBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 20 > ntool-traffic.log &") == 0);
#elif defined(__OpenBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 20 > ntool-traffic.log &") == 0);
#else
# error Some code wanted.
#endif
        sleep(1);
    } else {
        printf("WARN: Unable to intercept packets during 'net/--run' tests. For a more complete test install tcpdump.\n");
    }

    CUTE_ASSERT(blackcat("net --run --rule=ntool-rule --bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                         "ntool/bin/ntool 2> ntool.log", "test", "abc\nabc") == 0);

    if (has_tcpdump()) {
        sleep(3);
        data = get_file_data("ntool-traffic.log", &data_size);
        CUTE_ASSERT(data != NULL);
        remove("ntool-traffic.log");
        for (n = 0; n < ntool_out_nr; n++) {
            CUTE_ASSERT(strstr(data, ntool_out[n]) == NULL);
        }
        kryptos_freeseg(data, data_size);
    }

    data = get_file_data("ntool.log", &data_size);
    CUTE_ASSERT(data != NULL);

    for (n = 0; n < ntool_out_nr; n++) {
        CUTE_ASSERT(strstr(data, ntool_out[n]) != NULL);
    }

    kryptos_freeseg(data, data_size);
    remove("ntool.log");

#if !defined(__NetBSD__)

    //INFO(Rafael): Testing the strengthened E2EE mode (with a double ratchet mechanism).

    if (has_tcpdump()) {
#if defined(__linux__)
        CUTE_ASSERT(system("tcpdump -i lo -A -c 80 > ntool-traffic.log &") == 0);
#elif defined(__NetBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 80 > ntool-traffic.log &") == 0);
#elif defined(__FreeBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 80 > ntool-traffic.log &") == 0);
#elif defined(__OpenBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 80 > ntool-traffic.log &") == 0);
#else
# error Some code wanted.
#endif
        sleep(1);
    }

    remove("ntool.server.log");
    remove("ntool.client.log");

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=104 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s write/read 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=104 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c write/read 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=105 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s send/recv 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=105 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c send/recv 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=106 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s sendto/recvfrom 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=106 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c sendto/recvfrom 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=107 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s sendmsg/recvmsg 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=107 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c sendmsg/recvmsg 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(100);

    if (has_tcpdump()) {
        data = get_file_data("ntool-traffic.log", &data_size);
        CUTE_ASSERT(data != NULL);
        remove("ntool-traffic.log");
        for (n = 0; n < ntool_out_nr; n++) {
            CUTE_ASSERT(strstr(data, ntool_out[n]) == NULL);
        }
        kryptos_freeseg(data, data_size);
    }

    data = get_file_data("ntool.server.log", &data_size);
    CUTE_ASSERT(data != NULL);

    for (n = 0; n < (ntool_out_nr >> 1); n++) {
        CUTE_ASSERT(strstr(data, ntool_out[n]) != NULL);
    }

    kryptos_freeseg(data, data_size);

    data = get_file_data("ntool.client.log", &data_size);
    CUTE_ASSERT(data != NULL);

    for (n = ntool_out_nr >> 1; n < ntool_out_nr; n++) {
        CUTE_ASSERT(strstr(data, ntool_out[n]) != NULL);
    }

    kryptos_freeseg(data, data_size);

    remove("ntool.server.log");
    remove("ntool.client.log");

#else

    CUTE_ASSERT(blackcat("net --run --e2ee --rule=ntool-rule --xchg-port=104 "
                         "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                         "ntool/bin/ntool -s write/read 2>> ntool.server.log", "test", "abc\nabc") != 0);

#endif

    CUTE_ASSERT(blackcat("net --mk-dh-params --out=dh-params.txt --p-bits=160 --q-bits=32", "", NULL) == 0);

    CUTE_ASSERT(blackcat("net --mk-dh-key-pair --public-key-out=k.pub --private-key-out=k.priv --dh-params-in=dh-params.txt",
                         "1234", "1235") != 0);

    CUTE_ASSERT(blackcat("net --mk-dh-key-pair --public-key-out=k.pub --private-key-out=k.priv --dh-params-in=dh-params.txt",
                         "1234", "1234") == 0);

    CUTE_ASSERT(blackcat_nowait("net --skey-xchg --server --kpub=k.pub --port=5002 --bits=32",
                                "WabbaLabbaDubDub!\nWabbaLabbaDubDub!", NULL) == 0);

    CUTE_ASSERT(blackcat("net --skey-xchg --kpriv=k.priv --port=5002 --addr=127.0.0.1", "123", NULL) != 0);

    CUTE_ASSERT(blackcat_nowait("net --skey-xchg --kpriv=k.priv --port=5002 --addr=127.0.0.1", "1234", NULL) == 0);

#if !defined(__NetBSD__)

    if (has_tcpdump()) {
#if defined(__linux__)
        CUTE_ASSERT(system("tcpdump -i lo -A -c 80 > ntool-traffic.log &") == 0);
#elif defined(__NetBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 80 > ntool-traffic.log &") == 0);
#elif defined(__FreeBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 80 > ntool-traffic.log &") == 0);
#elif defined(__OpenBSD__)
        CUTE_ASSERT(system("tcpdump -i lo0 -A -c 80 > ntool-traffic.log &") == 0);
#else
# error Some code wanted.
#endif
        sleep(1);
    }

    remove("ntool.server.log");
    remove("ntool.client.log");

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=144 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpub=k.pub --bits=32 "
                                "ntool/bin/ntool -s write/read 2>> ntool.server.log", "test", NULL) == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=144 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpriv=k.priv "
                                "ntool/bin/ntool -c write/read 2>> ntool.client.log", "test", "1234") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=145 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpub=k.pub --bits=32 "
                                "ntool/bin/ntool -s send/recv 2>> ntool.server.log", "test", NULL) == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=145 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpriv=k.priv "
                                "ntool/bin/ntool -c send/recv 2>> ntool.client.log", "test", "1234") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=146 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpub=k.pub --bits=32 "
                                "ntool/bin/ntool -s sendto/recvfrom 2>> ntool.server.log", "test", NULL) == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=146 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpriv=k.priv "
                                "ntool/bin/ntool -c sendto/recvfrom 2>> ntool.client.log", "test", "1234") == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=147 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpub=k.pub --bits=32 "
                                "ntool/bin/ntool -s sendmsg/recvmsg 2>> ntool.server.log", "test", NULL) == 0);

    usleep(100);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=147 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "--kpriv=k.priv "
                                "ntool/bin/ntool -c sendmsg/recvmsg 2>> ntool.client.log", "test", "1234") == 0);

    if (has_tcpdump()) {
        data = get_file_data("ntool-traffic.log", &data_size);
        CUTE_ASSERT(data != NULL);
        remove("ntool-traffic.log");
        for (n = 0; n < ntool_out_nr; n++) {
            CUTE_ASSERT(strstr(data, ntool_out[n]) == NULL);
        }
        kryptos_freeseg(data, data_size);
    }

    data = get_file_data("ntool.server.log", &data_size);
    CUTE_ASSERT(data != NULL);

    for (n = 0; n < (ntool_out_nr >> 1); n++) {
        CUTE_ASSERT(strstr(data, ntool_out[n]) != NULL);
    }

    kryptos_freeseg(data, data_size);

    data = get_file_data("ntool.client.log", &data_size);
    CUTE_ASSERT(data != NULL);

    for (n = ntool_out_nr >> 1; n < ntool_out_nr; n++) {
        CUTE_ASSERT(strstr(data, ntool_out[n]) != NULL);
    }

    kryptos_freeseg(data, data_size);

    remove("ntool.server.log");
    remove("ntool.client.log");

#endif

    CUTE_ASSERT(remove("k.pub") == 0);
    CUTE_ASSERT(remove("k.priv") == 0);
    CUTE_ASSERT(remove("dh-params.txt") == 0);

    CUTE_ASSERT(blackcat("net --drop-rule --rule=ntool --db-path=ntool-test.db", "test", NULL) != 0);

    CUTE_ASSERT(blackcat("net --drop-rule --rule=ntool-rule --db-path=ntool-test.db", "tEst", NULL) != 0);

    CUTE_ASSERT(blackcat("net --drop-rule --rule=ntool-rule --db-path=ntool-test.db", "test", NULL) == 0);
    remove("ntool-test.db");
#else
    printf("=====\n"
           "WARN: The net module tests were skipped.\n"
           "=====\n");
#endif

CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_soft_token_usage_tests)
    char bcmd[65535];
    char *repotypes[] = {
        "init "
        " --catalog-hash=blake2b-512"
        " --key-hash=tiger"
        " --protection-layer-hash=whirlpool"
        " --protection-layer=%s"
        " --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
        "init "
        " --catalog-hash=blake2b-512"
        " --key-hash=tiger"
        " --protection-layer-hash=whirlpool"
        " --protection-layer=%s"
        " --otp"
        " --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
        "init "
        " --catalog-hash=sha3-512"
        " --key-hash=blake2s-256"
        " --protection-layer-hash=sha-224"
        " --protection-layer=%s"
        " --encoder=uuencode"
        " --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
        "init "
        " --catalog-hash=sha3-512"
        " --key-hash=bcrypt"
        " --bcrypt-cost=8"
        " --protection-layer-hash=sha-224"
        " --protection-layer=%s"
        " --encoder=base64"
        " --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
        "init "
        " --catalog-hash=sha3-512"
        " --key-hash=blake2s-256"
        " --protection-layer-hash=sha-224"
        " --protection-layer=%s"
        " --encoder=uuencode"
        " --keyed-alike"
        " --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
        "init "
        " --catalog-hash=sha3-512"
        " --key-hash=blake2s-256"
        " --protection-layer-hash=sha-224"
        " --protection-layer=%s"
        " --encoder=uuencode"
        " --kdf=pbkdf2"
        " --pbkdf2-count=32"
        " --pbkdf2-salt=\\xAA\\xBB\\xCCAABBCC\\x00"
        " --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat"
    };
    size_t repotypes_nr = sizeof(repotypes) / sizeof(repotypes[0]);
    char **rp, **rp_end;
    unsigned char *data;
    size_t data_size;

    remove("tokens/a.dat");
    remove("tokens/b.dat");
    remove("tokens/c.dat");
    remove("tokens/d.dat");
    remove("tokens/e.dat");
    remove("tokens/f.dat");
    rmdir("tokens");

    snprintf(bcmd, sizeof(bcmd) - 1, repotypes[0], get_test_protlayer(0, 3));
    // INFO(Rafael): It should fail due to the tokens do not exist.
    CUTE_ASSERT(blackcat(bcmd, "SkatingAway\nSkatingAway", "OnTheThinIceOfTheNewDay\nOnTheThinIceOfTheNewDay") != 0);

#if defined(__unix__)
    CUTE_ASSERT(mkdir("tokens", 0666) == 0);
#elif defined(_WIN32)
    CUTE_ASSERT(mkdir("tokens") == 0);
#else
# error Some code wanted.
#endif

    CUTE_ASSERT(blackcat("token tokens/a.dat tokens/b.dat tokens/c.dat --bytes=16", "", NULL) == 0);

    rp = &repotypes[0];
    rp_end = rp + repotypes_nr;

    while (rp != rp_end) {
        remove("s1.txt");
        CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);

        // INFO(Rafael): An init must be always sucessfully done.
        snprintf(bcmd, sizeof(bcmd) - 1, *rp, get_test_protlayer(0, 3));
        CUTE_ASSERT(blackcat(bcmd, "Monster\nMonster", "InTheParasol\nInTheParasol") == 0);

        // INFO(Rafael): From now on all authenticated operation in this repo must require the
        //               tokens passing, besides their correct sequence during init. Thus...

        // INFO(Rafael): ...a status without passing the tokens must fail.
        CUTE_ASSERT(blackcat("status", "Monster", "InTheParasol") != 0);

        // INFO(Rafael): ...a status with a wrong token passing must fail.
        CUTE_ASSERT(blackcat("status * --soft-token=tokens/b.dat,tokens/a.dat,tokens/c.dat",
                             "Monster", "InTheParasol") != 0);

        // INFO(Rafael): ...wrong passwords even with right tokens will fail.
        CUTE_ASSERT(blackcat("status * --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
                             "Monster", "InTheParasoL") != 0);

        CUTE_ASSERT(blackcat("add --soft-token=tokens/a.dat,tokens/c.dat,tokens/b.dat s1.txt --lock",
                             "Monster", "InTheParasun") != 0);

        CUTE_ASSERT(blackcat("add --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat s1.txt --lock",
                             "Monster", "InTheParasol") == 0);

        data = get_file_data("s1.txt", &data_size);

        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
        kryptos_freeseg(data, data_size);

        // INFO(Rafael): ...a status with a correct token passing must be successfully done.
        CUTE_ASSERT(blackcat("status * --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
                             "Monster", "InTheParasol") == 0);

        CUTE_ASSERT(blackcat("unlock s1.txt", "Monster", "InTheParasol") != 0);

        if (strstr(*rp, "--keyed-alike") == NULL) {
            CUTE_ASSERT(blackcat("unlock s1.txt --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
                                 "Monster", "InParasol") != 0);
        }

        CUTE_ASSERT(blackcat("unlock s1.txt --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
                             "Monster", "InTheParasol") == 0);

        data = get_file_data("s1.txt", &data_size);

        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(sensitive1));
        CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("lock s1.txt --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
                             "Monster", "InTheParasol") == 0);

        data = get_file_data("s1.txt", &data_size);

        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
        kryptos_freeseg(data, data_size);

        // INFO(Rafael): Now let's execute a setkey with new tokens.

        snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                         "--protection-layer=%s "
                                         "--new-soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat ", get_test_protlayer(0, 2));

        // INFO(Rafael): Without the current tokens it will fail.
        CUTE_ASSERT(blackcat(bcmd, "Monster", "InTheParasol") != 0);

        CUTE_ASSERT(blackcat("token tokens/d.dat tokens/e.dat tokens/f.dat --bytes=20 --overwrite", "", NULL) == 0);

        if (strstr(*rp, "--key-hash=bcrypt") == NULL) {
            snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                             "--soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat "
                                             "--protection-layer=%s "
                                             "--new-soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat ", get_test_protlayer(0,
                                                                                                                            2));
        } else {
            snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                             "--bcrypt-cost=10 "
                                             "--soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat "
                                             "--protection-layer=%s "
                                             "--new-soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat ", get_test_protlayer(0,
                                                                                                                            2));
        }

        // INFO(Rafael): With wrong password must fail.
        CUTE_ASSERT(blackcat(bcmd, "M0nster", "InTheParasol") != 0);

        if (strstr(*rp, "--keyed-alike") == NULL) {
            CUTE_ASSERT(blackcat(bcmd, "Monster\nInTheParasol",
                                       "MellowshipSlinky\nMellowshipSlinky\nInBMajor\nInBMajor") == 0);
        } else {
            CUTE_ASSERT(blackcat(bcmd, "Monster",
                                       "MellowshipSlinky\nMellowshipSlinky\nInBMajor\nInBMajor") == 0);
        }

        // INFO(Rafael): Now with old tokens must fail.
        CUTE_ASSERT(blackcat("unlock s1.txt --soft-token=tokens/a.dat,tokens/b.dat,tokens/c.dat",
                             "MellowshipSlinky", "InBMajor") != 0);

        CUTE_ASSERT(blackcat("unlock s1.txt --soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat",
                             "MellowshipSlinky", "InBMajor") == 0);

        data = get_file_data("s1.txt", &data_size);

        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(sensitive1));
        CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("lock s1.txt --soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat",
                             "MellowshipSlinky", "InBMajor") == 0);

        // INFO(Rafael): Now let's stop using soft-tokens.

        if (strstr(*rp, "--key-hash=bcrypt") == NULL) {
            snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                             "--soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat "
                                             "--protection-layer=%s ", get_test_protlayer(0, 2));
        } else {
            snprintf(bcmd, sizeof(bcmd) - 1, "setkey "
                                             "--bcrypt-cost=10 "
                                             "--soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat "
                                             "--protection-layer=%s ", get_test_protlayer(0, 2));
        }

        CUTE_ASSERT(blackcat(bcmd, "MellowshipSlinky\nInBMajor",
                                   "MellowshipSlinky\nMellowshipSlinky\nInBMajor\nInBMajor") == 0);


        // INFO(Rafael): Since we are not using tokens anymore it must fail.

        CUTE_ASSERT(blackcat("unlock s1.txt --soft-token=tokens/d.dat,tokens/e.dat,tokens/f.dat",
                             "MellowshipSlinky", "InBMajor") != 0);

        // INFO(Rafael): It must be done.

        CUTE_ASSERT(blackcat("unlock s1.txt", "MellowshipSlinky", "InBMajor") == 0);

        data = get_file_data("s1.txt", &data_size);

        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(sensitive1));
        CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
        kryptos_freeseg(data, data_size);

        // INFO(Rafael): ...deinit also must require tokens.
        CUTE_ASSERT(blackcat("deinit --soft-token=tokens/b.dat,tokens/c.dat,tokens/a.dat",
                             "MellowshipSlinky", "InBMajor") != 0);

        CUTE_ASSERT(blackcat("deinit", "MellowshipSlinky", "InBMajor") == 0);
        rp++;
    }

    CUTE_ASSERT(remove("s1.txt") == 0);
    CUTE_ASSERT(remove("tokens/a.dat") == 0);
    CUTE_ASSERT(remove("tokens/b.dat") == 0);
    CUTE_ASSERT(remove("tokens/c.dat") == 0);
    CUTE_ASSERT(remove("tokens/d.dat") == 0);
    CUTE_ASSERT(remove("tokens/e.dat") == 0);
    CUTE_ASSERT(remove("tokens/f.dat") == 0);
    CUTE_ASSERT(rmdir("tokens") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poke_token_cmd_tests)
    unsigned char *data;
    size_t data_size;
    CUTE_ASSERT(blackcat("token a.token b.token c.token --bytes=10", "", NULL) == 0);

    data = get_file_data("a.token", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 10);
    kryptos_freeseg(data, data_size);

    data = get_file_data("b.token", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 10);
    kryptos_freeseg(data, data_size);

    data = get_file_data("c.token", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 10);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("token a.token b.token c.token --bytes=100", "", NULL) != 0);
    CUTE_ASSERT(blackcat("token a.token b.token c.token --bytes=101 --overwrite", "", NULL) == 0);

    data = get_file_data("a.token", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 101);
    kryptos_freeseg(data, data_size);

    data = get_file_data("b.token", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 101);
    kryptos_freeseg(data, data_size);

    data = get_file_data("c.token", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == 101);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(remove("a.token") == 0);
    CUTE_ASSERT(remove("b.token") == 0);
    CUTE_ASSERT(remove("c.token") == 0);
CUTE_TEST_CASE_END

static int has_tcpdump(void) {
    return (system("tcpdump --version 2>/dev/null") == 0);
}

CUTE_TEST_CASE(blackcat_dev_tests)
#if !defined(_WIN32)
    unsigned char *sensitive1 = "[1] The wrath sing, goddess, of Peleus' son, Achilles, that destructive wrath which brought "
                       "countless woes upon the Achaeans, and sent forth to Hades many valiant souls of heroes, and "
                       "made them themselves spoil for dogs and every bird; thus the plan of Zeus came to fulfillment, "
                       "[5] from the time when first they parted in strife Atreus' son, king of men, and brilliant Achilles. "
                       "Who then of the gods was it that brought these two together to contend? The son of Leto and Zeus; for "
                       "he in anger against the king roused throughout the host an evil pestilence, and the people began to "
                       "perish, [10] because upon the priest Chryses the son of Atreus had wrought dishonour. For he had come "
                       "to the swift ships of the Achaeans to free his daughter, bearing ransom past counting; and in his "
                       "hands he held the wreaths of Apollo who strikes from afar,2 on a staff of gold; and he implored all "
                       "the Achaeans, [15] but most of all the two sons of Atreus, the marshallers of the people: 'Sons of "
                       "Atreus, and other well-greaved Achaeans, to you may the gods who have homes upon Olympus grant that "
                       "you sack the city of Priam, and return safe to your homes; but my dear child release to me, and "
                       "accept the ransom [20] out of reverence for the son of Zeus, Apollo who strikes from afar.' "
                       "Then all the rest of the Achaeans shouted assent, to reverence the priest and accept the glorious "
                       "ransom, yet the thing did not please the heart of Agamemnon, son of Atreus, but he sent him away "
                       "harshly, and laid upon him a stern command: [25] 'Let me not find you, old man, by the hollow ships, "
                       "either tarrying now or coming back later, lest your staff and the wreath of the god not protect you. "
                       "Her I will not set free. Sooner shall old age come upon her in our house, in Argos, far from her "
                       "native land, [30] as she walks to and fro before the loom and serves my bed. But go, do not anger me, "
                       "that you may return the safer.'";
    unsigned char *sensitive2 = "'Is that vodka?' Margarita asked weakly.\n"
                       "The cat jumped up in his seat with indignation.\n"
                       "'I beg pardon, my queen,' he rasped, 'Would I "
                       "ever allow myself to offer vodka to a lady? This is pure alcohol!'\n\n"
                       "The tongue may hide the truth but the eyes - never!\n\n"
                       "Cowardice is the most terrible of vices.\n\n"
                       "'You're not Dostoevsky,' said the citizeness, who was getting muddled by Koroviev. "
                       "Well, who knows, who knows,' he replied. 'Dostoevsky's dead,' said the citizeness, "
                       "but somehow not very confidently. 'I protest!' Behemoth exclaimed hotly. 'Dostoevsky is immortal!\n\n"
                       "manuscripts don't burn\n\n";
    // For all those kind of boring & pedantic people reading this piece of code, "p" comes from "p"arangaricutirimirruaru
    // not from "p"lain...
    unsigned char *p = "README\n"; 
    unsigned char *data;
    size_t data_size;
    int fd;
    char bcmd[65535], *protlayer;

    if (CUTE_GET_OPTION("no-dev") == NULL && CUTE_GET_OPTION("blackcat-dev-tests")) {

#if !defined(__NetBSD__)
        if ((fd = open("/dev/blackcat", O_RDONLY)) > -1) {
            close(fd);
            printf("== Test skipped. You can run device tests once before rebooting your system.\n");
            return 0;
        }
#else
        printf("WARN: You can run device tests once before rebooting.\n"
               "      Subsequent runnings will fail.\n");
#endif

        // INFO(Rafael): Module loading tests.

#if defined(__linux__)
        CUTE_ASSERT(blackcat("lkm --load ../../dev/blackcat.ko", "", NULL) == 0);
#elif defined(__FreeBSD__)
        CUTE_ASSERT(blackcat("lkm --load ../../dev/blackcat.ko", "", NULL) == 0);
#elif defined(__NetBSD__)
        CUTE_ASSERT(blackcat("lkm --load ../../dev/blackcat.kmod", "", NULL) == 0);
#endif

        // INFO(Rafael): Checking if the module hiding is okay.

        CUTE_ASSERT(check_blackcat_lkm_hiding() != 0);

        // INFO(Rafael): Even being hidden, let's check if is impossible to unload this.

        CUTE_ASSERT(try_unload_blackcat_lkm() != 0);

        test_env_housekeeping();

        protlayer = get_test_protlayer(0, 5);

        CUTE_ASSERT(protlayer != NULL);

        snprintf(bcmd, sizeof(bcmd) - 1, "init "
                                         "--catalog-hash=sha3-384 "
                                         "--key-hash=tiger "
                                         "--protection-layer-hash=sha-512 "
                                         "--protection-layer=%s", protlayer);

        CUTE_ASSERT(blackcat(bcmd,
                             "Or19Well84\nOr19Well84", "LeGuin\nLeGuin") == 0);

        CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
        CUTE_ASSERT(create_file("s2.txt", sensitive2, strlen(sensitive2)) == 1);
        CUTE_ASSERT(create_file("p.txt", p, strlen(p)) == 1);

        // INFO(Rafael): Testing the tasks bury and dig-up from paranoid sub-command.

        CUTE_ASSERT(blackcat("paranoid --bury s1.txt", "", NULL) != 0);

        CUTE_ASSERT(blackcat("paranoid --bury s1.txt", "Or19Well84", NULL) != 0);

        CUTE_ASSERT(file_is_hidden("s1.txt") == 0);
        CUTE_ASSERT(file_is_hidden("s2.txt") == 0);
        CUTE_ASSERT(file_is_hidden("p.txt") == 0);

        CUTE_ASSERT(blackcat("add s1.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("add p.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("add s2.txt", "Or19Well84", "LeGuin") == 0);

        CUTE_ASSERT(blackcat("paranoid --bury s1.txt", "Or19Well84", NULL) == 0);

        CUTE_ASSERT(file_is_hidden("s1.txt") == 1);
        CUTE_ASSERT(file_is_hidden("s2.txt") == 0);
        CUTE_ASSERT(file_is_hidden("p.txt") == 0);

        CUTE_ASSERT(blackcat("lock", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("unlock", "Or19Well84", "LeGuin") == 0);

        CUTE_ASSERT(blackcat("lock s1.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s1.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("lock s2.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s2.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("lock p.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("p.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, p, strlen(p)) != 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("unlock s1.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s1.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(sensitive1));
        CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("unlock s2.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s2.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(sensitive2));
        CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("unlock p.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("p.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(p));
        CUTE_ASSERT(memcmp(data, p, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("rm s1.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("rm s2.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("rm p.txt", "Or19Well84", "LeGuin") == 0);

        CUTE_ASSERT(blackcat("add s1.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("add p.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("add s2.txt", "Or19Well84", "LeGuin") == 0);

        CUTE_ASSERT(blackcat("paranoid --dig-up s1.txt", "", NULL) != 0);

        CUTE_ASSERT(blackcat("paranoid --dig-up s1.txt", "Or19Well84", NULL) == 0);

        CUTE_ASSERT(file_is_hidden("s1.txt") == 0);
        CUTE_ASSERT(file_is_hidden("s2.txt") == 0);
        CUTE_ASSERT(file_is_hidden("p.txt") == 0);

        CUTE_ASSERT(blackcat("paranoid --bury", "Or19Well84", NULL) == 0);

        CUTE_ASSERT(file_is_hidden("s1.txt") == 1);
        CUTE_ASSERT(file_is_hidden("s2.txt") == 1);
        CUTE_ASSERT(file_is_hidden("p.txt") == 1);

        CUTE_ASSERT(blackcat("paranoid --dig-up", "Or19Well84", NULL) == 0);

        CUTE_ASSERT(file_is_hidden("s1.txt") == 0);
        CUTE_ASSERT(file_is_hidden("s2.txt") == 0);
        CUTE_ASSERT(file_is_hidden("p.txt") == 0);

        // INFO(Rafael): Now verifying the entire repo burying and digging up.

        CUTE_ASSERT(blackcat("paranoid --bury-repo", "Rainbirds", NULL) != 0);

        CUTE_ASSERT(blackcat("paranoid --bury-repo", "Or19Well84", NULL) == 0);

        CUTE_ASSERT(file_is_hidden("../test") == 1);

        // INFO(Rafael): Checking basic file operations under this condition.

        CUTE_ASSERT(blackcat("lock", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("unlock", "Or19Well84", "LeGuin") == 0);

        CUTE_ASSERT(blackcat("lock s1.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s1.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, sensitive1, strlen(sensitive1)) != 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("lock s2.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s2.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, sensitive2, strlen(sensitive2)) != 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("lock p.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("p.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(memcmp(data, p, strlen(p)) != 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("unlock s1.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s1.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(sensitive1));
        CUTE_ASSERT(memcmp(data, sensitive1, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("unlock s2.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("s2.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(sensitive2));
        CUTE_ASSERT(memcmp(data, sensitive2, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("unlock p.txt", "Or19Well84", "LeGuin") == 0);

        data = get_file_data("p.txt", &data_size);
        CUTE_ASSERT(data != NULL);
        CUTE_ASSERT(data_size == strlen(p));
        CUTE_ASSERT(memcmp(data, p, data_size) == 0);
        kryptos_freeseg(data, data_size);

        CUTE_ASSERT(blackcat("rm s1.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("rm s2.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("rm p.txt", "Or19Well84", "LeGuin") == 0);

        CUTE_ASSERT(blackcat("add s1.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("add p.txt", "Or19Well84", "LeGuin") == 0);
        CUTE_ASSERT(blackcat("add s2.txt", "Or19Well84", "LeGuin") == 0);

        CUTE_ASSERT(blackcat("paranoid --dig-up-repo", "Metropolis", NULL) != 0);

        CUTE_ASSERT(blackcat("paranoid --dig-up-repo", "Or19Well84", NULL) == 0);

        CUTE_ASSERT(file_is_hidden("../test") == 0);

        // INFO(Rafael): Disable and enable history.

        CUTE_ASSERT(blackcat("paranoid --disable-history", "", "") == 0);

        CUTE_ASSERT(blackcat("paranoid --enable-history", "", "") == 0);

        // INFO(Rafael): Find hooks test.

        CUTE_ASSERT(blackcat("paranoid --find-hooks", "sjdasjd", NULL) != 0);

        CUTE_ASSERT(blackcat("paranoid --find-hooks", "Or19Well84", NULL) == 0);

# if defined(__FreeBSD__) || defined(__NetBSD__)

        // INFO(Rafael): Hook read and write (exit code != 0).

        CUTE_ASSERT(syshook() == 0);

        CUTE_ASSERT(blackcat("paranoid --find-hooks", "Or19Well84", NULL) != 0);

        CUTE_ASSERT(clear_syshook() == 0);

        CUTE_ASSERT(blackcat("paranoid --find-hooks", "Or19Well84", NULL) == 0);

# endif

        CUTE_ASSERT(blackcat("deinit", "Or19Well84", NULL) == 0);

        remove("s1.txt");
        remove("s2.txt");
        remove("p.txt");
    } else {
        printf("== Test skipped.\n");
    }
#else
    printf("== No support.\n");
#endif
CUTE_TEST_CASE_END

static int create_file(const char *filepath, const unsigned char *data, const size_t data_size) {
    FILE *fp;

    fp = fopen(filepath, "wb");

    if (fp == NULL) {
        return 0;
    }

    fwrite(data, 1, data_size, fp);

    fclose(fp);

    return 1;
}

static int blackcat(const char *command, const unsigned char *p1, const unsigned char *p2) {
    char bin[4096];
    char cmdline[4096];
    int exit_code;
    struct stat st;

    if (p1 == NULL) {
        return 0;
    }

#if defined(__unix__)
    strncpy(cmdline, "../", sizeof(cmdline) - 1);
    snprintf(bin, sizeof(bin) - 1, "%sbin/blackcat", cmdline);
#elif defined(_WIN32)
    strncpy(cmdline, "..\\", sizeof(cmdline) - 1);
    snprintf(bin, sizeof(bin) - 1, "%sbin\\blackcat.exe", cmdline);
#else
# error Some code wanted.
#endif

#if defined(__unix__)
    while (stat(bin, &st) != 0) {
        strncat(cmdline, "../", sizeof(cmdline) - 1);
        snprintf(bin, sizeof(bin) - 1, "%sbin/blackcat", cmdline);
    }
#elif defined(_WIN32)
    while (stat(bin, &st) != 0) {
        strncat(cmdline, "..\\", sizeof(cmdline) - 1);
        snprintf(bin, sizeof(bin) - 1, "%sbin\\blackcat.exe", cmdline);
    }
#else
# error Some code wanted.
#endif

    snprintf(cmdline, sizeof(cmdline) - 1, "%s\n", p1);

    if (p2 != NULL) {
        strncat(cmdline, p2, sizeof(cmdline) - 1);
        strncat(cmdline, "\n", sizeof(cmdline) - 1);
    }

    if (create_file(".bcpass", cmdline, strlen(cmdline)) == 0) {
        return 0;
    }

    snprintf(cmdline, sizeof(cmdline) - 1, "%s %s < .bcpass", bin, command);

    exit_code = system(cmdline);

    remove(".bcpass");

    return exit_code;
}

static int blackcat_nowait(const char *command, const unsigned char *p1, const unsigned char *p2) {
    char bin[4096];
    char cmdline[4096];
    int exit_code;
    struct stat st;

    if (p1 == NULL) {
        return 0;
    }

#if defined(__unix__)
    strncpy(cmdline, "../", sizeof(cmdline) - 1);
    snprintf(bin, sizeof(bin) - 1, "%sbin/blackcat", cmdline);
#elif defined(_WIN32)
    strncpy(cmdline, "..\\", sizeof(cmdline) - 1);
    snprintf(bin, sizeof(bin) - 1, "%sbin\\blackcat.exe", cmdline);
#else
# error Some code wanted.
#endif

#if defined(__unix__)
    while (stat(bin, &st) != 0) {
        strncat(cmdline, "../", sizeof(cmdline) - 1);
        snprintf(bin, sizeof(bin) - 1, "%sbin/blackcat", cmdline);
    }
#elif defined(_WIN32)
    while (stat(bin, &st) != 0) {
        strncat(cmdline, "..\\", sizeof(cmdline) - 1);
        snprintf(bin, sizeof(bin) - 1, "%sbin\\blackcat.exe", cmdline);
    }
#else
# error Some code wanted.
#endif

    snprintf(cmdline, sizeof(cmdline) - 1, "%s\n", p1);

    if (p2 != NULL) {
        strncat(cmdline, p2, sizeof(cmdline) - 1);
        strncat(cmdline, "\n", sizeof(cmdline) - 1);
    }

    if (create_file(".bcpass", cmdline, strlen(cmdline)) == 0) {
        return 0;
    }

    snprintf(cmdline, sizeof(cmdline) - 1, "%s %s < .bcpass &", bin, command);

    exit_code = system(cmdline);

    sleep(1);

    remove(".bcpass");

    return exit_code;
}

unsigned char *get_file_data(const char *filepath, size_t *data_size) {
    FILE *fp;
    unsigned char *data;

    if (data_size == NULL) {
        return NULL;
    }

    *data_size = 0;

    fp = fopen(filepath, "rb");

    if (fp == NULL) {
        return NULL;
    }

    fseek(fp, 0L, SEEK_END);
    *data_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    data = kryptos_newseg(*data_size + 1);

    if (data == NULL) {
        return NULL;
    }

    memset(data, 0, *data_size + 1);
    fread(data, 1, *data_size, fp);

    fclose(fp);

    return data;
}

static int check_blackcat_lkm_hiding(void) {
    int found = 1;
#if defined(__linux__) || defined(__NetBSD__)
# if defined(__linux__)
    FILE *fp = popen("lsmod | grep blackcat", "r");
# else
    FILE *fp = popen("modstat | grep blackcat", "r");
#endif
    char b;

    if (fp == NULL) {
        printf("PANIC: Unable to access pipe.\n");
        return 1;
    }

    found = fread(&b, 1, sizeof(b), fp) > 0;

    pclose(fp);

    return found == 0;
#elif defined(__FreeBSD__)
    return kldfind("blackcat.kld") == -1;
#endif
}

static int try_unload_blackcat_lkm(void) {
    char *cmdline =
#if defined(__linux__)
        "rmmod blackcat";
#elif defined(__FreeBSD__)
        "kldunload blackcat.ko";
#elif defined(__NetBSD__)
        "modunload blackcat.kmod";
#else
        "(null)";
#endif
    return system(cmdline);
}

static int file_is_hidden(const char *filepath) {
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__)
    int is_hidden;
    char cmdline[4096];
    FILE *fp = NULL;
    char b;

    if (filepath == NULL) {
        return 0;
    }

    snprintf(cmdline, sizeof(cmdline) - 1, "ls %s", filepath);

    if ((fp = popen(cmdline, "r")) == NULL) {
        printf("PANIC: Unable to access pipe.\n");
        return 0;
    }

    is_hidden = (fread(&b, 1, sizeof(b), fp) == 0);

    pclose(fp);

    return is_hidden;
#else
    return 0;
#endif
}

static int test_env_housekeeping(void) {
    blackcat("deinit", "GiveTheMuleWhatHeWants", NULL);
    blackcat("deinit", "IThinkILostMyHeadache", NULL);
    blackcat("deinit", "PaperScratcher", NULL);
    blackcat("deinit", "StoneFree", NULL);
    blackcat("deinit", "All Along The Watchtower", NULL);
    blackcat("deinit", "Stang's Swang", NULL);
    blackcat("deinit", "Gardenia", NULL);
    blackcat("deinit", "Or19Well84", NULL);
    remove("etc/s2.txt");
    rmdir("etc");
    remove("s1.txt");
    remove("s2.txt");
    remove("s3.txt");
    remove("p.txt");
    remove("unpack-test/bpack/etc/s2.txt");
    remove("unpack-test/bpack/s1.txt");
    remove("unpack-test/bpack/p.txt");
    rmdir("unpack-test/bpack/etc");
    rmdir("unpack-test/bpack");
    rmdir("unpack-test");
    remove("test.bpack");
    return 0;
}

static int syshook(void) {
#if defined(__linux__)
    return system("insmod hdev/hook.ko");
#elif defined(__FreeBSD__)
    return system("kldload hdev/hook.ko");
#elif defined(__NetBSD__)
    return system("modload hdev/hook.kmod");
#else
    return 1;
#endif
}

static int clear_syshook(void) {
#if defined(__linux__)
    return system("rmmod hook");
#elif defined(__FreeBSD__)
    return system("kldunload hook");
#elif defined(__NetBSD__)
    return system("modunload hook");
#else
    return 1;
#endif
}
