/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <cmd/options.h>
#include <cmd/version.h>
#include <cmd/levenshtein_distance.h>
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

// INFO(Rafael): The test case 'blackcat_clear_option_tests' needs the following options
//               out from the .rodata otherwise it would cause an abnormal program termination.

static char path[] = "";
static char cmd[] = "meow";
static char arg2[] = "--foo=bar";
static char arg3[] = "--bar=foo";
static char arg4[] = "--bool";

static char *argv[] = {
    path,
    cmd,
    arg2,
    arg3,
    arg4
};

static int argc = sizeof(argv) / sizeof(argv[0]);

CUTE_DECLARE_TEST_CASE(blackcat_cmd_tests_entry);

CUTE_DECLARE_TEST_CASE(blackcat_set_argc_argv_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_command_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_option_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_bool_option_tests);
CUTE_DECLARE_TEST_CASE(blackcat_get_argv_tests);
CUTE_DECLARE_TEST_CASE(get_blackcat_version_tests);
CUTE_DECLARE_TEST_CASE(blackcat_clear_options_tests);
CUTE_DECLARE_TEST_CASE(blackcat_poking_tests);
CUTE_DECLARE_TEST_CASE(levenshtein_distance_tests);
CUTE_DECLARE_TEST_CASE(blackcat_dev_tests);

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
    // INFO(Rafael): If all is okay, time to poke this shit.
    CUTE_RUN_TEST(blackcat_poking_tests);
    CUTE_RUN_TEST(blackcat_dev_tests);
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
    CUTE_ASSERT(strcmp(get_blackcat_version(), "1.0.0") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_clear_options_tests)
    int a;

    blackcat_clear_options();

    for (a = 0; a < argc; a++) {
        CUTE_ASSERT(strlen(argv[a]) == 0);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_poking_tests)
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
    unsigned char *sensitive3 = "Tears from the sky, in pools of pain... Tonight, I gonna go and dancing in the rain.\n";
    unsigned char *plain = "README\n";
    unsigned char *data;
    size_t data_size;
    unsigned char *k1, *k2;
    FILE *fp;
    char cwd[4096];
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
    char cmdline[4096];

    // INFO(Rafael): Just housekeeping.

    test_env_housekeeping();

    // INFO(Rafael): Wrong commands.

    CUTE_ASSERT(blackcat("shew", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("self", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("adds", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("rms", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("state", "----", NULL) != 0);
    CUTE_ASSERT(blackcat("rinite", "---", NULL) != 0);

    // INFO(Rafael): Showing the available ciphers, HMACs and hashes.

    CUTE_ASSERT(blackcat("show your-hands", "---", NULL) != 0);
    CUTE_ASSERT(blackcat("show ciphers", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show hmacs", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show hashes", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show encoders", "---", NULL) == 0);
    CUTE_ASSERT(blackcat("show hashes hmacs ciphers encoders", "---", NULL) == 0);

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
    CUTE_ASSERT(blackcat("help paranoid", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help lkm", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help setkey", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help undo", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help decoy", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help info", "", NULL) == 0);
    CUTE_ASSERT(blackcat("help not-implemented", "", NULL) != 0);
    CUTE_ASSERT(blackcat("help init deinit add rm status lock unlock show boo help pack unpack paranoid lkm setkey undo decoy info", "", NULL) != 0);
    CUTE_ASSERT(blackcat("help init deinit add rm status lock unlock show help pack paranoid unpack lkm setkey undo decoy info", "", NULL) == 0);

    // INFO(Rafael): Init command general tests.
    CUTE_ASSERT(blackcat("init", "none", "none") != 0);

    // INFO(Rafael): Incomplete init.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhat?") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike "
                         "--encoder=OI''55", "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=bcrypt "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=bcrypt "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);

    // INFO(Rafael): Valid keyed alike init.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") == 0);

    // INFO(Rafael): Init again must fail.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") != 0);


    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
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

    // INFO(Rafael): Getting the current repo's status.

    CUTE_ASSERT(blackcat("status", "Ahhhhh", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status etc/*.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status p.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

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
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive3));
    kryptos_freeseg(data, data_size);

    data = get_file_data("p.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size == strlen(plain));
    CUTE_ASSERT(memcmp(data, plain, data_size) == 0);
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock p.txt", "GiveTheMuleWhatHeWants", NULL) != 0);

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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "GiveTheMuleWhatHeWants-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
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

    // INFO(Rafael): Rm test.

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "GiveTheMuleWhat?", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
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

    // INFO(Rafael): Pack stuff.

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("pack", "GiveTheMuleWhatHeWants", NULL) != 0);

    CUTE_ASSERT(blackcat("pack test.bpack", "GIVETheMuleWhatHeWants", NULL) != 0);

    CUTE_ASSERT(blackcat("pack test.bpack", "GiveTheMuleWhatHeWants", NULL) == 0);

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

    // INFO(Rafael): Setkey stuff.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike", "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") == 0);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "All Along The Watchtower", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "All Along The Watchtower", NULL) == 0);

    // INFO(Rafael): Setting other parameters besides the keys.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "GiveTheMuleWhatHeWants", "GiveTheMuleWhatHeWants") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "GiveTheMuleWhatHeWants", NULL) == 0);
    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) == 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=sha12 "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencoder "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=whirlpool "
                         "--key-hash=cha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencoder "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tig3r "
                         "--encoder=uuencoder "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=yyencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=carmellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=bcrypt "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=bcrypt "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") != 0);

    CUTE_ASSERT(blackcat("setkey --keyed-alike "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "GiveTheMuleWhatHeWants\nAll Along The Watchtower\nAll Along The Watchtower", "") == 0);

    CUTE_ASSERT(blackcat("status", "GiveTheMuleWhatHeWants", NULL) != 0);
    CUTE_ASSERT(blackcat("status", "All Along The Watchtower", NULL) == 0);

    CUTE_ASSERT(blackcat("deinit", "All Along The Watchtower", NULL) == 0);

    // INFO(Rafael): Invalid keyed twice init with invalid key confirmations.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
                         "IThinkILostMyHeadache\nIThinkILOstMyHeadache", "UntilMyHeadacheGoes\nUntilMyHeadacheGoes") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
                         "IThinkILostMyHeadache\nIThinkILostMyHeadache", "UntilMyHeadacheGoe5\nUntilMyHeadacheGoes") != 0);

    // INFO(Rafael): Valid keyed twice init.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "IThinkILostMyHeadache", "UntilMyHeadcheGoes") == 0);

    CUTE_ASSERT(blackcat("unlock", "IThinkILostMyHeadache", "GiveTheMuleWhatHeWants-") != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "IThinkILostMyHeadache", "GiveTheMuleWhat?") != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
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

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike "
                         "--encoder=base64", "PaperScratcher", "PaperScratcher") == 0);

    // INFO(Rafael): Init again must fail.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike "
                         "--encoder=base64", "PaperScratcher", "PaperScratcher") != 0);


    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "PaperScratcher", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock --no-swap", "PaperScratcher-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "PaperWhat?", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
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

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike "
                         "--encoder=uuencode", "StoneFree", "StoneFree") == 0);

    // INFO(Rafael): Init again must fail.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike "
                         "--encoder=uuencode", "StoneFree", "StoneFree") != 0);


    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(mkdir("etc", 0666) == 0);
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("status", "StoneFree", NULL) == 0);

    CUTE_ASSERT(blackcat("unlock", "StoneFree-", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
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
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("rm s1.txt", "StoneTree", NULL) != 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
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
    CUTE_ASSERT(data_size != strlen(sensitive2));
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

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
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

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
                         "Stang's Swang\nStang's Swang", "Rock-N-Roll'e\nRock-N-Roll'e") == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(blackcat("add s1.txt", "Stang's Swang", NULL) == 0);
    CUTE_ASSERT(blackcat("add etc/s2.txt", "Stang's Swang", NULL) == 0);

    CUTE_ASSERT(blackcat("lock", "Stang's Swang", "Rock-N-Roll'e") == 0);
    CUTE_ASSERT(blackcat("status", "Stang's Swang", NULL) == 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=sha12 "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencoder "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-aes-256-cbc",
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=cha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencoder "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-aes-256-cbc",
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tig3r "
                         "--encoder=uuencoder "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-aes-256-cbc",
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=yyencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=carmellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "Stang's Suang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "Stang's Swang\nRock-iN-Roll'e", "Gardenia\nGardenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nArdenia\nKylie\nKylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
                         "Stang's Swang\nRock-N-Roll'e", "Gardenia\nGardenia\nKylie\nKrylie") != 0);

    CUTE_ASSERT(blackcat("setkey "
                         "--catalog-hash=whirlpool "
                         "--key-hash=sha-512 "
                         "--protection-layer-hash=tiger "
                         "--encoder=uuencode "
                         "--protection-layer=camellia-192-cbc,mars-192-cbc,misty1-ctr,hmac-sha3-512-aes-256-cbc",
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

    // INFO(Rafael): undo test.

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=whirlpool "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
                         "Talking head\nTalking head", "Who knows\nWho knows") == 0);

    CUTE_ASSERT(mkdir("etc", 0666) == 0);
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

    remove("etc/s2.txt");
    remove("s1.txt");
    remove("p.txt");

    CUTE_ASSERT(blackcat("decoy etc/s2.txt s1.txt --encoder=base64 --overwrite", "", NULL) != 0);
    CUTE_ASSERT(blackcat("decoy etc/s2.txt s1.txt --fsize=8192 --encoder=base64", "", NULL) == 0);
    CUTE_ASSERT(blackcat("decoy etc/s2.txt s1.txt --fsize=8192 --encoder=uuencode", "", NULL) != 0);
    CUTE_ASSERT(blackcat("decoy etc/s2.txt s1.txt --fsize=8192 --encoder=uuencode --overwrite", "", NULL) == 0);
    CUTE_ASSERT(blackcat("decoy p.txt --fsize=8192", "", NULL) == 0);

    remove("s1.txt");
    remove("etc/s2.txt");
    rmdir("etc");
    remove("p.txt");

    // INFO(Rafael): For people who like bcrypt with love (keyed alike init first, ok?).

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "HazeJaneII", "HazeJaneII") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--bcrypt-cost=101 "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "HazeJaneII", "HazeJaneII") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--bcrypt-cost=6 "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "HazeJaneII"
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
    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--bcrypt-cost=6 "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike", "HazeJaneII", "HazeJaneII") == 0);

    CUTE_ASSERT(mkdir("etc", 0666) == 0);

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
    CUTE_ASSERT(data_size != strlen(sensitive3));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "HazeJaneII", NULL) == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive3));
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

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
                         "HazeJaneII\nHazeJaneII", "IPutASpellOnYou\nIPutASpellOnYou") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--bcrypt-cost=82 "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
                         "HazeJaneII\nHazeJaneII", "OhWee!\nOhWee!") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--bcrypt-cost=6 "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
                         "HazeJaneII\nHazeJaneII", "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone\n"
                                                   "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone"
                                                   "YouNeverCallMyNameOnTheTelephone") != 0);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=bcrypt "
                         "--bcrypt-cost=8 "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc ",
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
    CUTE_ASSERT(data_size != strlen(sensitive3));
    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(blackcat("lock", "HazeJaneII", "NoUoniQuinousJeguere") != 0);

    CUTE_ASSERT(blackcat("lock", "HazeJaneII", "NoOneKnows") == 0);

    data = get_file_data("s1.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive1));
    kryptos_freeseg(data, data_size);

    data = get_file_data("etc/s2.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive2));
    kryptos_freeseg(data, data_size);

    data = get_file_data("s3.txt", &data_size);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(data_size != strlen(sensitive3));
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

    // INFO(Rafael): Repo detaching & attaching tests.

    CUTE_ASSERT(blackcat("detach --dest=metainfo.yyz", "", NULL) != 0);

    CUTE_ASSERT(mkdir("etc", 0666) == 0);

    CUTE_ASSERT(create_file("s1.txt", sensitive1, strlen(sensitive1)) == 1);
    CUTE_ASSERT(create_file("etc/s2.txt", sensitive2, strlen(sensitive2)) == 1);
    CUTE_ASSERT(create_file("p.txt", plain, strlen(plain)) == 1);
    CUTE_ASSERT(create_file("s3.txt", sensitive3, strlen(sensitive3)) == 1);

    CUTE_ASSERT(blackcat("init "
                         "--catalog-hash=sha3-384 "
                         "--key-hash=tiger "
                         "--protection-layer-hash=sha-512 "
                         "--protection-layer=aes-128-cbc "
                         "--keyed-alike",
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

#if !defined(SKIP_NET_TESTS)

    remove("ntool-test.db");
    remove("ntool.log");
    CUTE_ASSERT(blackcat("net --add-rule --rule=ntool-rule --type=socket --hash=bcrypt "
                         "--protection-layer=blowfish-ctr,aes-128-cbc --db-path=ntool-test.db", "test", "test") != 0);

    CUTE_ASSERT(blackcat("net --add-rule --rule=ntool-rule --type=socket --hash=whirlpool "
                         "--protection-layer=blowfish-ctr,aes-128-cbc --db-path=ntool-test.db", "test", "test") == 0);

    if (has_tcpdump()) {
        CUTE_ASSERT(system("tcpdump -i any -A -c 20 > ntool-traffic.log &") == 0);
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

    //INFO(Rafael): Testing the strengthened E2EE mode (with a double ratchet mechanism).

    if (has_tcpdump()) {
        CUTE_ASSERT(system("tcpdump -i any -A -c 80 > ntool-traffic.log &") == 0);
        sleep(1);
    }

    remove("ntool.server.log");
    remove("ntool.client.log");

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=104 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s write/read 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(1);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=104 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c write/read 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(1);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=105 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s send/recv 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(1);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=105 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c send/recv 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(1);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=106 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s sendto/recvfrom 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(1);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=106 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c sendto/recvfrom 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(1);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-port=107 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -s sendmsg/recvmsg 2>> ntool.server.log", "test", "abc\nabc") == 0);

    usleep(1);

    CUTE_ASSERT(blackcat_nowait("net --run --e2ee --rule=ntool-rule --xchg-addr=127.0.0.1 --xchg-port=107 "
                                "--bcsck-lib-path=../../lib/libbcsck.so --db-path=ntool-test.db "
                                "ntool/bin/ntool -c sendmsg/recvmsg 2>> ntool.client.log", "test", "abc\nabc") == 0);

    usleep(1);

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

    CUTE_ASSERT(blackcat("net --mk-dh-params --out=dh-params.txt --p-bits=160 --q-bits=32", "", NULL) == 0);

    CUTE_ASSERT(blackcat("net --mk-dh-key-pair --public-key-out=k.pub --private-key-out=k.priv --dh-params-in=dh-params.txt",
                         "", NULL) == 0);

    CUTE_ASSERT(blackcat_nowait("net --skey-xchg --server --kpub=k.pub --port=5002 --bits=32",
                                "WabbaLabbaDubDub!\nWabbaLabbaDubDub!", NULL) == 0);

    CUTE_ASSERT(blackcat_nowait("net --skey-xchg --kpriv=k.priv --port=5002 --addr=127.0.0.1 > kxchg.log", "", NULL) == 0);

    data = get_file_data("kxchg.log", &data_size);
    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(strstr(data, "INFO: The session key is 'WabbaLabbaDubDub!'.\n") != NULL);

    kryptos_freeseg(data, data_size);

    CUTE_ASSERT(remove("kxchg.log") == 0);
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

        CUTE_ASSERT(blackcat("init "
                             "--catalog-hash=sha3-384 "
                             "--key-hash=tiger "
                             "--protection-layer-hash=sha-512 "
                             "--protection-layer=aes-128-cbc,rc5-ofb/256,3des-ctr,hmac-whirlpool-noekeon-cbc,shacal2-ctr",
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

    strncpy(cmdline, "../", sizeof(cmdline) - 1);

    sprintf(bin, "%sbin/blackcat", cmdline);

    while (stat(bin, &st) != 0) {
        strcat(cmdline, "../");
        sprintf(bin, "%sbin/blackcat", cmdline);
    }

    sprintf(cmdline, "%s\n", p1);

    if (p2 != NULL) {
        strcat(cmdline, p2);
        strcat(cmdline, "\n");
    }

    if (create_file(".bcpass", cmdline, strlen(cmdline)) == 0) {
        return 0;
    }

    sprintf(cmdline, "%s %s < .bcpass", bin, command);

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

    strncpy(cmdline, "../", sizeof(cmdline) - 1);

    sprintf(bin, "%sbin/blackcat", cmdline);

    while (stat(bin, &st) != 0) {
        strcat(cmdline, "../");
        sprintf(bin, "%sbin/blackcat", cmdline);
    }

    sprintf(cmdline, "%s\n", p1);

    if (p2 != NULL) {
        strcat(cmdline, p2);
        strcat(cmdline, "\n");
    }

    if (create_file(".bcpass", cmdline, strlen(cmdline)) == 0) {
        return 0;
    }

    sprintf(cmdline, "%s %s < .bcpass &", bin, command);

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
#endif
    return system(cmdline);
}

static int file_is_hidden(const char *filepath) {
    int is_hidden;
    char cmdline[4096];
    FILE *fp = NULL;
    char b;

    if (filepath == NULL) {
        return 0;
    }

    sprintf(cmdline, "ls %s", filepath);

    if ((fp = popen(cmdline, "r")) == NULL) {
        printf("PANIC: Unable to access pipe.\n");
        return 0;
    }

    is_hidden = (fread(&b, 1, sizeof(b), fp) == 0);

    pclose(fp);

    return is_hidden;
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
