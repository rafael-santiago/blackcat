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
#include <string.h>

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

CUTE_MAIN(blackcat_cmd_tests_entry);

CUTE_TEST_CASE(blackcat_cmd_tests_entry)
    CUTE_RUN_TEST(blackcat_set_argc_argv_tests);
    CUTE_RUN_TEST(blackcat_get_command_tests);
    CUTE_RUN_TEST(blackcat_get_option_tests);
    CUTE_RUN_TEST(blackcat_get_bool_option_tests);
    CUTE_RUN_TEST(blackcat_get_argv_tests);
    CUTE_RUN_TEST(blackcat_clear_options_tests);
    CUTE_RUN_TEST(get_blackcat_version_tests);
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
    CUTE_ASSERT(strcmp(get_blackcat_version(), "0.0.1") == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_clear_options_tests)
    int a;

    blackcat_clear_options();

    for (a = 0; a < argc; a++) {
        CUTE_ASSERT(strlen(argv[a]) == 0);
    }
CUTE_TEST_CASE_END

