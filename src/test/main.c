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
#include <keychain/keychain.h>
#include <keychain/ciphering_schemes.h>
#include <string.h>

CUTE_DECLARE_TEST_CASE(blackcat_base_tests_entry);

CUTE_DECLARE_TEST_CASE(memory_tests);

CUTE_DECLARE_TEST_CASE(ctx_tests);

CUTE_DECLARE_TEST_CASE(keychain_arg_parsing_tests);

CUTE_DECLARE_TEST_CASE(blackcat_is_dec_tests);

CUTE_DECLARE_TEST_CASE(blackcat_available_cipher_schemes_tests);

CUTE_MAIN(blackcat_base_tests_entry)

CUTE_TEST_CASE(blackcat_base_tests_entry)
    CUTE_RUN_TEST(memory_tests);
    CUTE_RUN_TEST(ctx_tests);
    CUTE_RUN_TEST(keychain_arg_parsing_tests);
    CUTE_RUN_TEST(blackcat_is_dec_tests);
    CUTE_RUN_TEST(blackcat_available_cipher_schemes_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_available_cipher_schemes_tests)
    static char *huge_protchain[] = {
        "arc4", "seal/3-2012-3921", "rabbit/12234542",
        "aes-128-cbc", "aes-192-cbc", "aes-256-cbc",
        "des-cbc", "3des-cbc", "3des-ede-cbc",
        "idea-cbc",
        "rc2-cbc/123",
        "rc5-cbc/90",
        "rc6-128-cbc/20", "rc6-192-cbc/40", "rc6-256-cbc/120",
        "feal-cbc/28",
        "cast5-cbc",
        "camellia-128-cbc", "camellia-192-cbc", "camellia-256-cbc",
        "safer-k64-cbc/256",
        "blowfish-cbc",
        "serpent-cbc",
        "tea-cbc",
        "xtea-cbc/273",
        "misty1-cbc",
        "mars-128-cbc", "mars-192-cbc", "mars-256-cbc",
        "present-80-cbc", "present-128-cbc",
        "shacal1-cbc", "shacal2-cbc",
        "noekeon-cbc", "noekeon-d-cbc",
        "aes-128-ofb", "aes-192-ofb", "aes-256-ofb",
        "des-ofb", "3des-ofb", "3des-ede-ofb",
        "idea-ofb",
        "rc2-ofb/206",
        "rc5-ofb/80",
        "rc6-128-ofb/20", "rc6-192-ofb/256", "rc6-256-ofb/128",
        "feal-ofb/64",
        "cast5-ofb",
        "camellia-128-ofb", "camellia-192-ofb", "camellia-256-ofb",
        "safer-k64-ofb/263",
        "blowfish-ofb",
        "serpent-ofb",
        "tea-ofb",
        "xtea-ofb/448",
        "misty1-ofb",
        "mars-128-ofb", "mars-192-ofb", "mars-256-ofb",
        "present-80-ofb", "present-128-ofb",
        "shacal1-ofb", "shacal2-ofb",
        "noekeon-ofb", "noekeon-d-ofb",
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "des-ctr", "3des-ctr", "3des-ede-ctr",
        "idea-ctr",
        "rc2-ctr/132",
        "rc5-ctr/48",
        "rc6-128-ctr/96", "rc6-192-ctr/96", "rc6-256-ctr/96",
        "feal-ctr/178",
        "cast5-ctr",
        "camellia-128-ctr", "camellia-192-ctr", "camellia-256-ctr",
        "safer-k64-ctr/58",
        "blowfish-ctr",
        "serpent-ctr",
        "tea-ctr",
        "xtea-ctr/666",
        "misty1-ctr",
        "mars-128-ctr", "mars-192-ctr", "mars-256-ctr",
        "present-80-ctr", "present-128-ctr",
        "shacal1-ctr", "shacal2-ctr",
        "noekeon-ctr", "noekeon-d-ctr",
        "hmac-sha224-aes-128-cbc", "hmac-sha256-aes-128-cbc", "hmac-sha384-aes-128-cbc",
        "hmac-sha512-aes-128-cbc",
        "hmac-sha3-224-aes-128-cbc", "hmac-sha3-256-aes-128-cbc", "hmac-sha3-384-aes-128-cbc",
        "hmac-sha3-512-aes-128-cbc",
        "hmac-tiger-aes-128-cbc",
        "hmac-whirlpool-aes-128-cbc",
        "hmac-sha224-aes-192-cbc", "hmac-sha256-aes-192-cbc", "hmac-sha384-aes-192-cbc",
        "hmac-sha512-aes-192-cbc", "hmac-sha3-224-aes-192-cbc", "hmac-sha3-256-aes-192-cbc",
        "hmac-sha3-384-aes-192-cbc", "hmac-sha3-512-aes-192-cbc",
        "hmac-tiger-aes-192-cbc",
        "hmac-whirlpool-aes-192-cbc", "hmac-sha224-aes-256-cbc", "hmac-sha256-aes-256-cbc",
        "hmac-sha384-aes-256-cbc", "hmac-sha512-aes-256-cbc",
        "hmac-sha3-224-aes-256-cbc", "hmac-sha3-256-aes-256-cbc", "hmac-sha3-384-aes-256-cbc",
        "hmac-sha3-512-aes-256-cbc",
        "hmac-tiger-aes-256-cbc",
        "hmac-whirlpool-aes-256-cbc",
        "hmac-sha224-des-cbc", "hmac-sha256-des-cbc", "hmac-sha384-des-cbc", "hmac-sha512-des-cbc",
        "hmac-sha3-224-des-cbc", "hmac-sha3-256-des-cbc", "hmac-sha3-384-des-cbc", "hmac-sha3-512-des-cbc",
        "hmac-tiger-des-cbc",
        "hmac-whirlpool-des-cbc",
        "hmac-sha224-3des-cbc", "hmac-sha256-3des-cbc", "hmac-sha384-3des-cbc", "hmac-sha512-3des-cbc",
        "hmac-sha3-224-3des-cbc", "hmac-sha3-256-3des-cbc", "hmac-sha3-384-3des-cbc", "hmac-sha3-512-3des-cbc",
        "hmac-tiger-3des-cbc",
        "hmac-whirlpool-3des-cbc",
        "hmac-sha224-3des-ede-cbc", "hmac-sha256-3des-ede-cbc", "hmac-sha384-3des-ede-cbc", "hmac-sha512-3des-ede-cbc",
        "hmac-sha3-224-3des-ede-cbc", "hmac-sha3-256-3des-ede-cbc", "hmac-sha3-384-3des-ede-cbc", "hmac-sha3-512-3des-ede-cbc",
        "hmac-tiger-3des-ede-cbc",
        "hmac-whirlpool-3des-ede-cbc",
        "hmac-sha224-idea-cbc",
        "hmac-sha256-idea-cbc", "hmac-sha384-idea-cbc", "hmac-sha512-idea-cbc",
        "hmac-sha3-224-idea-cbc", "hmac-sha3-256-idea-cbc", "hmac-sha3-384-idea-cbc", "hmac-sha3-512-idea-cbc",
        "hmac-tiger-idea-cbc",
        "hmac-whirlpool-idea-cbc",
        "hmac-sha224-rc2-cbc/182", "hmac-sha256-rc2-cbc/182", "hmac-sha384-rc2-cbc/182", "hmac-sha512-rc2-cbc/182",
        "hmac-sha3-224-rc2-cbc/182", "hmac-sha3-256-rc2-cbc/182", "hmac-sha3-384-rc2-cbc/182", "hmac-sha3-512-rc2-cbc/182",
        "hmac-tiger-rc2-cbc/182",
        "hmac-whirlpool-rc2-cbc/182",
        "hmac-sha224-rc5-cbc/256", "hmac-sha256-rc5-cbc/256", "hmac-sha384-rc5-cbc/256", "hmac-sha512-rc5-cbc/256",
        "hmac-sha3-224-rc5-cbc/256", "hmac-sha3-256-rc5-cbc/256", "hmac-sha3-384-rc5-cbc/256", "hmac-sha3-512-rc5-cbc/256",
        "hmac-tiger-rc5-cbc/256",
        "hmac-whirlpool-rc5-cbc/256",
        "hmac-sha224-rc6-128-cbc/128", "hmac-sha256-rc6-128-cbc/128", "hmac-sha384-rc6-128-cbc/128",
        "hmac-sha512-rc6-128-cbc/128",
        "hmac-sha3-224-rc6-128-cbc/128", "hmac-sha3-256-rc6-128-cbc/128", "hmac-sha3-384-rc6-128-cbc/128",
        "hmac-sha3-512-rc6-128-cbc/128",
        "hmac-tiger-rc6-128-cbc/128",
        "hmac-whirlpool-rc6-128-cbc/128",
        "hmac-sha224-rc6-192-cbc/192", "hmac-sha256-rc6-192-cbc/192", "hmac-sha384-rc6-192-cbc/192",
        "hmac-sha512-rc6-192-cbc/192",
        "hmac-sha3-224-rc6-192-cbc/192", "hmac-sha3-256-rc6-192-cbc/192", "hmac-sha3-384-rc6-192-cbc/192",
        "hmac-sha3-512-rc6-192-cbc/192",
        "hmac-tiger-rc6-192-cbc/192",
        "hmac-whirlpool-rc6-192-cbc/192",
        "hmac-sha224-rc6-256-cbc/256", "hmac-sha256-rc6-256-cbc/256", "hmac-sha384-rc6-256-cbc/256",
        "hmac-sha512-rc6-256-cbc/256",
        "hmac-sha3-224-rc6-256-cbc/256", "hmac-sha3-256-rc6-256-cbc/256", "hmac-sha3-384-rc6-256-cbc/256",
        "hmac-sha3-512-rc6-256-cbc/256",
        "hmac-tiger-rc6-256-cbc/256",
        "hmac-whirlpool-rc6-256-cbc/256",
        "hmac-sha224-feal-cbc/100", "hmac-sha256-feal-cbc/100", "hmac-sha384-feal-cbc/100", "hmac-sha512-feal-cbc/100",
        "hmac-sha3-224-feal-cbc/100", "hmac-sha3-256-feal-cbc/100", "hmac-sha3-384-feal-cbc/100", "hmac-sha3-512-feal-cbc/100",
        "hmac-tiger-feal-cbc/100",
        "hmac-whirlpool-feal-cbc/100",
        "hmac-sha224-cast5-cbc", "hmac-sha256-cast5-cbc", "hmac-sha384-cast5-cbc", "hmac-sha512-cast5-cbc",
        "hmac-sha3-224-cast5-cbc", "hmac-sha3-256-cast5-cbc", "hmac-sha3-384-cast5-cbc", "hmac-sha3-512-cast5-cbc",
        "hmac-tiger-cast5-cbc",
        "hmac-whirlpool-cast5-cbc",
        "hmac-sha224-camellia-128-cbc", "hmac-sha256-camellia-128-cbc", "hmac-sha384-camellia-128-cbc",
        "hmac-sha512-camellia-128-cbc",
        "hmac-sha3-224-camellia-128-cbc", "hmac-sha3-256-camellia-128-cbc", "hmac-sha3-384-camellia-128-cbc",
        "hmac-sha3-512-camellia-128-cbc",
        "hmac-tiger-camellia-128-cbc",
        "hmac-whirlpool-camellia-128-cbc",
        "hmac-sha224-camellia-192-cbc", "hmac-sha256-camellia-192-cbc", "hmac-sha384-camellia-192-cbc",
        "hmac-sha512-camellia-192-cbc",
        "hmac-sha3-224-camellia-192-cbc", "hmac-sha3-256-camellia-192-cbc", "hmac-sha3-384-camellia-192-cbc",
        "hmac-sha3-512-camellia-192-cbc",
        "hmac-tiger-camellia-192-cbc",
        "hmac-whirlpool-camellia-192-cbc",
        "hmac-sha224-camellia-256-cbc", "hmac-sha256-camellia-256-cbc", "hmac-sha384-camellia-256-cbc",
        "hmac-sha512-camellia-256-cbc",
        "hmac-sha3-224-camellia-256-cbc", "hmac-sha3-256-camellia-256-cbc", "hmac-sha3-384-camellia-256-cbc",
        "hmac-sha3-512-camellia-256-cbc",
        "hmac-tiger-camellia-256-cbc",
        "hmac-whirlpool-camellia-256-cbc",
        "hmac-sha224-safer-k64-cbc/101", "hmac-sha256-safer-k64-cbc/101", "hmac-sha384-safer-k64-cbc/101",
        "hmac-sha512-safer-k64-cbc/101",
        "hmac-sha3-224-safer-k64-cbc/101", "hmac-sha3-256-safer-k64-cbc/101", "hmac-sha3-384-safer-k64-cbc/101",
        "hmac-sha3-512-safer-k64-cbc/101",
        "hmac-tiger-safer-k64-cbc/101",
        "hmac-whirlpool-safer-k64-cbc/101",
        "hmac-sha224-blowfish-cbc", "hmac-sha256-blowfish-cbc", "hmac-sha384-blowfish-cbc", "hmac-sha512-blowfish-cbc",
        "hmac-sha3-224-blowfish-cbc", "hmac-sha3-256-blowfish-cbc", "hmac-sha3-384-blowfish-cbc", "hmac-sha3-512-blowfish-cbc",
        "hmac-tiger-blowfish-cbc",
        "hmac-whirlpool-blowfish-cbc",
        "hmac-sha224-serpent-cbc", "hmac-sha256-serpent-cbc", "hmac-sha384-serpent-cbc", "hmac-sha512-serpent-cbc",
        "hmac-sha3-224-serpent-cbc", "hmac-sha3-256-serpent-cbc", "hmac-sha3-384-serpent-cbc", "hmac-sha3-512-serpent-cbc",
        "hmac-tiger-serpent-cbc",
        "hmac-whirlpool-serpent-cbc",
        "hmac-sha224-tea-cbc", "hmac-sha256-tea-cbc", "hmac-sha384-tea-cbc", "hmac-sha512-tea-cbc",
        "hmac-sha3-224-tea-cbc", "hmac-sha3-256-tea-cbc", "hmac-sha3-384-tea-cbc", "hmac-sha3-512-tea-cbc",
        "hmac-tiger-tea-cbc",
        "hmac-whirlpool-tea-cbc",
        "hmac-sha224-xtea-cbc/299", "hmac-sha256-xtea-cbc/299", "hmac-sha384-xtea-cbc/299", "hmac-sha512-xtea-cbc/299",
        "hmac-sha3-224-xtea-cbc/299", "hmac-sha3-256-xtea-cbc/299", "hmac-sha3-384-xtea-cbc/299", "hmac-sha3-512-xtea-cbc/299",
        "hmac-tiger-xtea-cbc/299",
        "hmac-whirlpool-xtea-cbc/299",
        "hmac-sha224-misty1-cbc", "hmac-sha256-misty1-cbc", "hmac-sha384-misty1-cbc", "hmac-sha512-misty1-cbc",
        "hmac-sha3-224-misty1-cbc", "hmac-sha3-256-misty1-cbc", "hmac-sha3-384-misty1-cbc", "hmac-sha3-512-misty1-cbc",
        "hmac-tiger-misty1-cbc",
        "hmac-whirlpool-misty1-cbc",
        "hmac-sha224-mars-128-cbc", "hmac-sha256-mars-128-cbc", "hmac-sha384-mars-128-cbc", "hmac-sha512-mars-128-cbc",
        "hmac-sha3-224-mars-128-cbc", "hmac-sha3-256-mars-128-cbc", "hmac-sha3-384-mars-128-cbc", "hmac-sha3-512-mars-128-cbc",
        "hmac-tiger-mars-128-cbc",
        "hmac-whirlpool-mars-128-cbc",
        "hmac-sha224-mars-192-cbc", "hmac-sha256-mars-192-cbc", "hmac-sha384-mars-192-cbc", "hmac-sha512-mars-192-cbc",
        "hmac-sha3-224-mars-192-cbc", "hmac-sha3-256-mars-192-cbc", "hmac-sha3-384-mars-192-cbc", "hmac-sha3-512-mars-192-cbc",
        "hmac-tiger-mars-192-cbc",
        "hmac-whirlpool-mars-192-cbc",
        "hmac-sha224-mars-256-cbc", "hmac-sha256-mars-256-cbc", "hmac-sha384-mars-256-cbc", "hmac-sha512-mars-256-cbc",
        "hmac-sha3-224-mars-256-cbc", "hmac-sha3-256-mars-256-cbc", "hmac-sha3-384-mars-256-cbc", "hmac-sha3-512-mars-256-cbc",
        "hmac-tiger-mars-256-cbc",
        "hmac-whirlpool-mars-256-cbc",
        "hmac-sha224-present-80-cbc", "hmac-sha256-present-80-cbc", "hmac-sha384-present-80-cbc", "hmac-sha512-present-80-cbc",
        "hmac-sha3-224-present-80-cbc", "hmac-sha3-256-present-80-cbc", "hmac-sha3-384-present-80-cbc",
        "hmac-sha3-512-present-80-cbc",
        "hmac-tiger-present-80-cbc", "hmac-whirlpool-present-80-cbc", "hmac-sha224-present-128-cbc",
        "hmac-sha256-present-128-cbc", "hmac-sha384-present-128-cbc", "hmac-sha512-present-128-cbc",
        "hmac-sha3-224-present-128-cbc", "hmac-sha3-256-present-128-cbc", "hmac-sha3-384-present-128-cbc",
        "hmac-sha3-512-present-128-cbc",
        "hmac-tiger-present-128-cbc",
        "hmac-whirlpool-present-128-cbc",
        "hmac-sha224-shacal1-cbc", "hmac-sha256-shacal1-cbc", "hmac-sha384-shacal1-cbc", "hmac-sha512-shacal1-cbc",
        "hmac-sha3-224-shacal1-cbc", "hmac-sha3-256-shacal1-cbc", "hmac-sha3-384-shacal1-cbc",
        "hmac-sha3-512-shacal1-cbc",
        "hmac-tiger-shacal1-cbc",
        "hmac-whirlpool-shacal1-cbc",
        "hmac-sha224-shacal2-cbc", "hmac-sha256-shacal2-cbc", "hmac-sha384-shacal2-cbc", "hmac-sha512-shacal2-cbc",
        "hmac-sha3-224-shacal2-cbc", "hmac-sha3-256-shacal2-cbc", "hmac-sha3-384-shacal2-cbc", "hmac-sha3-512-shacal2-cbc",
        "hmac-tiger-shacal2-cbc",
        "hmac-whirlpool-shacal2-cbc",
        "hmac-sha224-noekeon-cbc", "hmac-sha256-noekeon-cbc", "hmac-sha384-noekeon-cbc", "hmac-sha512-noekeon-cbc",
        "hmac-sha3-224-noekeon-cbc", "hmac-sha3-256-noekeon-cbc", "hmac-sha3-384-noekeon-cbc", "hmac-sha3-512-noekeon-cbc",
        "hmac-tiger-noekeon-cbc",
        "hmac-whirlpool-noekeon-cbc",
        "hmac-sha224-noekeon-d-cbc", "hmac-sha256-noekeon-d-cbc", "hmac-sha384-noekeon-d-cbc", "hmac-sha512-noekeon-d-cbc",
        "hmac-sha3-224-noekeon-d-cbc", "hmac-sha3-256-noekeon-d-cbc", "hmac-sha3-384-noekeon-d-cbc",
        "hmac-sha3-512-noekeon-d-cbc",
        "hmac-tiger-noekeon-d-cbc",
        "hmac-whirlpool-noekeon-d-cbc",
        "hmac-sha224-aes-128-ofb", "hmac-sha256-aes-128-ofb", "hmac-sha384-aes-128-ofb",
        "hmac-sha512-aes-128-ofb",
        "hmac-sha3-224-aes-128-ofb", "hmac-sha3-256-aes-128-ofb", "hmac-sha3-384-aes-128-ofb",
        "hmac-sha3-512-aes-128-ofb",
        "hmac-tiger-aes-128-ofb",
        "hmac-whirlpool-aes-128-ofb",
        "hmac-sha224-aes-192-ofb", "hmac-sha256-aes-192-ofb", "hmac-sha384-aes-192-ofb",
        "hmac-sha512-aes-192-ofb", "hmac-sha3-224-aes-192-ofb", "hmac-sha3-256-aes-192-ofb",
        "hmac-sha3-384-aes-192-ofb", "hmac-sha3-512-aes-192-ofb",
        "hmac-tiger-aes-192-ofb",
        "hmac-whirlpool-aes-192-ofb", "hmac-sha224-aes-256-ofb", "hmac-sha256-aes-256-ofb",
        "hmac-sha384-aes-256-ofb", "hmac-sha512-aes-256-ofb",
        "hmac-sha3-224-aes-256-ofb", "hmac-sha3-256-aes-256-ofb", "hmac-sha3-384-aes-256-ofb",
        "hmac-sha3-512-aes-256-ofb",
        "hmac-tiger-aes-256-ofb",
        "hmac-whirlpool-aes-256-ofb",
        "hmac-sha224-des-ofb", "hmac-sha256-des-ofb", "hmac-sha384-des-ofb", "hmac-sha512-des-ofb",
        "hmac-sha3-224-des-ofb", "hmac-sha3-256-des-ofb", "hmac-sha3-384-des-ofb", "hmac-sha3-512-des-ofb",
        "hmac-tiger-des-ofb",
        "hmac-whirlpool-des-ofb",
        "hmac-sha224-3des-ofb", "hmac-sha256-3des-ofb", "hmac-sha384-3des-ofb", "hmac-sha512-3des-ofb",
        "hmac-sha3-224-3des-ofb", "hmac-sha3-256-3des-ofb", "hmac-sha3-384-3des-ofb", "hmac-sha3-512-3des-ofb",
        "hmac-tiger-3des-ofb",
        "hmac-whirlpool-3des-ofb",
        "hmac-sha224-3des-ede-ofb", "hmac-sha256-3des-ede-ofb", "hmac-sha384-3des-ede-ofb", "hmac-sha512-3des-ede-ofb",
        "hmac-sha3-224-3des-ede-ofb", "hmac-sha3-256-3des-ede-ofb", "hmac-sha3-384-3des-ede-ofb", "hmac-sha3-512-3des-ede-ofb",
        "hmac-tiger-3des-ede-ofb",
        "hmac-whirlpool-3des-ede-ofb",
        "hmac-sha224-idea-ofb",
        "hmac-sha256-idea-ofb", "hmac-sha384-idea-ofb", "hmac-sha512-idea-ofb",
        "hmac-sha3-224-idea-ofb", "hmac-sha3-256-idea-ofb", "hmac-sha3-384-idea-ofb", "hmac-sha3-512-idea-ofb",
        "hmac-tiger-idea-ofb",
        "hmac-whirlpool-idea-ofb",
        "hmac-sha224-rc2-ofb/182", "hmac-sha256-rc2-ofb/182", "hmac-sha384-rc2-ofb/182", "hmac-sha512-rc2-ofb/182",
        "hmac-sha3-224-rc2-ofb/182", "hmac-sha3-256-rc2-ofb/182", "hmac-sha3-384-rc2-ofb/182", "hmac-sha3-512-rc2-ofb/182",
        "hmac-tiger-rc2-ofb/182",
        "hmac-whirlpool-rc2-ofb/182",
        "hmac-sha224-rc5-ofb/256", "hmac-sha256-rc5-ofb/256", "hmac-sha384-rc5-ofb/256", "hmac-sha512-rc5-ofb/256",
        "hmac-sha3-224-rc5-ofb/256", "hmac-sha3-256-rc5-ofb/256", "hmac-sha3-384-rc5-ofb/256", "hmac-sha3-512-rc5-ofb/256",
        "hmac-tiger-rc5-ofb/256",
        "hmac-whirlpool-rc5-ofb/256",
        "hmac-sha224-rc6-128-ofb/128", "hmac-sha256-rc6-128-ofb/128", "hmac-sha384-rc6-128-ofb/128",
        "hmac-sha512-rc6-128-ofb/128",
        "hmac-sha3-224-rc6-128-ofb/128", "hmac-sha3-256-rc6-128-ofb/128", "hmac-sha3-384-rc6-128-ofb/128",
        "hmac-sha3-512-rc6-128-ofb/128",
        "hmac-tiger-rc6-128-ofb/128",
        "hmac-whirlpool-rc6-128-ofb/128",
        "hmac-sha224-rc6-192-ofb/192", "hmac-sha256-rc6-192-ofb/192", "hmac-sha384-rc6-192-ofb/192",
        "hmac-sha512-rc6-192-ofb/192",
        "hmac-sha3-224-rc6-192-ofb/192", "hmac-sha3-256-rc6-192-ofb/192", "hmac-sha3-384-rc6-192-ofb/192",
        "hmac-sha3-512-rc6-192-ofb/192",
        "hmac-tiger-rc6-192-ofb/192",
        "hmac-whirlpool-rc6-192-ofb/192",
        "hmac-sha224-rc6-256-ofb/256", "hmac-sha256-rc6-256-ofb/256", "hmac-sha384-rc6-256-ofb/256",
        "hmac-sha512-rc6-256-ofb/256",
        "hmac-sha3-224-rc6-256-ofb/256", "hmac-sha3-256-rc6-256-ofb/256", "hmac-sha3-384-rc6-256-ofb/256",
        "hmac-sha3-512-rc6-256-ofb/256",
        "hmac-tiger-rc6-256-ofb/256",
        "hmac-whirlpool-rc6-256-ofb/256",
        "hmac-sha224-feal-ofb/100", "hmac-sha256-feal-ofb/100", "hmac-sha384-feal-ofb/100", "hmac-sha512-feal-ofb/100",
        "hmac-sha3-224-feal-ofb/100", "hmac-sha3-256-feal-ofb/100", "hmac-sha3-384-feal-ofb/100", "hmac-sha3-512-feal-ofb/100",
        "hmac-tiger-feal-ofb/100",
        "hmac-whirlpool-feal-ofb/100",
        "hmac-sha224-cast5-ofb", "hmac-sha256-cast5-ofb", "hmac-sha384-cast5-ofb", "hmac-sha512-cast5-ofb",
        "hmac-sha3-224-cast5-ofb", "hmac-sha3-256-cast5-ofb", "hmac-sha3-384-cast5-ofb", "hmac-sha3-512-cast5-ofb",
        "hmac-tiger-cast5-ofb",
        "hmac-whirlpool-cast5-ofb",
        "hmac-sha224-camellia-128-ofb", "hmac-sha256-camellia-128-ofb", "hmac-sha384-camellia-128-ofb",
        "hmac-sha512-camellia-128-ofb",
        "hmac-sha3-224-camellia-128-ofb", "hmac-sha3-256-camellia-128-ofb", "hmac-sha3-384-camellia-128-ofb",
        "hmac-sha3-512-camellia-128-ofb",
        "hmac-tiger-camellia-128-ofb",
        "hmac-whirlpool-camellia-128-ofb",
        "hmac-sha224-camellia-192-ofb", "hmac-sha256-camellia-192-ofb", "hmac-sha384-camellia-192-ofb",
        "hmac-sha512-camellia-192-ofb",
        "hmac-sha3-224-camellia-192-ofb", "hmac-sha3-256-camellia-192-ofb", "hmac-sha3-384-camellia-192-ofb",
        "hmac-sha3-512-camellia-192-ofb",
        "hmac-tiger-camellia-192-ofb",
        "hmac-whirlpool-camellia-192-ofb",
        "hmac-sha224-camellia-256-ofb", "hmac-sha256-camellia-256-ofb", "hmac-sha384-camellia-256-ofb",
        "hmac-sha512-camellia-256-ofb",
        "hmac-sha3-224-camellia-256-ofb", "hmac-sha3-256-camellia-256-ofb", "hmac-sha3-384-camellia-256-ofb",
        "hmac-sha3-512-camellia-256-ofb",
        "hmac-tiger-camellia-256-ofb",
        "hmac-whirlpool-camellia-256-ofb",
        "hmac-sha224-safer-k64-ofb/101", "hmac-sha256-safer-k64-ofb/101", "hmac-sha384-safer-k64-ofb/101",
        "hmac-sha512-safer-k64-ofb/101",
        "hmac-sha3-224-safer-k64-ofb/101", "hmac-sha3-256-safer-k64-ofb/101", "hmac-sha3-384-safer-k64-ofb/101",
        "hmac-sha3-512-safer-k64-ofb/101",
        "hmac-tiger-safer-k64-ofb/101",
        "hmac-whirlpool-safer-k64-ofb/101",
        "hmac-sha224-blowfish-ofb", "hmac-sha256-blowfish-ofb", "hmac-sha384-blowfish-ofb", "hmac-sha512-blowfish-ofb",
        "hmac-sha3-224-blowfish-ofb", "hmac-sha3-256-blowfish-ofb", "hmac-sha3-384-blowfish-ofb", "hmac-sha3-512-blowfish-ofb",
        "hmac-tiger-blowfish-ofb",
        "hmac-whirlpool-blowfish-ofb",
        "hmac-sha224-serpent-ofb", "hmac-sha256-serpent-ofb", "hmac-sha384-serpent-ofb", "hmac-sha512-serpent-ofb",
        "hmac-sha3-224-serpent-ofb", "hmac-sha3-256-serpent-ofb", "hmac-sha3-384-serpent-ofb", "hmac-sha3-512-serpent-ofb",
        "hmac-tiger-serpent-ofb",
        "hmac-whirlpool-serpent-ofb",
        "hmac-sha224-tea-ofb", "hmac-sha256-tea-ofb", "hmac-sha384-tea-ofb", "hmac-sha512-tea-ofb",
        "hmac-sha3-224-tea-ofb", "hmac-sha3-256-tea-ofb", "hmac-sha3-384-tea-ofb", "hmac-sha3-512-tea-ofb",
        "hmac-tiger-tea-ofb",
        "hmac-whirlpool-tea-ofb",
        "hmac-sha224-xtea-ofb/299", "hmac-sha256-xtea-ofb/299", "hmac-sha384-xtea-ofb/299", "hmac-sha512-xtea-ofb/299",
        "hmac-sha3-224-xtea-ofb/299", "hmac-sha3-256-xtea-ofb/299", "hmac-sha3-384-xtea-ofb/299", "hmac-sha3-512-xtea-ofb/299",
        "hmac-tiger-xtea-ofb/299",
        "hmac-whirlpool-xtea-ofb/299",
        "hmac-sha224-misty1-ofb", "hmac-sha256-misty1-ofb", "hmac-sha384-misty1-ofb", "hmac-sha512-misty1-ofb",
        "hmac-sha3-224-misty1-ofb", "hmac-sha3-256-misty1-ofb", "hmac-sha3-384-misty1-ofb", "hmac-sha3-512-misty1-ofb",
        "hmac-tiger-misty1-ofb",
        "hmac-whirlpool-misty1-ofb",
        "hmac-sha224-mars-128-ofb", "hmac-sha256-mars-128-ofb", "hmac-sha384-mars-128-ofb", "hmac-sha512-mars-128-ofb",
        "hmac-sha3-224-mars-128-ofb", "hmac-sha3-256-mars-128-ofb", "hmac-sha3-384-mars-128-ofb", "hmac-sha3-512-mars-128-ofb",
        "hmac-tiger-mars-128-ofb",
        "hmac-whirlpool-mars-128-ofb",
        "hmac-sha224-mars-192-ofb", "hmac-sha256-mars-192-ofb", "hmac-sha384-mars-192-ofb", "hmac-sha512-mars-192-ofb",
        "hmac-sha3-224-mars-192-ofb", "hmac-sha3-256-mars-192-ofb", "hmac-sha3-384-mars-192-ofb", "hmac-sha3-512-mars-192-ofb",
        "hmac-tiger-mars-192-ofb",
        "hmac-whirlpool-mars-192-ofb",
        "hmac-sha224-mars-256-ofb", "hmac-sha256-mars-256-ofb", "hmac-sha384-mars-256-ofb", "hmac-sha512-mars-256-ofb",
        "hmac-sha3-224-mars-256-ofb", "hmac-sha3-256-mars-256-ofb", "hmac-sha3-384-mars-256-ofb", "hmac-sha3-512-mars-256-ofb",
        "hmac-tiger-mars-256-ofb",
        "hmac-whirlpool-mars-256-ofb",
        "hmac-sha224-present-80-ofb", "hmac-sha256-present-80-ofb", "hmac-sha384-present-80-ofb", "hmac-sha512-present-80-ofb",
        "hmac-sha3-224-present-80-ofb", "hmac-sha3-256-present-80-ofb", "hmac-sha3-384-present-80-ofb",
        "hmac-sha3-512-present-80-ofb",
        "hmac-tiger-present-80-ofb", "hmac-whirlpool-present-80-ofb", "hmac-sha224-present-128-ofb",
        "hmac-sha256-present-128-ofb", "hmac-sha384-present-128-ofb", "hmac-sha512-present-128-ofb",
        "hmac-sha3-224-present-128-ofb", "hmac-sha3-256-present-128-ofb", "hmac-sha3-384-present-128-ofb",
        "hmac-sha3-512-present-128-ofb",
        "hmac-tiger-present-128-ofb",
        "hmac-whirlpool-present-128-ofb",
        "hmac-sha224-shacal1-ofb", "hmac-sha256-shacal1-ofb", "hmac-sha384-shacal1-ofb", "hmac-sha512-shacal1-ofb",
        "hmac-sha3-224-shacal1-ofb", "hmac-sha3-256-shacal1-ofb", "hmac-sha3-384-shacal1-ofb",
        "hmac-sha3-512-shacal1-ofb",
        "hmac-tiger-shacal1-ofb",
        "hmac-whirlpool-shacal1-ofb",
        "hmac-sha224-shacal2-ofb", "hmac-sha256-shacal2-ofb", "hmac-sha384-shacal2-ofb", "hmac-sha512-shacal2-ofb",
        "hmac-sha3-224-shacal2-ofb", "hmac-sha3-256-shacal2-ofb", "hmac-sha3-384-shacal2-ofb", "hmac-sha3-512-shacal2-ofb",
        "hmac-tiger-shacal2-ofb",
        "hmac-whirlpool-shacal2-ofb",
        "hmac-sha224-noekeon-ofb", "hmac-sha256-noekeon-ofb", "hmac-sha384-noekeon-ofb", "hmac-sha512-noekeon-ofb",
        "hmac-sha3-224-noekeon-ofb", "hmac-sha3-256-noekeon-ofb", "hmac-sha3-384-noekeon-ofb", "hmac-sha3-512-noekeon-ofb",
        "hmac-tiger-noekeon-ofb",
        "hmac-whirlpool-noekeon-ofb",
        "hmac-sha224-noekeon-d-ofb", "hmac-sha256-noekeon-d-ofb", "hmac-sha384-noekeon-d-ofb", "hmac-sha512-noekeon-d-ofb",
        "hmac-sha3-224-noekeon-d-ofb", "hmac-sha3-256-noekeon-d-ofb", "hmac-sha3-384-noekeon-d-ofb",
        "hmac-sha3-512-noekeon-d-ofb",
        "hmac-tiger-noekeon-d-ofb",
        "hmac-whirlpool-noekeon-d-ofb",
        "hmac-sha224-aes-128-ctr", "hmac-sha256-aes-128-ctr", "hmac-sha384-aes-128-ctr",
        "hmac-sha512-aes-128-ctr",
        "hmac-sha3-224-aes-128-ctr", "hmac-sha3-256-aes-128-ctr", "hmac-sha3-384-aes-128-ctr",
        "hmac-sha3-512-aes-128-ctr",
        "hmac-tiger-aes-128-ctr",
        "hmac-whirlpool-aes-128-ctr",
        "hmac-sha224-aes-192-ctr", "hmac-sha256-aes-192-ctr", "hmac-sha384-aes-192-ctr",
        "hmac-sha512-aes-192-ctr", "hmac-sha3-224-aes-192-ctr", "hmac-sha3-256-aes-192-ctr",
        "hmac-sha3-384-aes-192-ctr", "hmac-sha3-512-aes-192-ctr",
        "hmac-tiger-aes-192-ctr",
        "hmac-whirlpool-aes-192-ctr", "hmac-sha224-aes-256-ctr", "hmac-sha256-aes-256-ctr",
        "hmac-sha384-aes-256-ctr", "hmac-sha512-aes-256-ctr",
        "hmac-sha3-224-aes-256-ctr", "hmac-sha3-256-aes-256-ctr", "hmac-sha3-384-aes-256-ctr",
        "hmac-sha3-512-aes-256-ctr",
        "hmac-tiger-aes-256-ctr",
        "hmac-whirlpool-aes-256-ctr",
        "hmac-sha224-des-ctr", "hmac-sha256-des-ctr", "hmac-sha384-des-ctr", "hmac-sha512-des-ctr",
        "hmac-sha3-224-des-ctr", "hmac-sha3-256-des-ctr", "hmac-sha3-384-des-ctr", "hmac-sha3-512-des-ctr",
        "hmac-tiger-des-ctr",
        "hmac-whirlpool-des-ctr",
        "hmac-sha224-3des-ctr", "hmac-sha256-3des-ctr", "hmac-sha384-3des-ctr", "hmac-sha512-3des-ctr",
        "hmac-sha3-224-3des-ctr", "hmac-sha3-256-3des-ctr", "hmac-sha3-384-3des-ctr", "hmac-sha3-512-3des-ctr",
        "hmac-tiger-3des-ctr",
        "hmac-whirlpool-3des-ctr",
        "hmac-sha224-3des-ede-ctr", "hmac-sha256-3des-ede-ctr", "hmac-sha384-3des-ede-ctr", "hmac-sha512-3des-ede-ctr",
        "hmac-sha3-224-3des-ede-ctr", "hmac-sha3-256-3des-ede-ctr", "hmac-sha3-384-3des-ede-ctr", "hmac-sha3-512-3des-ede-ctr",
        "hmac-tiger-3des-ede-ctr",
        "hmac-whirlpool-3des-ede-ctr",
        "hmac-sha224-idea-ctr",
        "hmac-sha256-idea-ctr", "hmac-sha384-idea-ctr", "hmac-sha512-idea-ctr",
        "hmac-sha3-224-idea-ctr", "hmac-sha3-256-idea-ctr", "hmac-sha3-384-idea-ctr", "hmac-sha3-512-idea-ctr",
        "hmac-tiger-idea-ctr",
        "hmac-whirlpool-idea-ctr",
        "hmac-sha224-rc2-ctr/182", "hmac-sha256-rc2-ctr/182", "hmac-sha384-rc2-ctr/182", "hmac-sha512-rc2-ctr/182",
        "hmac-sha3-224-rc2-ctr/182", "hmac-sha3-256-rc2-ctr/182", "hmac-sha3-384-rc2-ctr/182", "hmac-sha3-512-rc2-ctr/182",
        "hmac-tiger-rc2-ctr/182",
        "hmac-whirlpool-rc2-ctr/182",
        "hmac-sha224-rc5-ctr/256", "hmac-sha256-rc5-ctr/256", "hmac-sha384-rc5-ctr/256", "hmac-sha512-rc5-ctr/256",
        "hmac-sha3-224-rc5-ctr/256", "hmac-sha3-256-rc5-ctr/256", "hmac-sha3-384-rc5-ctr/256", "hmac-sha3-512-rc5-ctr/256",
        "hmac-tiger-rc5-ctr/256",
        "hmac-whirlpool-rc5-ctr/256",
        "hmac-sha224-rc6-128-ctr/128", "hmac-sha256-rc6-128-ctr/128", "hmac-sha384-rc6-128-ctr/128",
        "hmac-sha512-rc6-128-ctr/128",
        "hmac-sha3-224-rc6-128-ctr/128", "hmac-sha3-256-rc6-128-ctr/128", "hmac-sha3-384-rc6-128-ctr/128",
        "hmac-sha3-512-rc6-128-ctr/128",
        "hmac-tiger-rc6-128-ctr/128",
        "hmac-whirlpool-rc6-128-ctr/128",
        "hmac-sha224-rc6-192-ctr/192", "hmac-sha256-rc6-192-ctr/192", "hmac-sha384-rc6-192-ctr/192",
        "hmac-sha512-rc6-192-ctr/192",
        "hmac-sha3-224-rc6-192-ctr/192", "hmac-sha3-256-rc6-192-ctr/192", "hmac-sha3-384-rc6-192-ctr/192",
        "hmac-sha3-512-rc6-192-ctr/192",
        "hmac-tiger-rc6-192-ctr/192",
        "hmac-whirlpool-rc6-192-ctr/192",
        "hmac-sha224-rc6-256-ctr/256", "hmac-sha256-rc6-256-ctr/256", "hmac-sha384-rc6-256-ctr/256",
        "hmac-sha512-rc6-256-ctr/256",
        "hmac-sha3-224-rc6-256-ctr/256", "hmac-sha3-256-rc6-256-ctr/256", "hmac-sha3-384-rc6-256-ctr/256",
        "hmac-sha3-512-rc6-256-ctr/256",
        "hmac-tiger-rc6-256-ctr/256",
        "hmac-whirlpool-rc6-256-ctr/256",
        "hmac-sha224-feal-ctr/100", "hmac-sha256-feal-ctr/100", "hmac-sha384-feal-ctr/100", "hmac-sha512-feal-ctr/100",
        "hmac-sha3-224-feal-ctr/100", "hmac-sha3-256-feal-ctr/100", "hmac-sha3-384-feal-ctr/100", "hmac-sha3-512-feal-ctr/100",
        "hmac-tiger-feal-ctr/100",
        "hmac-whirlpool-feal-ctr/100",
        "hmac-sha224-cast5-ctr", "hmac-sha256-cast5-ctr", "hmac-sha384-cast5-ctr", "hmac-sha512-cast5-ctr",
        "hmac-sha3-224-cast5-ctr", "hmac-sha3-256-cast5-ctr", "hmac-sha3-384-cast5-ctr", "hmac-sha3-512-cast5-ctr",
        "hmac-tiger-cast5-ctr",
        "hmac-whirlpool-cast5-ctr",
        "hmac-sha224-camellia-128-ctr", "hmac-sha256-camellia-128-ctr", "hmac-sha384-camellia-128-ctr",
        "hmac-sha512-camellia-128-ctr",
        "hmac-sha3-224-camellia-128-ctr", "hmac-sha3-256-camellia-128-ctr", "hmac-sha3-384-camellia-128-ctr",
        "hmac-sha3-512-camellia-128-ctr",
        "hmac-tiger-camellia-128-ctr",
        "hmac-whirlpool-camellia-128-ctr",
        "hmac-sha224-camellia-192-ctr", "hmac-sha256-camellia-192-ctr", "hmac-sha384-camellia-192-ctr",
        "hmac-sha512-camellia-192-ctr",
        "hmac-sha3-224-camellia-192-ctr", "hmac-sha3-256-camellia-192-ctr", "hmac-sha3-384-camellia-192-ctr",
        "hmac-sha3-512-camellia-192-ctr",
        "hmac-tiger-camellia-192-ctr",
        "hmac-whirlpool-camellia-192-ctr",
        "hmac-sha224-camellia-256-ctr", "hmac-sha256-camellia-256-ctr", "hmac-sha384-camellia-256-ctr",
        "hmac-sha512-camellia-256-ctr",
        "hmac-sha3-224-camellia-256-ctr", "hmac-sha3-256-camellia-256-ctr", "hmac-sha3-384-camellia-256-ctr",
        "hmac-sha3-512-camellia-256-ctr",
        "hmac-tiger-camellia-256-ctr",
        "hmac-whirlpool-camellia-256-ctr",
        "hmac-sha224-safer-k64-ctr/101", "hmac-sha256-safer-k64-ctr/101", "hmac-sha384-safer-k64-ctr/101",
        "hmac-sha512-safer-k64-ctr/101",
        "hmac-sha3-224-safer-k64-ctr/101", "hmac-sha3-256-safer-k64-ctr/101", "hmac-sha3-384-safer-k64-ctr/101",
        "hmac-sha3-512-safer-k64-ctr/101",
        "hmac-tiger-safer-k64-ctr/101",
        "hmac-whirlpool-safer-k64-ctr/101",
        "hmac-sha224-blowfish-ctr", "hmac-sha256-blowfish-ctr", "hmac-sha384-blowfish-ctr", "hmac-sha512-blowfish-ctr",
        "hmac-sha3-224-blowfish-ctr", "hmac-sha3-256-blowfish-ctr", "hmac-sha3-384-blowfish-ctr", "hmac-sha3-512-blowfish-ctr",
        "hmac-tiger-blowfish-ctr",
        "hmac-whirlpool-blowfish-ctr",
        "hmac-sha224-serpent-ctr", "hmac-sha256-serpent-ctr", "hmac-sha384-serpent-ctr", "hmac-sha512-serpent-ctr",
        "hmac-sha3-224-serpent-ctr", "hmac-sha3-256-serpent-ctr", "hmac-sha3-384-serpent-ctr", "hmac-sha3-512-serpent-ctr",
        "hmac-tiger-serpent-ctr",
        "hmac-whirlpool-serpent-ctr",
        "hmac-sha224-tea-ctr", "hmac-sha256-tea-ctr", "hmac-sha384-tea-ctr", "hmac-sha512-tea-ctr",
        "hmac-sha3-224-tea-ctr", "hmac-sha3-256-tea-ctr", "hmac-sha3-384-tea-ctr", "hmac-sha3-512-tea-ctr",
        "hmac-tiger-tea-ctr",
        "hmac-whirlpool-tea-ctr",
        "hmac-sha224-xtea-ctr/299", "hmac-sha256-xtea-ctr/299", "hmac-sha384-xtea-ctr/299", "hmac-sha512-xtea-ctr/299",
        "hmac-sha3-224-xtea-ctr/299", "hmac-sha3-256-xtea-ctr/299", "hmac-sha3-384-xtea-ctr/299", "hmac-sha3-512-xtea-ctr/299",
        "hmac-tiger-xtea-ctr/299",
        "hmac-whirlpool-xtea-ctr/299",
        "hmac-sha224-misty1-ctr", "hmac-sha256-misty1-ctr", "hmac-sha384-misty1-ctr", "hmac-sha512-misty1-ctr",
        "hmac-sha3-224-misty1-ctr", "hmac-sha3-256-misty1-ctr", "hmac-sha3-384-misty1-ctr", "hmac-sha3-512-misty1-ctr",
        "hmac-tiger-misty1-ctr",
        "hmac-whirlpool-misty1-ctr",
        "hmac-sha224-mars-128-ctr", "hmac-sha256-mars-128-ctr", "hmac-sha384-mars-128-ctr", "hmac-sha512-mars-128-ctr",
        "hmac-sha3-224-mars-128-ctr", "hmac-sha3-256-mars-128-ctr", "hmac-sha3-384-mars-128-ctr", "hmac-sha3-512-mars-128-ctr",
        "hmac-tiger-mars-128-ctr",
        "hmac-whirlpool-mars-128-ctr",
        "hmac-sha224-mars-192-ctr", "hmac-sha256-mars-192-ctr", "hmac-sha384-mars-192-ctr", "hmac-sha512-mars-192-ctr",
        "hmac-sha3-224-mars-192-ctr", "hmac-sha3-256-mars-192-ctr", "hmac-sha3-384-mars-192-ctr", "hmac-sha3-512-mars-192-ctr",
        "hmac-tiger-mars-192-ctr",
        "hmac-whirlpool-mars-192-ctr",
        "hmac-sha224-mars-256-ctr", "hmac-sha256-mars-256-ctr", "hmac-sha384-mars-256-ctr", "hmac-sha512-mars-256-ctr",
        "hmac-sha3-224-mars-256-ctr", "hmac-sha3-256-mars-256-ctr", "hmac-sha3-384-mars-256-ctr", "hmac-sha3-512-mars-256-ctr",
        "hmac-tiger-mars-256-ctr",
        "hmac-whirlpool-mars-256-ctr",
        "hmac-sha224-present-80-ctr", "hmac-sha256-present-80-ctr", "hmac-sha384-present-80-ctr", "hmac-sha512-present-80-ctr",
        "hmac-sha3-224-present-80-ctr", "hmac-sha3-256-present-80-ctr", "hmac-sha3-384-present-80-ctr",
        "hmac-sha3-512-present-80-ctr",
        "hmac-tiger-present-80-ctr", "hmac-whirlpool-present-80-ctr", "hmac-sha224-present-128-ctr",
        "hmac-sha256-present-128-ctr", "hmac-sha384-present-128-ctr", "hmac-sha512-present-128-ctr",
        "hmac-sha3-224-present-128-ctr", "hmac-sha3-256-present-128-ctr", "hmac-sha3-384-present-128-ctr",
        "hmac-sha3-512-present-128-ctr",
        "hmac-tiger-present-128-ctr",
        "hmac-whirlpool-present-128-ctr",
        "hmac-sha224-shacal1-ctr", "hmac-sha256-shacal1-ctr", "hmac-sha384-shacal1-ctr", "hmac-sha512-shacal1-ctr",
        "hmac-sha3-224-shacal1-ctr", "hmac-sha3-256-shacal1-ctr", "hmac-sha3-384-shacal1-ctr",
        "hmac-sha3-512-shacal1-ctr",
        "hmac-tiger-shacal1-ctr",
        "hmac-whirlpool-shacal1-ctr",
        "hmac-sha224-shacal2-ctr", "hmac-sha256-shacal2-ctr", "hmac-sha384-shacal2-ctr", "hmac-sha512-shacal2-ctr",
        "hmac-sha3-224-shacal2-ctr", "hmac-sha3-256-shacal2-ctr", "hmac-sha3-384-shacal2-ctr", "hmac-sha3-512-shacal2-ctr",
        "hmac-tiger-shacal2-ctr",
        "hmac-whirlpool-shacal2-ctr",
        "hmac-sha224-noekeon-ctr", "hmac-sha256-noekeon-ctr", "hmac-sha384-noekeon-ctr", "hmac-sha512-noekeon-ctr",
        "hmac-sha3-224-noekeon-ctr", "hmac-sha3-256-noekeon-ctr", "hmac-sha3-384-noekeon-ctr", "hmac-sha3-512-noekeon-ctr",
        "hmac-tiger-noekeon-ctr",
        "hmac-whirlpool-noekeon-ctr",
        "hmac-sha224-noekeon-d-ctr", "hmac-sha256-noekeon-d-ctr", "hmac-sha384-noekeon-d-ctr", "hmac-sha512-noekeon-d-ctr",
        "hmac-sha3-224-noekeon-d-ctr", "hmac-sha3-256-noekeon-d-ctr", "hmac-sha3-384-noekeon-d-ctr",
        "hmac-sha3-512-noekeon-d-ctr",
        "hmac-tiger-noekeon-d-ctr",
        "hmac-whirlpool-noekeon-d-ctr"
    };

    static size_t huge_protchain_sz = sizeof(huge_protchain) / sizeof(huge_protchain[0]);
    ssize_t a;
    size_t h;
    blackcat_protlayer_chain_ctx *pchain;

    CUTE_ASSERT(huge_protchain_sz == g_blackcat_ciphering_schemes_nr);

    for (h = 0; h < huge_protchain_sz; h++) {
        a = get_algo_index(huge_protchain[h]);

        CUTE_ASSERT(a > -1 && a < g_blackcat_ciphering_schemes_nr);

        pchain = NULL;
        pchain = add_protlayer_to_chain(pchain, huge_protchain[h], "secret", 6);

        CUTE_ASSERT(pchain != NULL);

        CUTE_ASSERT(pchain->key != NULL);

        if (g_blackcat_ciphering_schemes[a].key_size > -1) {
            CUTE_ASSERT(pchain->key_size == g_blackcat_ciphering_schemes[a].key_size);
        } else {
            CUTE_ASSERT(pchain->key_size == 6);
        }

        CUTE_ASSERT(pchain->processor == g_blackcat_ciphering_schemes[a].processor);

        if (!is_null_arg_handler(g_blackcat_ciphering_schemes[a].args)) {
            CUTE_ASSERT(pchain->argc > 0);
        } else {
            CUTE_ASSERT(pchain->argc == 0);
        }

        CUTE_ASSERT(pchain->mode == g_blackcat_ciphering_schemes[a].mode);

        del_protlayer_chain_ctx(pchain);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_is_dec_tests)
    struct is_dec_tests_ctx {
        char *buf;
        int valid;
    };
    struct is_dec_tests_ctx is_dec_tests[] = {
        { "0", 1 }, { "1", 1 }, { "2", 1 }, { "3", 1 }, { "4", 1 }, { "5", 1 }, { "6", 1 }, { "7", 1 }, { "8", 1 }, { "9", 1 },

        { "0'", 0 }, { "1a", 0 }, { "2b", 0 }, { "3c", 0 }, { "4d", 0 }, { "5D", 0 }, { "6E", 0 }, { "7f", 0 }, { "8g", 0 },
        { "9h", 0 },

        { "00", 1 }, { "111", 1 }, { "2222", 1 }, { "33333", 1 }, { "4444444", 1 }, { "55555555", 1 }, { "666666666", 1 },
        { "7723817238123712", 1 }, { "87273172", 1 }, { "91", 1 }
    };
    size_t is_dec_tests_nr = sizeof(is_dec_tests) / sizeof(is_dec_tests[0]), i;

    CUTE_ASSERT(blackcat_is_dec(NULL, 6723) == 0);
    CUTE_ASSERT(blackcat_is_dec("valid", 0) == 0);
    CUTE_ASSERT(blackcat_is_dec(NULL, 0) == 0);

    for (i = 0; i < is_dec_tests_nr; i++) {
        CUTE_ASSERT(blackcat_is_dec(is_dec_tests[i].buf, strlen(is_dec_tests[i].buf)) == is_dec_tests[i].valid);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(keychain_arg_parsing_tests)
    const char *algo_params = "anyscheme-anyhash-anychiper/"
                      "a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v-w-x-y-z-0-1-2-3-4-5-6-7-8-9-"
                      "dannyboooooooy-aa-bb-cc-dd-ee-ff-gg-hh-ii-jj-kk-ll-mm-nn-oo-pp-qq-rr-ss-tt-uu-vv-ww-xx-yy-zz-"
                      "00-11-22-33-44-55-66-77-88-99-done";
    const char *expected_args[] = {
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", 
        "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        "dannyboooooooy",
        "aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj", "kk", "ll", "mm", "nn", "oo", "pp", "qq", "rr", "ss",
        "tt", "uu", "vv", "ww", "xx", "yy", "zz", "00", "11", "22", "33", "44", "55", "66", "77", "88", "99",
        "done"
    };
    size_t expected_args_nr = sizeof(expected_args) / sizeof(expected_args[0]), e;
    const char *begin, *end;
    char *arg;

    blackcat_keychain_arg_init(algo_params, strlen(algo_params), &begin, &end);

    for (e = 0; e < expected_args_nr; e++) {
        arg = blackcat_keychain_arg_next(&begin, end, NULL, NULL);
        CUTE_ASSERT(arg != NULL);
        CUTE_ASSERT(strcmp(arg, expected_args[e]) == 0);
        free(arg);
    }

    arg = blackcat_keychain_arg_next(&begin, end, NULL, NULL);

    CUTE_ASSERT(arg == NULL);
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
    CUTE_ASSERT(pchain->key != NULL);
    CUTE_ASSERT(pchain->key_size != 0);
    CUTE_ASSERT(pchain->processor != NULL);
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
    CUTE_ASSERT(pchain->next->key != NULL);
    CUTE_ASSERT(pchain->next->key_size != 0);
    CUTE_ASSERT(pchain->next->processor != NULL);
    CUTE_ASSERT(pchain->next->last == pchain);
    CUTE_ASSERT(pchain->next->next == NULL);

    del_protlayer_chain_ctx(pchain);
CUTE_TEST_CASE_END
