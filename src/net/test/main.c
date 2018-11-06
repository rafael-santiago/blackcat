/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <net/ctx/ctx.h>
#include <net/db/db.h>
#include <keychain/ciphering_schemes.h>
#include <string.h>
#include <errno.h>

CUTE_DECLARE_TEST_CASE(blackcat_net_tests_entry);
CUTE_DECLARE_TEST_CASE(ctx_tests);
CUTE_DECLARE_TEST_CASE(net_db_io_tests);

CUTE_MAIN(blackcat_net_tests_entry);

CUTE_TEST_CASE(blackcat_net_tests_entry)
    CUTE_RUN_TEST(ctx_tests);
    CUTE_RUN_TEST(net_db_io_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(net_db_io_tests)
    char error[1024];
    bnt_channel_rule_ctx *rule;
    kryptos_u8_t *rule_key = NULL;
    size_t rule_key_size = 0;

    remove("stub.io");
    CUTE_ASSERT(blackcat_netdb_load("stub.io") == 0);

    CUTE_ASSERT(blackcat_netdb_add(NULL,
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                   "(inval)",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                   "af_inet",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                   "socket",
                                   "sha-227",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "ae5-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuenc0de",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   NULL,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   NULL,
                                   strlen("OnBattleshipHill")) == EINVAL);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule.0",
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == 0);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule.1",
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   "uuencode",
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == 0);

    CUTE_ASSERT(blackcat_netdb_unload() == 0);

    CUTE_ASSERT(blackcat_netdb_load("stub.io") == 0);
    CUTE_ASSERT(blackcat_netdb_drop("sock-rule.0", "OnBattleshipHil", strlen("OnBattleshipHil")) == EFAULT);
    CUTE_ASSERT(blackcat_netdb_drop("sock-rude.0", "OnBattleshipHill", strlen("OnBattleshipHill")) == ENOENT);
    CUTE_ASSERT(blackcat_netdb_drop("sock-rule.0", "OnBattleshipHill", strlen("OnBattleshipHill")) == 0);
    CUTE_ASSERT(blackcat_netdb_drop("sock-rule.0", "OnBattleshipHill", strlen("OnBattleshipHill")) == ENOENT);
    CUTE_ASSERT(blackcat_netdb_drop("sock-rule.1", "OnBattleshipHill", strlen("OnBattleshipHill")) == 0);
    CUTE_ASSERT(blackcat_netdb_drop("sock-rule.1", "OnBattleshipHill", strlen("OnBattleshipHill")) == ENOENT);

    CUTE_ASSERT(blackcat_netdb_add("sock-rule.3",
                                   "socket",
                                   "sha-224",
                                   NULL,
                                   "aes-192-ctr,rc5-cbc/60,rc6-256-ofb/128",
                                   NULL,
                                   error,
                                   "OnBattleshipHill",
                                   strlen("OnBattleshipHill")) == 0);

    rule_key_size = 3;
    rule_key = (kryptos_u8_t *)kryptos_newseg(rule_key_size);
    CUTE_ASSERT(rule_key != NULL);
    memcpy(rule_key, "boo", 3);

    rule = blackcat_netdb_select("sock-rule.3", "OnBattleshipHill", strlen("OnBattleshipHill"), &rule_key, &rule_key_size);

    CUTE_ASSERT(rule_key_size == 0 && rule_key == NULL);

    CUTE_ASSERT(rule != NULL);

    del_bnt_channel_rule_ctx(rule);

    CUTE_ASSERT(blackcat_netdb_unload() == 0);

    remove("stub.io");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(ctx_tests)
    bnt_channel_rule_ctx *rules = NULL;
    struct bnt_channel_rule_assertion assertion;
    kryptos_u8_t *key;
    size_t key_size;

    key = (kryptos_u8_t *) kryptos_newseg(8);
    memset(key, 'Z', 8);
    key_size = 8;

    memset(&assertion, 'A', sizeof(assertion));
    rules = add_bnt_channel_rule(rules, "ABC", assertion, "hmac-sha-384-aes-192-cbc,misty1-ctr", &key, &key_size,
                                 get_hash_processor("whirlpool"), get_encoder("base64"));

    CUTE_ASSERT(rules != NULL);

    CUTE_ASSERT(rules->ruleid_size == 3);
    CUTE_ASSERT(memcmp(rules->ruleid, "ABC", rules->ruleid_size) == 0);
    CUTE_ASSERT(memcmp(&rules->assertion, &assertion, sizeof(assertion)) == 0);
    CUTE_ASSERT(rules->pchain != NULL);
    CUTE_ASSERT(key == NULL);
    CUTE_ASSERT(key_size == 0);

    key = (kryptos_u8_t *) kryptos_newseg(8);
    memset(key, 'Z', 8);
    key_size = 8;

    memset(&assertion, 'D', sizeof(assertion));
    rules = add_bnt_channel_rule(rules, "DEFG", assertion, "hmac-sha-384-aes-192-cbc,misty1-ctr", &key, &key_size,
                                 get_hash_processor("whirlpool"), get_encoder("base64"));

    CUTE_ASSERT(rules->next != NULL);

    CUTE_ASSERT(rules->next->last == rules);
    CUTE_ASSERT(rules->tail == rules->next);
    CUTE_ASSERT(rules->next->ruleid_size == 4);
    CUTE_ASSERT(memcmp(rules->next->ruleid, "DEFG", rules->next->ruleid_size) == 0);
    CUTE_ASSERT(memcmp(&rules->next->assertion, &assertion, sizeof(assertion)) == 0);
    CUTE_ASSERT(rules->next->pchain != NULL);
    CUTE_ASSERT(key == NULL);
    CUTE_ASSERT(key_size == 0);

    memset(&assertion, 'H', sizeof(assertion));
    rules = add_bnt_channel_rule(rules, "HI", assertion, "hmac-sha-384-aes-192-cbc,misty1-ctr", &key, &key_size,
                                 get_hash_processor("whirlpool"), get_encoder("base64"));

    CUTE_ASSERT(rules->next->next != NULL);

    CUTE_ASSERT(rules->next->next->last == rules->next);
    CUTE_ASSERT(rules->tail == rules->next->next);
    CUTE_ASSERT(rules->next->next->ruleid_size == 2);
    CUTE_ASSERT(memcmp(rules->next->next->ruleid, "HI", rules->next->next->ruleid_size) == 0);
    CUTE_ASSERT(memcmp(&rules->next->next->assertion, &assertion, sizeof(assertion)) == 0);
    CUTE_ASSERT(rules->next->next->pchain != NULL);
    CUTE_ASSERT(key == NULL);
    CUTE_ASSERT(key_size == 0);

    CUTE_ASSERT(get_bnt_channel_rule("BOOM!", NULL) == NULL);
    CUTE_ASSERT(get_bnt_channel_rule(NULL, rules) == NULL);
    CUTE_ASSERT(get_bnt_channel_rule("HI", rules) == rules->tail);
    CUTE_ASSERT(get_bnt_channel_rule("DEFG", rules) == rules->next);
    CUTE_ASSERT(get_bnt_channel_rule("ABC", rules) == rules);
    CUTE_ASSERT(get_bnt_channel_rule("JKL", rules) == NULL);

    CUTE_ASSERT(del_bnt_channel_rule(NULL, "BOOM") == NULL);
    CUTE_ASSERT(del_bnt_channel_rule(rules, NULL) == rules);
    CUTE_ASSERT(del_bnt_channel_rule(rules, "Unk") == rules);

    rules = del_bnt_channel_rule(rules, "DEFG");
    CUTE_ASSERT(rules != NULL && strcmp(rules->ruleid, "ABC") == 0);
    CUTE_ASSERT(rules->tail != NULL && strcmp(rules->tail->ruleid, "HI") == 0);
    CUTE_ASSERT(rules->tail->last == rules && rules->next == rules->tail);

    rules = del_bnt_channel_rule(rules, "ABC");
    CUTE_ASSERT(rules != NULL && strcmp(rules->ruleid, "HI") == 0);
    CUTE_ASSERT(rules->tail == NULL && rules->next == NULL);

    rules = del_bnt_channel_rule(rules, "HI");
    CUTE_ASSERT(rules == NULL);

    del_bnt_channel_rule_ctx(rules);
CUTE_TEST_CASE_END
