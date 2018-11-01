#include <cutest.h>
#include <net/ctx/ctx.h>
#include <keychain/ciphering_schemes.h>
#include <string.h>

CUTE_DECLARE_TEST_CASE(blackcat_net_tests_entry);
CUTE_DECLARE_TEST_CASE(ctx_tests);

CUTE_MAIN(blackcat_net_tests_entry);

CUTE_TEST_CASE(blackcat_net_tests_entry)
    CUTE_RUN_TEST(ctx_tests);
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
