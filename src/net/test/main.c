/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <base/test/huge_protchain.h>
#include <ctx/ctx.h>
#include <net/ctx/ctx.h>
#include <net/db/db.h>
#include <net/dh/dh.h>
#include <keychain/ciphering_schemes.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

CUTE_DECLARE_TEST_CASE(blackcat_net_tests_entry);
CUTE_DECLARE_TEST_CASE(ctx_tests);
CUTE_DECLARE_TEST_CASE(net_db_io_tests);
CUTE_DECLARE_TEST_CASE(encrypt_decrypt_dh_kpriv_tests);

CUTE_MAIN(blackcat_net_tests_entry);

CUTE_TEST_CASE(blackcat_net_tests_entry)
    CUTE_RUN_TEST(ctx_tests);
    CUTE_RUN_TEST(net_db_io_tests);
    CUTE_RUN_TEST(encrypt_decrypt_dh_kpriv_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(encrypt_decrypt_dh_kpriv_tests)
    kryptos_u8_t *buf = "-----we gon' boogaloo-----\0";
    size_t buf_size = 27;
    kryptos_u8_t *cryptogram = NULL, *plaintext;
    size_t cryptogram_size, plaintext_size;

    cryptogram = encrypt_dh_kpriv(buf, buf_size, "boo", 3, &cryptogram_size);
    CUTE_ASSERT(cryptogram != NULL);

    CUTE_ASSERT(strstr(cryptogram, "-----BEGIN BC DH KPRIV-----") == (char *)cryptogram);
    CUTE_ASSERT(strstr(cryptogram, "-----END BC DH KPRIV-----") == (char *)(cryptogram +
                                                                            strlen(cryptogram) -
                                                                            strlen("-----END BC DH KPRIV-----") - 1));

    plaintext = decrypt_dh_kpriv(cryptogram, cryptogram_size, "boo", 3, &plaintext_size);
    CUTE_ASSERT(plaintext != NULL);
    CUTE_ASSERT(strstr(plaintext, buf) != NULL);

    kryptos_freeseg(cryptogram, cryptogram_size);
    kryptos_freeseg(plaintext, plaintext_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(net_db_io_tests)
    char error[1024];
    bnt_channel_rule_ctx *rule;
    kryptos_u8_t *rule_key = NULL;
    size_t rule_key_size = 0;
    int lock;
    char *protlayer = get_test_protlayer(0, 3);

    CUTE_ASSERT(protlayer != NULL);

    for (lock = 0; lock < 2; lock++) {
        remove("stub.io");
        CUTE_ASSERT(blackcat_netdb_load("stub.io", lock) == 0);

        CUTE_ASSERT(blackcat_netdb_add(NULL,
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                       "(inval)",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                       "af_inet",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                       "socket",
                                       "sha-227",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        if (isalpha(protlayer[0])) {
            protlayer[0] = toupper(protlayer[0]);
        } else {
            protlayer[1] = toupper(protlayer[1]);
        }

        CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        if (isalpha(protlayer[0])) {
            protlayer[0] = tolower(protlayer[0]);
        } else {
            protlayer[1] = tolower(protlayer[1]);
        }

        CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuenc0de",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       NULL,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule",
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       NULL,
                                       strlen("OnBattleshipHill")) == EINVAL);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule.0",
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == 0);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule.1",
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       "uuencode",
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == 0);

        CUTE_ASSERT(blackcat_netdb_unload() == 0);

        CUTE_ASSERT(blackcat_netdb_load("stub.io", lock) == 0);
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
                                       protlayer,
                                       NULL,
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == 0);

        CUTE_ASSERT(blackcat_netdb_add("sock-rule.3",
                                       "socket",
                                       "sha-224",
                                       NULL,
                                       protlayer,
                                       NULL,
                                       error,
                                       "OnBattleshipHill",
                                       strlen("OnBattleshipHill")) == EINVAL);

        rule_key_size = 3;
        rule_key = (kryptos_u8_t *)kryptos_newseg(rule_key_size);
        CUTE_ASSERT(rule_key != NULL);
        memcpy(rule_key, "boo", 3);

        rule = blackcat_netdb_select("sock-rule.3", "OnBattleshipHill", strlen("OnBattleshipHill"), &rule_key, &rule_key_size);

        CUTE_ASSERT(rule_key_size == 0 && rule_key == NULL);

        CUTE_ASSERT(rule != NULL);

        del_bnt_channel_rule_ctx(rule);

        CUTE_ASSERT(blackcat_netdb_unload() == 0);
    }

    remove("stub.io");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(ctx_tests)
    bnt_channel_rule_ctx *rules = NULL;
    struct bnt_channel_rule_assertion assertion;
    kryptos_u8_t *key;
    size_t key_size;
    bnt_keychunk_ctx *kchunk = NULL, *kp;
    bnt_keychain_ctx *kchain = NULL, *kcp, *kcp_l;
    kryptos_u64_t seqno;
    bnt_keyset_ctx ks, *keyset = &ks;
    blackcat_protlayer_chain_ctx *pchain = NULL, *p;
    kryptos_u8_t *keystream, *ksp;
    size_t keystream_size;
    struct blackcat_keychain_handle_ctx handle;
    char *protlayer = get_test_protlayer(0, 2);

    key = (kryptos_u8_t *) kryptos_newseg(8);
    memset(key, 'Z', 8);
    key_size = 8;

    memset(&assertion, 'A', sizeof(assertion));
    rules = add_bnt_channel_rule(rules, "ABC", assertion, protlayer, &key, &key_size,
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
    rules = add_bnt_channel_rule(rules, "DEFG", assertion, protlayer, &key, &key_size,
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
    rules = add_bnt_channel_rule(rules, "HI", assertion, protlayer, &key, &key_size,
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

    kchunk = add_bnt_keychunk(kchunk, "abc", 3);
    CUTE_ASSERT(kchunk != NULL);
    CUTE_ASSERT(kchunk->tail == kchunk);
    CUTE_ASSERT(kchunk->next == NULL);
    CUTE_ASSERT(kchunk->data_size == 3);
    CUTE_ASSERT(kchunk->data != NULL);
    CUTE_ASSERT(memcmp(kchunk->data, "abc", 3) == 0);
    kchunk = add_bnt_keychunk(kchunk, "d", 1);
    CUTE_ASSERT(kchunk != NULL);
    CUTE_ASSERT(kchunk->next != NULL);
    CUTE_ASSERT(kchunk->tail == kchunk->next);
    CUTE_ASSERT(kchunk->next->data_size == 1);
    CUTE_ASSERT(kchunk->next->data != NULL);
    CUTE_ASSERT(memcmp(kchunk->next->data, "d", 1) == 0);
    kchunk = add_bnt_keychunk(kchunk, "efghijklmnopq", 13);
    CUTE_ASSERT(kchunk != NULL);
    CUTE_ASSERT(kchunk->next->next != NULL);
    CUTE_ASSERT(kchunk->tail == kchunk->next->next);
    CUTE_ASSERT(kchunk->next->next->data_size == 13);
    CUTE_ASSERT(kchunk->next->next->data != NULL);
    CUTE_ASSERT(memcmp(kchunk->next->next->data, "efghijklmnopq", 13) == 0);
    del_bnt_keychunk(kchunk);

    for (seqno = 0; seqno < 11; seqno++) {
        kchain = add_bnt_keychain(kchain, seqno);
        kchain = add_bnt_keychain(kchain, seqno);
        CUTE_ASSERT(kchain != NULL);
        CUTE_ASSERT(kchain->tail != NULL);
    }

    seqno = 0;
    kcp_l = NULL;

    for (kcp = kchain; kcp != NULL; kcp_l = kcp, kcp = kcp->next) {
        CUTE_ASSERT(kcp->seqno == seqno++);
        CUTE_ASSERT(kcp_l == kcp->last);
    }

    for (seqno = 0; seqno < 11; seqno++) {
        kcp = get_bnt_keychain(seqno, kchain);
        CUTE_ASSERT(kcp != NULL);
        CUTE_ASSERT(kcp->seqno == seqno);
    }

    CUTE_ASSERT(get_bnt_keychain(seqno, kchain) == NULL);

    kchain = del_bnt_keychain_seqno(kchain, 3);
    kchain = del_bnt_keychain_seqno(kchain, 9);
    kchain = del_bnt_keychain_seqno(kchain, 8);
    kchain = del_bnt_keychain_seqno(kchain, 1);
    kchain = del_bnt_keychain_seqno(kchain, 0);
    kchain = del_bnt_keychain_seqno(kchain, 10);

    CUTE_ASSERT(get_bnt_keychain(0, kchain) == NULL);
    CUTE_ASSERT(get_bnt_keychain(1, kchain) == NULL);
    CUTE_ASSERT(get_bnt_keychain(2, kchain) != NULL);
    CUTE_ASSERT(get_bnt_keychain(3, kchain) == NULL);
    CUTE_ASSERT(get_bnt_keychain(4, kchain) != NULL);
    CUTE_ASSERT(get_bnt_keychain(5, kchain) != NULL);
    CUTE_ASSERT(get_bnt_keychain(6, kchain) != NULL);
    CUTE_ASSERT(get_bnt_keychain(7, kchain) != NULL);
    CUTE_ASSERT(get_bnt_keychain(8, kchain) == NULL);
    CUTE_ASSERT(get_bnt_keychain(9, kchain) == NULL);
    CUTE_ASSERT(get_bnt_keychain(10, kchain) == NULL);

    kchain = del_bnt_keychain_seqno(kchain, 2);
    kchain = del_bnt_keychain_seqno(kchain, 4);
    kchain = del_bnt_keychain_seqno(kchain, 5);
    kchain = del_bnt_keychain_seqno(kchain, 6);
    kchain = del_bnt_keychain_seqno(kchain, 7);

    CUTE_ASSERT(kchain == NULL);

    key = (kryptos_u8_t *) kryptos_newseg(9);
    CUTE_ASSERT(key != NULL);
    key_size = 9;

    handle.hash = get_hash_processor("whirlpool");
    handle.kdf_clockwork = NULL;

    pchain = add_composite_protlayer_to_chain(pchain,
                                              get_test_protlayer(0, 4), &key, &key_size,
                                              &handle, NULL);

    CUTE_ASSERT(init_bnt_keyset(&keyset, pchain, 50,
                                get_hash_processor("sha3-512"), get_hash_input_size("sha3-512"), get_hash_size("sha3-512"),
                                NULL, "----->", 6, "<-----", 6) == 1);

    CUTE_ASSERT(step_bnt_keyset(&keyset, 100, keyset->send_chain) == 0);

    CUTE_ASSERT(step_bnt_keyset(&keyset, 0, keyset->send_chain) == 0);

    CUTE_ASSERT(step_bnt_keyset(&keyset, 20, keyset->send_chain) == 1);

    CUTE_ASSERT(step_bnt_keyset(&keyset,  1, keyset->send_chain ) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  2, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  3, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  4, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  5, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  6, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  7, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  8, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  9, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 10, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 11, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 12, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 13, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 14, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 15, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 16, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 17, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 18, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 19, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 20, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 21, keyset->send_chain) == 1);

    keystream_size = 0;

    for (p = pchain; p != NULL; p = p->next) {
        keystream_size += p->key_size;
    }

    for (seqno = 0; seqno < 22; seqno++) {
        keystream = (kryptos_u8_t *) kryptos_newseg(keystream_size);
        ksp = keystream;

        for (kp = keyset->send_chain->key; kp != NULL; kp = kp->next) {
            memcpy(ksp, kp->data, kp->data_size);
            ksp += kp->data_size;
        }

        CUTE_ASSERT(set_protlayer_key_by_keychain_seqno(seqno, pchain, &keyset->send_chain, &keyset) == 1);

        ksp = keystream;

        for (p = pchain; p != NULL; p = p->next) {
            CUTE_ASSERT(memcmp(p->key, ksp, p->key_size) == 0);
            ksp += p->key_size;
        }

        kryptos_freeseg(keystream, keystream_size);
    }

    for (seqno = 0; seqno < 22; seqno++) {
        keystream = (kryptos_u8_t *) kryptos_newseg(keystream_size);
        ksp = keystream;

        for (kp = keyset->recv_chain->key; kp != NULL; kp = kp->next) {
            memcpy(ksp, kp->data, kp->data_size);
            ksp += kp->data_size;
        }

        CUTE_ASSERT(set_protlayer_key_by_keychain_seqno(seqno, pchain, &keyset->recv_chain, &keyset) == 1);

        ksp = keystream;

        for (p = pchain; p != NULL; p = p->next) {
            CUTE_ASSERT(memcmp(p->key, ksp, p->key_size) == 0);
            ksp += p->key_size;
        }

        kryptos_freeseg(keystream, keystream_size);
    }

    for (seqno = 0; seqno < 22; seqno++) {
        CUTE_ASSERT(set_protlayer_key_by_keychain_seqno(seqno, pchain, &keyset->send_chain, &keyset) == 0);
        CUTE_ASSERT(set_protlayer_key_by_keychain_seqno(seqno, pchain, &keyset->recv_chain, &keyset) == 0);
    }

    CUTE_ASSERT(step_bnt_keyset(&keyset,  0, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  1, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  2, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  3, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  4, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  5, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  6, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  7, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  8, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset,  9, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 10, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 11, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 12, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 13, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 14, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 15, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 16, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 17, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 18, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 19, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 20, keyset->send_chain) == 0);
    CUTE_ASSERT(step_bnt_keyset(&keyset, 21, keyset->send_chain) == 0);

    del_protlayer_chain_ctx(pchain);
    deinit_bnt_keyset(keyset);
CUTE_TEST_CASE_END
