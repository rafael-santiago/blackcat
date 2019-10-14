/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <cutest.h>
#include <test/huge_protchain.h>
#include <ctx/ctx.h>
#include <keychain/keychain.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/processor.h>
#include <keychain/kdf/kdf_utils.h>
#include <kbd/kbd.h>
#include <util/random.h>
#include <util/token.h>
#include <string.h>

CUTE_DECLARE_TEST_CASE(blackcat_base_tests_entry);
CUTE_DECLARE_TEST_CASE(ctx_tests);
CUTE_DECLARE_TEST_CASE(keychain_arg_parsing_tests);
CUTE_DECLARE_TEST_CASE(blackcat_is_dec_tests);
CUTE_DECLARE_TEST_CASE(blackcat_available_cipher_schemes_tests);
CUTE_DECLARE_TEST_CASE(blackcat_meta_processor_tests);
CUTE_DECLARE_TEST_CASE(get_hash_processor_tests);
CUTE_DECLARE_TEST_CASE(get_hash_size_tests);
CUTE_DECLARE_TEST_CASE(get_hash_input_size_tests);
CUTE_DECLARE_TEST_CASE(is_hmac_processor_tests);
CUTE_DECLARE_TEST_CASE(is_weak_hash_funcs_usage_tests);
CUTE_DECLARE_TEST_CASE(get_hash_processor_name_tests);
CUTE_DECLARE_TEST_CASE(get_hmac_catalog_scheme_tests);
CUTE_DECLARE_TEST_CASE(get_random_hmac_catalog_scheme_tests);
CUTE_DECLARE_TEST_CASE(add_composite_ciphers_to_chain_tests);
CUTE_DECLARE_TEST_CASE(get_encoder_tests);
CUTE_DECLARE_TEST_CASE(get_encoder_name_tests);
CUTE_DECLARE_TEST_CASE(get_hmac_key_size_tests);
CUTE_DECLARE_TEST_CASE(blackcat_bcrypt_tests);
CUTE_DECLARE_TEST_CASE(is_pht_tests);
CUTE_DECLARE_TEST_CASE(blackcat_getuserkey_tests);
CUTE_DECLARE_TEST_CASE(random_printable_padding_tests);
CUTE_DECLARE_TEST_CASE(blackcat_otp_meta_processor_tests);
CUTE_DECLARE_TEST_CASE(get_kdf_tests);
CUTE_DECLARE_TEST_CASE(get_kdf_name_tests);
CUTE_DECLARE_TEST_CASE(blackcat_kdf_clockwork_ctx_tests);
CUTE_DECLARE_TEST_CASE(blackcat_kdf_usr_params_get_next_tests);
CUTE_DECLARE_TEST_CASE(get_hkdf_clockwork_tests);
CUTE_DECLARE_TEST_CASE(get_pbkdf2_clockwork_tests);
CUTE_DECLARE_TEST_CASE(get_argon2i_clockwork_tests);
CUTE_DECLARE_TEST_CASE(get_kdf_clockwork_tests);
CUTE_DECLARE_TEST_CASE(get_kdf_usr_params_tests);
CUTE_DECLARE_TEST_CASE(blackcat_kdf_tests);
CUTE_DECLARE_TEST_CASE(blackcat_fmt_str_tests);
CUTE_DECLARE_TEST_CASE(token_wrap_tests);

CUTE_MAIN(blackcat_base_tests_entry)

CUTE_TEST_CASE(blackcat_base_tests_entry)
    CUTE_RUN_TEST(ctx_tests);
    CUTE_RUN_TEST(keychain_arg_parsing_tests);
    CUTE_RUN_TEST(blackcat_is_dec_tests);
    CUTE_RUN_TEST(blackcat_fmt_str_tests);
    CUTE_RUN_TEST(get_hash_processor_tests);
    CUTE_RUN_TEST(get_hash_size_tests);
    CUTE_RUN_TEST(get_hash_input_size_tests);
    CUTE_RUN_TEST(get_encoder_tests);
    CUTE_RUN_TEST(get_encoder_name_tests);
    CUTE_RUN_TEST(get_kdf_tests);
    CUTE_RUN_TEST(get_kdf_name_tests);
    CUTE_RUN_TEST(is_hmac_processor_tests);
    CUTE_RUN_TEST(get_hmac_key_size_tests);
    CUTE_RUN_TEST(is_weak_hash_funcs_usage_tests);
    CUTE_RUN_TEST(blackcat_available_cipher_schemes_tests);
    CUTE_RUN_TEST(blackcat_meta_processor_tests);
    CUTE_RUN_TEST(blackcat_otp_meta_processor_tests);
    CUTE_RUN_TEST(get_hmac_catalog_scheme_tests);
    CUTE_RUN_TEST(get_random_hmac_catalog_scheme_tests);
    CUTE_RUN_TEST(add_composite_ciphers_to_chain_tests);
    CUTE_RUN_TEST(blackcat_bcrypt_tests);
    CUTE_RUN_TEST(is_pht_tests);
    if (CUTE_GET_OPTION("skip-kbd-tests") == NULL) {
        CUTE_RUN_TEST(blackcat_getuserkey_tests);
    } else {
        printf("== WARN: blackcat_getuserkey_tests was skipped due to '--skip-kbd-tests' option.\n");
    }
    CUTE_RUN_TEST(random_printable_padding_tests);
    CUTE_RUN_TEST(blackcat_kdf_clockwork_ctx_tests);
    CUTE_RUN_TEST(blackcat_kdf_usr_params_get_next_tests);
    CUTE_RUN_TEST(get_hkdf_clockwork_tests);
    CUTE_RUN_TEST(get_pbkdf2_clockwork_tests);
    CUTE_RUN_TEST(get_argon2i_clockwork_tests);
    CUTE_RUN_TEST(get_kdf_clockwork_tests);
    CUTE_RUN_TEST(get_kdf_usr_params_tests);
    CUTE_RUN_TEST(blackcat_kdf_tests);
    CUTE_RUN_TEST(token_wrap_tests);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_otp_meta_processor_tests)
    blackcat_protlayer_chain_ctx *protlayer = NULL;
    kryptos_u8_t *pass;
    size_t pass_size = 4;
    kryptos_u8_t *in = (kryptos_u8_t *)"(null)\x00";
    size_t in_size = 7;
    size_t out_size, plain_size;
    kryptos_u8_t *out = NULL, *plain = NULL;
    struct blackcat_keychain_handle_ctx handle;
    pass = (kryptos_u8_t *)kryptos_newseg(pass_size);
    CUTE_ASSERT(pass != NULL);
    pass[0] = 0xDE;
    pass[1] = 0xAD;
    pass[2] = 0xBE;
    pass[3] = 0xEF;
    kryptos_u8_t *cascade[4];
    size_t cascade_nr = 4, c;

    cascade[0] = (kryptos_u8_t *)get_test_protlayer(1, 1);
    cascade[1] = (kryptos_u8_t *)get_test_protlayer(1, 2);
    cascade[2] = (kryptos_u8_t *)get_test_protlayer(1, 3);
    cascade[3] = (kryptos_u8_t *)get_test_protlayer(1, 4);

    CUTE_ASSERT(cascade[0] != NULL && cascade[1] != NULL && cascade[2] != NULL && cascade[3] != NULL);

    handle.hash = get_hash_processor("tiger");
    handle.kdf_clockwork = NULL;

    // INFO(Rafael): We need to ascertain the right division of the protection layer in order to encrypt
    //               the cryptogram and its one-time pad key. Thus we will test protection layers of different sizes.
    //               If someone screwed it up this test will let we know.

    for (c = 0; c < cascade_nr; c++) {
        protlayer = add_composite_protlayer_to_chain(protlayer, (char *)cascade[c],
                                                     &pass, &pass_size, &handle, NULL);
        CUTE_ASSERT(protlayer != NULL);
        out = blackcat_otp_encrypt_data(protlayer, in, in_size, &out_size);
        CUTE_ASSERT(out != NULL);
        plain = blackcat_otp_decrypt_data(protlayer, out, out_size, &plain_size);
        CUTE_ASSERT(plain != NULL);
        CUTE_ASSERT(plain_size == in_size);
        CUTE_ASSERT(memcmp(plain, in, plain_size) == 0);
        kryptos_freeseg(out, out_size);
        kryptos_freeseg(plain, plain_size);
        del_protlayer_chain_ctx(protlayer);
        protlayer = NULL;
    }

    free(cascade[0]);
    free(cascade[1]);
    free(cascade[2]);
    free(cascade[3]);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(random_printable_padding_tests)
    kryptos_u8_t *pad;
    size_t t, curr_size;
    for (t = 0; t < 10; t++) {
        CUTE_ASSERT((pad = random_printable_padding(&curr_size)) != NULL);
        kryptos_freeseg(pad, curr_size);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_getuserkey_tests)
    size_t password_size;
    kryptos_u8_t *password;
    kryptos_u8_t *expected = (kryptos_u8_t *)"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                             "\xDE\xAD\xBE\xEF\x00\x00\x01";
    // INFO(Rafael): This statement is pretty important to avoid a 4kb 'leak' done by stdio.
    setbuf(stdin, NULL);
    password = blackcat_getuserkey(&password_size);
    CUTE_ASSERT(password != NULL);
    CUTE_ASSERT(password_size == 69);
    CUTE_ASSERT(memcmp(password, expected, password_size) == 0);
    kryptos_freeseg(password, password_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(is_pht_tests)
    struct test_ctx {
        blackcat_hash_processor p;
        int is;
    };
    struct test_ctx test[] = {
        { kryptos_sha224_hash,     0 },
        { kryptos_sha256_hash,     0 },
        { kryptos_sha384_hash,     0 },
        { kryptos_sha512_hash,     0 },
        { kryptos_sha3_224_hash,   0 },
        { kryptos_sha3_256_hash,   0 },
        { kryptos_sha3_384_hash,   0 },
        { kryptos_sha3_512_hash,   0 },
        { kryptos_tiger_hash,      0 },
        { kryptos_whirlpool_hash,  0 },
        { kryptos_blake2s256_hash, 0 },
        { kryptos_blake2b512_hash, 0 },
        { blackcat_bcrypt,         1 },
        { NULL,                    0 }
    };
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        CUTE_ASSERT(is_pht(test[t].p) == test[t].is);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_bcrypt_tests)
    kryptos_task_ctx t, *ktask = &t;
    int cost;
    kryptos_u8_t *password = (kryptos_u8_t *)"wabba labba dub dub!";
    size_t password_size = 20, wrong_password_size;

    kryptos_task_init_as_null(ktask);

    blackcat_bcrypt(NULL, 0);
    blackcat_bcrypt(&ktask, 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in = password;
    ktask->in_size = password_size;
    cost = 8;

    ktask->arg[0] = &cost;
    blackcat_bcrypt(&ktask, 0);

    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    ktask->in = ktask->out;
    ktask->in_size = ktask->out_size;
    ktask->arg[0] = "wabba lab -- Burp! -- ba dub dub!\x00";
    wrong_password_size = strlen(ktask->arg[0]);
    ktask->arg[1] = &wrong_password_size;

    blackcat_bcrypt(&ktask, 1);

    CUTE_ASSERT(ktask->result == kKryptosProcessError);
    ktask->arg[0] = password;
    ktask->arg[1] = &password_size;
    blackcat_bcrypt(&ktask, 1);

    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    kryptos_task_free(ktask, KRYPTOS_TASK_IN);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_encoder_name_tests)
    struct get_encoder_name_test_ctx {
        blackcat_encoder encoder;
        const char *name;
    };
    struct get_encoder_name_test_ctx test_vect[] = {
        { blackcat_uuencode, "uuencode"                                            },
        { blackcat_base64,   "base64"                                              },
        { NULL,              "uh-uh-it-is-all-the-same-no-matter-where-you-are..." },
        { NULL,              "he-said-but-he-was-wrong"                            },
        { NULL,              NULL                                                  }
    };
    size_t test_vect_nr = sizeof(test_vect) / sizeof(test_vect[0]), t;

    for (t = 0; t < test_vect_nr; t++) {
        if (test_vect[t].encoder != NULL) {
            CUTE_ASSERT(strcmp(get_encoder_name(test_vect[t].encoder), test_vect[t].name) == 0);
        } else {
            CUTE_ASSERT(get_encoder_name(test_vect[t].encoder) == NULL);
        }
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_encoder_tests)
    struct get_encoder_test_ctx {
        const char *name;
        blackcat_encoder encoder;
    };
    struct get_encoder_test_ctx test_vect[] = {
        { "base64",        blackcat_base64    },
        { "uuencode",      blackcat_uuencode  },
        { "BeastOfBurden", NULL               },
        { NULL,            NULL               }
    };
    size_t test_vect_nr = sizeof(test_vect) / sizeof(test_vect[0]), t;

    for (t = 0; t < test_vect_nr; t++) {
        CUTE_ASSERT(get_encoder(test_vect[t].name) == test_vect[t].encoder);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(add_composite_ciphers_to_chain_tests)
    blackcat_protlayer_chain_ctx *chain = NULL;
    struct blackcat_keychain_handle_ctx handle;
    kryptos_u8_t *key = NULL;
    size_t key_size = 0;

    handle.hash = get_hash_processor("tiger");
    handle.kdf_clockwork = NULL;

    CUTE_ASSERT(add_composite_protlayer_to_chain(chain, NULL, &key, &key_size, &handle, NULL) == NULL);
    CUTE_ASSERT(add_composite_protlayer_to_chain(chain, "", NULL, &key_size, &handle, NULL) == NULL);
    CUTE_ASSERT(add_composite_protlayer_to_chain(chain, "", &key, NULL, &handle, NULL) == NULL);
    CUTE_ASSERT(add_composite_protlayer_to_chain(chain, "", &key, &key_size, NULL, NULL) == NULL);

    key = (kryptos_u8_t *) malloc(4);
    CUTE_ASSERT(key != NULL);
    memcpy(key, "test", 4);
    key_size = 4;

    chain = add_composite_protlayer_to_chain(chain, "hmac-cha3-512-bug-a-loo-cipher-cbc",
                                             &key, &key_size, &handle, get_encoder("uuencode"));

    CUTE_ASSERT(chain == NULL);
    CUTE_ASSERT(key == NULL);
    CUTE_ASSERT(key_size == 0);

    key = (kryptos_u8_t *) malloc(4);
    CUTE_ASSERT(key != NULL);
    memcpy(key, "test", 4);
    key_size = 4;

    chain = add_composite_protlayer_to_chain(chain, "hmac-sha3-512-des-cbc,aes-128-ofb,shacal2-ctr|feal-cbc/167,"
                                                    "hmac-cha3-512-bug-a-loo-cipher-cbc",
                                             &key, &key_size, &handle, get_encoder("base64"));

    CUTE_ASSERT(chain == NULL);
    CUTE_ASSERT(key == NULL);
    CUTE_ASSERT(key_size == 0);

    key = (kryptos_u8_t *) malloc(4);
    CUTE_ASSERT(key != NULL);
    memcpy(key, "test", 4);
    key_size = 4;

    chain = add_composite_protlayer_to_chain(chain, get_test_protlayer(0, 1), &key, &key_size, &handle, NULL);

    CUTE_ASSERT(chain != NULL);
    CUTE_ASSERT(chain->next == NULL);

    CUTE_ASSERT(key == NULL);
    CUTE_ASSERT(key_size == 0);

    del_protlayer_chain_ctx(chain);

    key = (kryptos_u8_t *) malloc(4);
    CUTE_ASSERT(key != NULL);
    memcpy(key, "test", 4);
    key_size = 4;

    chain = NULL;
    chain = add_composite_protlayer_to_chain(chain,
                                             get_test_protlayer(0, 4),
                                             &key, &key_size, &handle, NULL);

    CUTE_ASSERT(chain != NULL);

    CUTE_ASSERT(chain->next != NULL);
    CUTE_ASSERT(chain->next->next != NULL);
    CUTE_ASSERT(chain->next->next->next != NULL);
    CUTE_ASSERT(chain->next->next->next->next == NULL);

    CUTE_ASSERT(key == NULL);
    CUTE_ASSERT(key_size == 0);

    del_protlayer_chain_ctx(chain);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_hmac_catalog_scheme_tests)
    size_t h;
    const struct blackcat_hmac_catalog_algorithms_ctx *hc;

    CUTE_ASSERT(get_hmac_catalog_scheme("hmac-bug-a-loo64") == NULL);

    for (h = 0; h < hmac_schemes_nr; h++) {
        hc = get_hmac_catalog_scheme(hmac_schemes[h]);
        CUTE_ASSERT(hc != NULL);
        CUTE_ASSERT(is_hmac_processor(hc->processor) == 1);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_random_hmac_catalog_scheme_tests)
    CUTE_ASSERT(get_random_hmac_catalog_scheme() != NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_hash_processor_name_tests)
    struct test_ctx {
        blackcat_hash_processor p;
        const char *n;
    };
    struct test_ctx test[] = {
        { kryptos_sha224_hash,     "sha224"       },
        { kryptos_sha256_hash,     "sha256"       },
        { kryptos_sha384_hash,     "sha384"       },
        { kryptos_sha512_hash,     "sha512"       },
        { kryptos_sha3_224_hash,   "sha3-224"     },
        { kryptos_sha3_256_hash,   "sha3-256"     },
        { kryptos_sha3_384_hash,   "sha3-384"     },
        { kryptos_sha3_512_hash,   "sha3-512"     },
        { kryptos_tiger_hash,      "tiger"        },
        { kryptos_whirlpool_hash,  "whirlpool"    },
        { blackcat_bcrypt,         "bcrypt"       },
        { kryptos_blake2s256_hash, "blake2s256"   },
        { kryptos_blake2b512_hash, "blake2b512"   },
        { NULL,                     NULL          },
        { (blackcat_hash_processor)&test[0], NULL }
    };
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        if (test[t].n == NULL) {
            CUTE_ASSERT(get_hash_processor_name(test[t].p) == NULL);
        } else {
            CUTE_ASSERT(strcmp(get_hash_processor_name(test[t].p), test[t].n) == 0);
        }
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(is_weak_hash_funcs_usage_tests)
    struct test_ctx {
        blackcat_hash_processor h1, h2;
        int is;
    };
#define add_test_step(hash_1, hash_2, w) { kryptos_ ## hash_1 ## _hash, kryptos_ ## hash_2 ## _hash, w }
    struct test_ctx test[] = {
        add_test_step(sha224, sha224, 1),
        add_test_step(sha256, sha256, 1),
        add_test_step(sha384, sha384, 1),
        add_test_step(sha512, sha512, 1),
        add_test_step(sha224, sha256, 1),
        add_test_step(sha256, sha224, 1),
        add_test_step(sha384, sha512, 1),
        add_test_step(sha512, sha384, 1),
        add_test_step(sha3_224, sha3_224, 1),
        add_test_step(sha3_256, sha3_256, 1),
        add_test_step(sha3_384, sha3_384, 1),
        add_test_step(sha3_512, sha3_512, 1),
        add_test_step(sha3_224, sha3_256, 1),
        add_test_step(sha3_224, sha3_384, 1),
        add_test_step(sha3_224, sha3_512, 1),
        add_test_step(sha3_256, sha3_224, 1),
        add_test_step(sha3_256, sha3_384, 1),
        add_test_step(sha3_256, sha3_512, 1),
        add_test_step(sha3_384, sha3_224, 1),
        add_test_step(sha3_384, sha3_256, 1),
        add_test_step(sha3_384, sha3_512, 1),
        add_test_step(sha3_512, sha3_224, 1),
        add_test_step(sha3_512, sha3_256, 1),
        add_test_step(sha3_512, sha3_384, 1),
        add_test_step(tiger, tiger, 1),
        add_test_step(whirlpool, whirlpool, 1),
        add_test_step(sha224, sha3_224, 0),
        add_test_step(whirlpool, sha512, 0),
        add_test_step(tiger, sha3_384, 0),
        add_test_step(blake2s256, blake2s256, 1),
        add_test_step(blake2b512, blake2b512, 1)
    };
#undef add_test_step
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        CUTE_ASSERT(is_weak_hash_funcs_usage(test[t].h1, test[t].h2) == test[t].is);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_hash_processor_tests)
    struct test_ctx {
        const char *hash;
        blackcat_hash_processor processor;
    };
    struct test_ctx test[] = {
        { "sha-224",     kryptos_sha224_hash     },
        { "sha-256",     kryptos_sha256_hash     },
        { "sha-384",     kryptos_sha384_hash     },
        { "sha-512",     kryptos_sha512_hash     },
        { "sha3-224",    kryptos_sha3_224_hash   },
        { "sha3-256",    kryptos_sha3_256_hash   },
        { "sha3-384",    kryptos_sha3_384_hash   },
        { "sha3-512",    kryptos_sha3_512_hash   },
        { "tiger",       kryptos_tiger_hash      },
        { "whirlpool",   kryptos_whirlpool_hash  },
        { "bcrypt",      blackcat_bcrypt         },
        { "blake2s-256", kryptos_blake2s256_hash },
        { "blake2b-512", kryptos_blake2b512_hash },
        { "bug-a-loo",   NULL                    },
        { "sha3_224",    NULL                    },
        { "sha3_256",    NULL                    },
        { "sha3_384",    NULL                    },
        { "sha3_512",    NULL                    }
    };
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        CUTE_ASSERT(get_hash_processor(test[t].hash) == test[t].processor);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_hash_size_tests)
    struct test_ctx {
        const char *hash;
        blackcat_hash_size_func size;
    };
    struct test_ctx test[] = {
        { "sha-224",     kryptos_sha224_hash_size     },
        { "sha-256",     kryptos_sha256_hash_size     },
        { "sha-384",     kryptos_sha384_hash_size     },
        { "sha-512",     kryptos_sha512_hash_size     },
        { "sha3-224",    kryptos_sha3_224_hash_size   },
        { "sha3-256",    kryptos_sha3_256_hash_size   },
        { "sha3-384",    kryptos_sha3_384_hash_size   },
        { "sha3-512",    kryptos_sha3_512_hash_size   },
        { "tiger",       kryptos_tiger_hash_size      },
        { "whirlpool",   kryptos_whirlpool_hash_size  },
        { "bcrypt",      blackcat_bcrypt_size         },
        { "blake2s-256", kryptos_blake2s256_hash_size },
        { "blake2b-512", kryptos_blake2b512_hash_size },
        { "bug-a-loo",   NULL                         },
        { "sha3_224",    NULL                         },
        { "sha3_256",    NULL                         },
        { "sha3_384",    NULL                         },
        { "sha3_512",    NULL                         }
    };
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        CUTE_ASSERT(get_hash_size(test[t].hash) == test[t].size);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_hash_input_size_tests)
    struct test_ctx {
        const char *hash;
        blackcat_hash_size_func size;
    };
    struct test_ctx test[] = {
        { "sha-224",     kryptos_sha224_hash_input_size     },
        { "sha-256",     kryptos_sha256_hash_input_size     },
        { "sha-384",     kryptos_sha384_hash_input_size     },
        { "sha-512",     kryptos_sha512_hash_input_size     },
        { "sha3-224",    kryptos_sha3_224_hash_input_size   },
        { "sha3-256",    kryptos_sha3_256_hash_input_size   },
        { "sha3-384",    kryptos_sha3_384_hash_input_size   },
        { "sha3-512",    kryptos_sha3_512_hash_input_size   },
        { "tiger",       kryptos_tiger_hash_input_size      },
        { "whirlpool",   kryptos_whirlpool_hash_input_size  },
        { "bcrypt",      blackcat_bcrypt_input_size         },
        { "blake2s-256", kryptos_blake2s256_hash_input_size },
        { "blake2b-512", kryptos_blake2b512_hash_input_size },
        { "bug-a-loo",   NULL                               },
        { "sha3_224",    NULL                               },
        { "sha3_256",    NULL                               },
        { "sha3_384",    NULL                               },
        { "sha3_512",    NULL                               }
    };
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        CUTE_ASSERT(get_hash_input_size(test[t].hash) == test[t].size);
    }
CUTE_TEST_CASE_END


CUTE_TEST_CASE(get_hmac_key_size_tests)
    struct test_ctx {
        blackcat_cipher_processor processor;
        size_t key_size;
    };
#define add_test_step(c, k) { blackcat_ ## c, k }
    struct test_ctx test[] = {
#if defined(BLACKCAT_WITH_AES)
        add_test_step(aes128, 0),
        add_test_step(aes192, 0),
        add_test_step(aes256, 0),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(des, 0),
        add_test_step(triple_des, 0),
        add_test_step(triple_des_ede, 0),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(idea, 0),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(rc2, 0),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(rc5, 0),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(rc6_128, 0),
        add_test_step(rc6_192, 0),
        add_test_step(rc6_256, 0),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(feal, 0),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(cast5, 0),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(camellia128, 0),
        add_test_step(camellia192, 0),
        add_test_step(camellia256, 0),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(saferk64, 0),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(blowfish, 0),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(serpent, 0),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(tea, 0),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(xtea, 0),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(misty1, 0),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(mars128, 0),
        add_test_step(mars192, 0),
        add_test_step(mars256, 0),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(present80, 0),
        add_test_step(present128, 0),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(shacal1, 0),
        add_test_step(shacal2, 0),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(noekeon, 0),
        add_test_step(noekeon_d, 0),
#endif
        add_test_step(gibberish_wrap, 0),
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha224_aes128, 16),
        add_test_step(hmac_sha224_aes192, 24),
        add_test_step(hmac_sha224_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha224_des, 8),
        add_test_step(hmac_sha224_triple_des, 24),
        add_test_step(hmac_sha224_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha224_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha224_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha224_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha224_rc6_128, 16),
        add_test_step(hmac_sha224_rc6_192, 24),
        add_test_step(hmac_sha224_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha224_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha224_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha224_camellia128, 16),
        add_test_step(hmac_sha224_camellia192, 24),
        add_test_step(hmac_sha224_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha224_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha224_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha224_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha224_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha224_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha224_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha224_mars128, 16),
        add_test_step(hmac_sha224_mars192, 24),
        add_test_step(hmac_sha224_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha224_present80, 10),
        add_test_step(hmac_sha224_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha224_shacal1, 64),
        add_test_step(hmac_sha224_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha224_noekeon, 16),
        add_test_step(hmac_sha224_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha256_aes128, 16),
        add_test_step(hmac_sha256_aes192, 24),
        add_test_step(hmac_sha256_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha256_des, 8),
        add_test_step(hmac_sha256_triple_des, 24),
        add_test_step(hmac_sha256_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha256_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha256_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha256_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha256_rc6_128, 16),
        add_test_step(hmac_sha256_rc6_192, 24),
        add_test_step(hmac_sha256_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha256_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha256_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha256_camellia128, 16),
        add_test_step(hmac_sha256_camellia192, 24),
        add_test_step(hmac_sha256_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha256_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha256_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha256_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha256_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha256_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha256_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha256_mars128, 16),
        add_test_step(hmac_sha256_mars192, 24),
        add_test_step(hmac_sha256_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha256_present80, 10),
        add_test_step(hmac_sha256_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha256_shacal1, 64),
        add_test_step(hmac_sha256_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha256_noekeon, 16),
        add_test_step(hmac_sha256_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha384_aes128, 16),
        add_test_step(hmac_sha384_aes192, 24),
        add_test_step(hmac_sha384_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha384_des, 8),
        add_test_step(hmac_sha384_triple_des, 24),
        add_test_step(hmac_sha384_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha384_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha384_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha384_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha384_rc6_128, 16),
        add_test_step(hmac_sha384_rc6_192, 24),
        add_test_step(hmac_sha384_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha384_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha384_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha384_camellia128, 16),
        add_test_step(hmac_sha384_camellia192, 24),
        add_test_step(hmac_sha384_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha384_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha384_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha384_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha384_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha384_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha384_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha384_mars128, 16),
        add_test_step(hmac_sha384_mars192, 24),
        add_test_step(hmac_sha384_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha384_present80, 10),
        add_test_step(hmac_sha384_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha384_shacal1, 64),
        add_test_step(hmac_sha384_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha384_noekeon, 16),
        add_test_step(hmac_sha384_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha512_aes128, 16),
        add_test_step(hmac_sha512_aes192, 24),
        add_test_step(hmac_sha512_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha512_des, 8),
        add_test_step(hmac_sha512_triple_des, 24),
        add_test_step(hmac_sha512_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha512_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha512_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha512_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha512_rc6_128, 16),
        add_test_step(hmac_sha512_rc6_192, 24),
        add_test_step(hmac_sha512_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha512_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha512_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha512_camellia128, 16),
        add_test_step(hmac_sha512_camellia192, 24),
        add_test_step(hmac_sha512_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha512_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha512_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha512_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha512_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha512_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha512_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha512_mars128, 16),
        add_test_step(hmac_sha512_mars192, 24),
        add_test_step(hmac_sha512_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha512_present80, 10),
        add_test_step(hmac_sha512_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha512_shacal1, 64),
        add_test_step(hmac_sha512_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha512_noekeon, 16),
        add_test_step(hmac_sha512_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_224_aes128, 16),
        add_test_step(hmac_sha3_224_aes192, 24),
        add_test_step(hmac_sha3_224_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha3_224_des, 8),
        add_test_step(hmac_sha3_224_triple_des, 24),
        add_test_step(hmac_sha3_224_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_224_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_224_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_224_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_224_rc6_128, 16),
        add_test_step(hmac_sha3_224_rc6_192, 24),
        add_test_step(hmac_sha3_224_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha3_224_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_224_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_224_camellia128, 16),
        add_test_step(hmac_sha3_224_camellia192, 24),
        add_test_step(hmac_sha3_224_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_224_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_224_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_224_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_224_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_224_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_224_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_224_mars128, 16),
        add_test_step(hmac_sha3_224_mars192, 24),
        add_test_step(hmac_sha3_224_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_224_present80, 10),
        add_test_step(hmac_sha3_224_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_224_shacal1, 64),
        add_test_step(hmac_sha3_224_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_224_noekeon, 16),
        add_test_step(hmac_sha3_224_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_256_aes128, 16),
        add_test_step(hmac_sha3_256_aes192, 24),
        add_test_step(hmac_sha3_256_aes256, 32),
#endif
#if defined(BLACKAT_WITH_DES)
        add_test_step(hmac_sha3_256_des, 8),
        add_test_step(hmac_sha3_256_triple_des, 24),
        add_test_step(hmac_sha3_256_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_256_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_256_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_256_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_256_rc6_128, 16),
        add_test_step(hmac_sha3_256_rc6_192, 24),
        add_test_step(hmac_sha3_256_rc6_256, 32),
#endif
#if defined(BLACKAT_WITH_FEAL)
        add_test_step(hmac_sha3_256_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_256_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_256_camellia128, 16),
        add_test_step(hmac_sha3_256_camellia192, 24),
        add_test_step(hmac_sha3_256_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_256_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_256_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_256_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_256_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_256_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_256_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_256_mars128, 16),
        add_test_step(hmac_sha3_256_mars192, 24),
        add_test_step(hmac_sha3_256_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_256_present80, 10),
        add_test_step(hmac_sha3_256_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_256_shacal1, 64),
        add_test_step(hmac_sha3_256_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_256_noekeon, 16),
        add_test_step(hmac_sha3_256_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_384_aes128, 16),
        add_test_step(hmac_sha3_384_aes192, 24),
        add_test_step(hmac_sha3_384_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha3_384_des, 8),
        add_test_step(hmac_sha3_384_triple_des, 24),
        add_test_step(hmac_sha3_384_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_384_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_384_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_384_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_384_rc6_128, 16),
        add_test_step(hmac_sha3_384_rc6_192, 24),
        add_test_step(hmac_sha3_384_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha3_384_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_384_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_384_camellia128, 16),
        add_test_step(hmac_sha3_384_camellia192, 24),
        add_test_step(hmac_sha3_384_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_384_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_384_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_384_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_384_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_384_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_384_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_384_mars128, 16),
        add_test_step(hmac_sha3_384_mars192, 24),
        add_test_step(hmac_sha3_384_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_384_present80, 10),
        add_test_step(hmac_sha3_384_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_384_shacal1, 64),
        add_test_step(hmac_sha3_384_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_384_noekeon, 16),
        add_test_step(hmac_sha3_384_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_512_aes128, 16),
        add_test_step(hmac_sha3_512_aes192, 24),
        add_test_step(hmac_sha3_512_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha3_512_des, 8),
        add_test_step(hmac_sha3_512_triple_des, 24),
        add_test_step(hmac_sha3_512_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_512_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_512_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_512_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_512_rc6_128, 16),
        add_test_step(hmac_sha3_512_rc6_192, 24),
        add_test_step(hmac_sha3_512_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha3_512_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_512_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_512_camellia128, 16),
        add_test_step(hmac_sha3_512_camellia192, 24),
        add_test_step(hmac_sha3_512_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_512_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_512_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_512_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_512_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_512_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_512_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_512_mars128, 16),
        add_test_step(hmac_sha3_512_mars192, 24),
        add_test_step(hmac_sha3_512_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_512_present80, 10),
        add_test_step(hmac_sha3_512_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_512_shacal1, 64),
        add_test_step(hmac_sha3_512_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_512_noekeon, 16),
        add_test_step(hmac_sha3_512_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_tiger_aes128, 16),
        add_test_step(hmac_tiger_aes192, 24),
        add_test_step(hmac_tiger_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_tiger_des, 8),
        add_test_step(hmac_tiger_triple_des, 24),
        add_test_step(hmac_tiger_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_tiger_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_tiger_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_tiger_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_tiger_rc6_128, 16),
        add_test_step(hmac_tiger_rc6_192, 24),
        add_test_step(hmac_tiger_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_tiger_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_tiger_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_tiger_camellia128, 16),
        add_test_step(hmac_tiger_camellia192, 24),
        add_test_step(hmac_tiger_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_tiger_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_tiger_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_tiger_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_tiger_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_tiger_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_tiger_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_tiger_mars128, 16),
        add_test_step(hmac_tiger_mars192, 24),
        add_test_step(hmac_tiger_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_tiger_present80, 10),
        add_test_step(hmac_tiger_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_tiger_shacal1, 64),
        add_test_step(hmac_tiger_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_tiger_noekeon, 16),
        add_test_step(hmac_tiger_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_whirlpool_aes128, 16),
        add_test_step(hmac_whirlpool_aes192, 24),
        add_test_step(hmac_whirlpool_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_whirlpool_des, 8),
        add_test_step(hmac_whirlpool_triple_des, 24),
        add_test_step(hmac_whirlpool_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_whirlpool_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_whirlpool_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_whirlpool_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_whirlpool_rc6_128, 16),
        add_test_step(hmac_whirlpool_rc6_192, 24),
        add_test_step(hmac_whirlpool_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_whirlpool_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_whirlpool_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_whirlpool_camellia128, 16),
        add_test_step(hmac_whirlpool_camellia192, 24),
        add_test_step(hmac_whirlpool_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_whirlpool_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_whirlpool_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_whirlpool_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_whirlpool_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_whirlpool_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_whirlpool_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_whirlpool_mars128, 16),
        add_test_step(hmac_whirlpool_mars192, 24),
        add_test_step(hmac_whirlpool_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_whirlpool_present80, 10),
        add_test_step(hmac_whirlpool_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_whirlpool_shacal1, 64),
        add_test_step(hmac_whirlpool_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_whirlpool_noekeon, 16),
        add_test_step(hmac_whirlpool_noekeon_d, 16),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_blake2s256_aes128, 16),
        add_test_step(hmac_blake2s256_aes192, 24),
        add_test_step(hmac_blake2s256_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_blake2s256_des, 8),
        add_test_step(hmac_blake2s256_triple_des, 24),
        add_test_step(hmac_blake2s256_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_blake2s256_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_blake2s256_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_blake2s256_rc5, 64),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_blake2s256_rc6_128, 16),
        add_test_step(hmac_blake2s256_rc6_192, 24),
        add_test_step(hmac_blake2s256_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_blake2s256_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_blake2s256_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_blake2s256_camellia128, 16),
        add_test_step(hmac_blake2s256_camellia192, 24),
        add_test_step(hmac_blake2s256_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_blake2s256_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_blake2s256_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_blake2s256_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_blake2s256_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_blake2s256_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_blake2s256_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_blake2s256_mars128, 16),
        add_test_step(hmac_blake2s256_mars192, 24),
        add_test_step(hmac_blake2s256_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_blake2s256_present80, 10),
        add_test_step(hmac_blake2s256_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_blake2s256_shacal1, 64),
        add_test_step(hmac_blake2s256_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_blake2s256_noekeon, 16),
        add_test_step(hmac_blake2s256_noekeon_d, 16),
#endif
#if defined(BLACKAT_WITH_AES)
        add_test_step(hmac_blake2b512_aes128, 16),
        add_test_step(hmac_blake2b512_aes192, 24),
        add_test_step(hmac_blake2b512_aes256, 32),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_blake2b512_des, 8),
        add_test_step(hmac_blake2b512_triple_des, 24),
        add_test_step(hmac_blake2b512_triple_des_ede, 24),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_blake2b512_idea, 16),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_blake2b512_rc2, 128),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_blake2b512_rc5, 64),
#endif
#if defined(BLACKAT_WITH_RC6)
        add_test_step(hmac_blake2b512_rc6_128, 16),
        add_test_step(hmac_blake2b512_rc6_192, 24),
        add_test_step(hmac_blake2b512_rc6_256, 32),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_blake2b512_feal, 8),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_blake2b512_cast5, 16),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_blake2b512_camellia128, 16),
        add_test_step(hmac_blake2b512_camellia192, 24),
        add_test_step(hmac_blake2b512_camellia256, 32),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_blake2b512_saferk64, 8),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_blake2b512_blowfish, 56),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_blake2b512_serpent, 32),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_blake2b512_tea, 16),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_blake2b512_xtea, 16),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_blake2b512_misty1, 16),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_blake2b512_mars128, 16),
        add_test_step(hmac_blake2b512_mars192, 24),
        add_test_step(hmac_blake2b512_mars256, 32),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_blake2b512_present80, 10),
        add_test_step(hmac_blake2b512_present128, 16),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_blake2b512_shacal1, 64),
        add_test_step(hmac_blake2b512_shacal2, 64),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_blake2b512_noekeon, 16),
        add_test_step(hmac_blake2b512_noekeon_d, 16)
#endif
    };
#undef add_test_step
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        CUTE_ASSERT(get_hmac_key_size(test[t].processor) == test[t].key_size);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(is_hmac_processor_tests)
    struct test_ctx {
        blackcat_cipher_processor processor;
        const int is;
    };
#define add_test_step(c, i) { blackcat_ ## c, i }

    struct test_ctx test[] = {
#if defined(BLACKCAT_WITH_AES)
        add_test_step(aes128, 0),
        add_test_step(aes192, 0),
        add_test_step(aes256, 0),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(des, 0),
        add_test_step(triple_des, 0),
        add_test_step(triple_des_ede, 0),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(idea, 0),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(rc2, 0),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(rc5, 0),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(rc6_128, 0),
        add_test_step(rc6_192, 0),
        add_test_step(rc6_256, 0),
#endif
#if defined(BLACKAT_WITH_FEAL)
        add_test_step(feal, 0),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(cast5, 0),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(camellia128, 0),
        add_test_step(camellia192, 0),
        add_test_step(camellia256, 0),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(saferk64, 0),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(blowfish, 0),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(serpent, 0),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(tea, 0),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(xtea, 0),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(misty1, 0),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(mars128, 0),
        add_test_step(mars192, 0),
        add_test_step(mars256, 0),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(present80, 0),
        add_test_step(present128, 0),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(shacal1, 0),
        add_test_step(shacal2, 0),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(noekeon, 0),
        add_test_step(noekeon_d, 0),
#endif
        add_test_step(gibberish_wrap, 0),
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha224_aes128, 1),
        add_test_step(hmac_sha224_aes192, 1),
        add_test_step(hmac_sha224_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha224_des, 1),
        add_test_step(hmac_sha224_triple_des, 1),
        add_test_step(hmac_sha224_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha224_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha224_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha224_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha224_rc6_128, 1),
        add_test_step(hmac_sha224_rc6_192, 1),
        add_test_step(hmac_sha224_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha224_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha224_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha224_camellia128, 1),
        add_test_step(hmac_sha224_camellia192, 1),
        add_test_step(hmac_sha224_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha224_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha224_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha224_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha224_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha224_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha224_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha224_mars128, 1),
        add_test_step(hmac_sha224_mars192, 1),
        add_test_step(hmac_sha224_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha224_present80, 1),
        add_test_step(hmac_sha224_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha224_shacal1, 1),
        add_test_step(hmac_sha224_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha224_noekeon, 1),
        add_test_step(hmac_sha224_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha256_aes128, 1),
        add_test_step(hmac_sha256_aes192, 1),
        add_test_step(hmac_sha256_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha256_des, 1),
        add_test_step(hmac_sha256_triple_des, 1),
        add_test_step(hmac_sha256_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha256_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha256_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha256_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha256_rc6_128, 1),
        add_test_step(hmac_sha256_rc6_192, 1),
        add_test_step(hmac_sha256_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha256_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha256_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha256_camellia128, 1),
        add_test_step(hmac_sha256_camellia192, 1),
        add_test_step(hmac_sha256_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha256_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha256_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha256_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha256_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha256_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha256_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha256_mars128, 1),
        add_test_step(hmac_sha256_mars192, 1),
        add_test_step(hmac_sha256_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha256_present80, 1),
        add_test_step(hmac_sha256_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha256_shacal1, 1),
        add_test_step(hmac_sha256_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha256_noekeon, 1),
        add_test_step(hmac_sha256_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha384_aes128, 1),
        add_test_step(hmac_sha384_aes192, 1),
        add_test_step(hmac_sha384_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha384_des, 1),
        add_test_step(hmac_sha384_triple_des, 1),
        add_test_step(hmac_sha384_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha384_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha384_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha384_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha384_rc6_128, 1),
        add_test_step(hmac_sha384_rc6_192, 1),
        add_test_step(hmac_sha384_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha384_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha384_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha384_camellia128, 1),
        add_test_step(hmac_sha384_camellia192, 1),
        add_test_step(hmac_sha384_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha384_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha384_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha384_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha384_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha384_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha384_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha384_mars128, 1),
        add_test_step(hmac_sha384_mars192, 1),
        add_test_step(hmac_sha384_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha384_present80, 1),
        add_test_step(hmac_sha384_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha384_shacal1, 1),
        add_test_step(hmac_sha384_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha384_noekeon, 1),
        add_test_step(hmac_sha384_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha512_aes128, 1),
        add_test_step(hmac_sha512_aes192, 1),
        add_test_step(hmac_sha512_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha512_des, 1),
        add_test_step(hmac_sha512_triple_des, 1),
        add_test_step(hmac_sha512_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha512_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha512_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha512_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha512_rc6_128, 1),
        add_test_step(hmac_sha512_rc6_192, 1),
        add_test_step(hmac_sha512_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha512_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha512_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha512_camellia128, 1),
        add_test_step(hmac_sha512_camellia192, 1),
        add_test_step(hmac_sha512_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha512_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha512_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha512_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha512_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha512_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha512_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha512_mars128, 1),
        add_test_step(hmac_sha512_mars192, 1),
        add_test_step(hmac_sha512_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha512_present80, 1),
        add_test_step(hmac_sha512_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha512_shacal1, 1),
        add_test_step(hmac_sha512_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha512_noekeon, 1),
        add_test_step(hmac_sha512_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_224_aes128, 1),
        add_test_step(hmac_sha3_224_aes192, 1),
        add_test_step(hmac_sha3_224_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha3_224_des, 1),
        add_test_step(hmac_sha3_224_triple_des, 1),
        add_test_step(hmac_sha3_224_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_224_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_224_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_224_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_224_rc6_128, 1),
        add_test_step(hmac_sha3_224_rc6_192, 1),
        add_test_step(hmac_sha3_224_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha3_224_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_224_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_224_camellia128, 1),
        add_test_step(hmac_sha3_224_camellia192, 1),
        add_test_step(hmac_sha3_224_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_224_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_224_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_224_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_224_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_224_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_224_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_224_mars128, 1),
        add_test_step(hmac_sha3_224_mars192, 1),
        add_test_step(hmac_sha3_224_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_224_present80, 1),
        add_test_step(hmac_sha3_224_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_224_shacal1, 1),
        add_test_step(hmac_sha3_224_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_224_noekeon, 1),
        add_test_step(hmac_sha3_224_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_256_aes128, 1),
        add_test_step(hmac_sha3_256_aes192, 1),
        add_test_step(hmac_sha3_256_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha3_256_des, 1),
        add_test_step(hmac_sha3_256_triple_des, 1),
        add_test_step(hmac_sha3_256_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_256_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_256_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_256_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_256_rc6_128, 1),
        add_test_step(hmac_sha3_256_rc6_192, 1),
        add_test_step(hmac_sha3_256_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha3_256_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_256_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_256_camellia128, 1),
        add_test_step(hmac_sha3_256_camellia192, 1),
        add_test_step(hmac_sha3_256_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_256_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_256_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_256_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_256_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_256_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_256_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_256_mars128, 1),
        add_test_step(hmac_sha3_256_mars192, 1),
        add_test_step(hmac_sha3_256_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_256_present80, 1),
        add_test_step(hmac_sha3_256_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_256_shacal1, 1),
        add_test_step(hmac_sha3_256_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_256_noekeon, 1),
        add_test_step(hmac_sha3_256_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_384_aes128, 1),
        add_test_step(hmac_sha3_384_aes192, 1),
        add_test_step(hmac_sha3_384_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha3_384_des, 1),
        add_test_step(hmac_sha3_384_triple_des, 1),
        add_test_step(hmac_sha3_384_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_384_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_384_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_384_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_384_rc6_128, 1),
        add_test_step(hmac_sha3_384_rc6_192, 1),
        add_test_step(hmac_sha3_384_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha3_384_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_384_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_384_camellia128, 1),
        add_test_step(hmac_sha3_384_camellia192, 1),
        add_test_step(hmac_sha3_384_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_384_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_384_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_384_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_384_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_384_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_384_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_384_mars128, 1),
        add_test_step(hmac_sha3_384_mars192, 1),
        add_test_step(hmac_sha3_384_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_384_present80, 1),
        add_test_step(hmac_sha3_384_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_384_shacal1, 1),
        add_test_step(hmac_sha3_384_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_384_noekeon, 1),
        add_test_step(hmac_sha3_384_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_sha3_512_aes128, 1),
        add_test_step(hmac_sha3_512_aes192, 1),
        add_test_step(hmac_sha3_512_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_sha3_512_des, 1),
        add_test_step(hmac_sha3_512_triple_des, 1),
        add_test_step(hmac_sha3_512_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_sha3_512_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_sha3_512_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_sha3_512_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_sha3_512_rc6_128, 1),
        add_test_step(hmac_sha3_512_rc6_192, 1),
        add_test_step(hmac_sha3_512_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_sha3_512_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_sha3_512_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_sha3_512_camellia128, 1),
        add_test_step(hmac_sha3_512_camellia192, 1),
        add_test_step(hmac_sha3_512_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_sha3_512_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_sha3_512_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_sha3_512_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_sha3_512_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_sha3_512_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_sha3_512_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_sha3_512_mars128, 1),
        add_test_step(hmac_sha3_512_mars192, 1),
        add_test_step(hmac_sha3_512_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_sha3_512_present80, 1),
        add_test_step(hmac_sha3_512_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_sha3_512_shacal1, 1),
        add_test_step(hmac_sha3_512_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_sha3_512_noekeon, 1),
        add_test_step(hmac_sha3_512_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_tiger_aes128, 1),
        add_test_step(hmac_tiger_aes192, 1),
        add_test_step(hmac_tiger_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_tiger_des, 1),
        add_test_step(hmac_tiger_triple_des, 1),
        add_test_step(hmac_tiger_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_tiger_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_tiger_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_tiger_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_tiger_rc6_128, 1),
        add_test_step(hmac_tiger_rc6_192, 1),
        add_test_step(hmac_tiger_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_tiger_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_tiger_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_tiger_camellia128, 1),
        add_test_step(hmac_tiger_camellia192, 1),
        add_test_step(hmac_tiger_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_tiger_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_tiger_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_tiger_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_tiger_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_tiger_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_tiger_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_tiger_mars128, 1),
        add_test_step(hmac_tiger_mars192, 1),
        add_test_step(hmac_tiger_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_tiger_present80, 1),
        add_test_step(hmac_tiger_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_tiger_shacal1, 1),
        add_test_step(hmac_tiger_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_tiger_noekeon, 1),
        add_test_step(hmac_tiger_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_whirlpool_aes128, 1),
        add_test_step(hmac_whirlpool_aes192, 1),
        add_test_step(hmac_whirlpool_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_whirlpool_des, 1),
        add_test_step(hmac_whirlpool_triple_des, 1),
        add_test_step(hmac_whirlpool_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_whirlpool_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_whirlpool_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_whirlpool_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_whirlpool_rc6_128, 1),
        add_test_step(hmac_whirlpool_rc6_192, 1),
        add_test_step(hmac_whirlpool_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_whirlpool_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_whirlpool_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_whirlpool_camellia128, 1),
        add_test_step(hmac_whirlpool_camellia192, 1),
        add_test_step(hmac_whirlpool_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_whirlpool_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_whirlpool_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_whirlpool_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_whirlpool_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_whirlpool_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_whirlpool_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_whirlpool_mars128, 1),
        add_test_step(hmac_whirlpool_mars192, 1),
        add_test_step(hmac_whirlpool_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_whirlpool_present80, 1),
        add_test_step(hmac_whirlpool_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_whirlpool_shacal1, 1),
        add_test_step(hmac_whirlpool_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_whirlpool_noekeon, 1),
        add_test_step(hmac_whirlpool_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_blake2s256_aes128, 1),
        add_test_step(hmac_blake2s256_aes192, 1),
        add_test_step(hmac_blake2s256_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_blake2s256_des, 1),
        add_test_step(hmac_blake2s256_triple_des, 1),
        add_test_step(hmac_blake2s256_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_blake2s256_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_blake2s256_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_blake2s256_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_blake2s256_rc6_128, 1),
        add_test_step(hmac_blake2s256_rc6_192, 1),
        add_test_step(hmac_blake2s256_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_blake2s256_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_blake2s256_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_blake2s256_camellia128, 1),
        add_test_step(hmac_blake2s256_camellia192, 1),
        add_test_step(hmac_blake2s256_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_blake2s256_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_blake2s256_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_blake2s256_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_blake2s256_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_blake2s256_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_blake2s256_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_blake2s256_mars128, 1),
        add_test_step(hmac_blake2s256_mars192, 1),
        add_test_step(hmac_blake2s256_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_blake2s256_present80, 1),
        add_test_step(hmac_blake2s256_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_blake2s256_shacal1, 1),
        add_test_step(hmac_blake2s256_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_blake2s256_noekeon, 1),
        add_test_step(hmac_blake2s256_noekeon_d, 1),
#endif
#if defined(BLACKCAT_WITH_AES)
        add_test_step(hmac_blake2b512_aes128, 1),
        add_test_step(hmac_blake2b512_aes192, 1),
        add_test_step(hmac_blake2b512_aes256, 1),
#endif
#if defined(BLACKCAT_WITH_DES)
        add_test_step(hmac_blake2b512_des, 1),
        add_test_step(hmac_blake2b512_triple_des, 1),
        add_test_step(hmac_blake2b512_triple_des_ede, 1),
#endif
#if defined(BLACKCAT_WITH_IDEA)
        add_test_step(hmac_blake2b512_idea, 1),
#endif
#if defined(BLACKCAT_WITH_RC2)
        add_test_step(hmac_blake2b512_rc2, 1),
#endif
#if defined(BLACKCAT_WITH_RC5)
        add_test_step(hmac_blake2b512_rc5, 1),
#endif
#if defined(BLACKCAT_WITH_RC6)
        add_test_step(hmac_blake2b512_rc6_128, 1),
        add_test_step(hmac_blake2b512_rc6_192, 1),
        add_test_step(hmac_blake2b512_rc6_256, 1),
#endif
#if defined(BLACKCAT_WITH_FEAL)
        add_test_step(hmac_blake2b512_feal, 1),
#endif
#if defined(BLACKCAT_WITH_CAST5)
        add_test_step(hmac_blake2b512_cast5, 1),
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
        add_test_step(hmac_blake2b512_camellia128, 1),
        add_test_step(hmac_blake2b512_camellia192, 1),
        add_test_step(hmac_blake2b512_camellia256, 1),
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
        add_test_step(hmac_blake2b512_saferk64, 1),
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
        add_test_step(hmac_blake2b512_blowfish, 1),
#endif
#if defined(BLACKCAT_WITH_SERPENT)
        add_test_step(hmac_blake2b512_serpent, 1),
#endif
#if defined(BLACKCAT_WITH_TEA)
        add_test_step(hmac_blake2b512_tea, 1),
#endif
#if defined(BLACKCAT_WITH_XTEA)
        add_test_step(hmac_blake2b512_xtea, 1),
#endif
#if defined(BLACKCAT_WITH_MISTY1)
        add_test_step(hmac_blake2b512_misty1, 1),
#endif
#if defined(BLACKCAT_WITH_MARS)
        add_test_step(hmac_blake2b512_mars128, 1),
        add_test_step(hmac_blake2b512_mars192, 1),
        add_test_step(hmac_blake2b512_mars256, 1),
#endif
#if defined(BLACKCAT_WITH_PRESENT)
        add_test_step(hmac_blake2b512_present80, 1),
        add_test_step(hmac_blake2b512_present128, 1),
#endif
#if defined(BLACKCAT_WITH_SHACAL)
        add_test_step(hmac_blake2b512_shacal1, 1),
        add_test_step(hmac_blake2b512_shacal2, 1),
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
        add_test_step(hmac_blake2b512_noekeon, 1),
        add_test_step(hmac_blake2b512_noekeon_d, 1)
#endif
    };
#undef add_test_step
    size_t test_nr = sizeof(test) / sizeof(test[0]), t;

    for (t = 0; t < test_nr; t++) {
        CUTE_ASSERT(is_hmac_processor(test[t].processor) == test[t].is);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_meta_processor_tests)
    blackcat_protlayer_chain_ctx *pchain = NULL;
    size_t h;
    kryptos_u8_t *in = (kryptos_u8_t *)"test", *out, *dec;
    size_t in_size = 4, out_size, dec_size;
    kryptos_u8_t *key;
    size_t key_size;
    struct blackcat_keychain_handle_ctx handle;

    handle.hash = NULL;
    handle.kdf_clockwork = NULL;

    CUTE_ASSERT(huge_protchain_sz == g_blackcat_ciphering_schemes_nr);

    key = (kryptos_u8_t *) malloc(6);
    CUTE_ASSERT(key != NULL);
    memcpy(key, "secret", 6);
    key_size = 6;

    for (h = 0; h < huge_protchain_sz; h++) {
        pchain = NULL;
        pchain = add_protlayer_to_chain(pchain, huge_protchain[h], &key, &key_size, &handle);

        out = blackcat_encrypt_data(pchain, in, in_size, &out_size);

        CUTE_ASSERT(out != NULL);
        CUTE_ASSERT(out_size != 0);

        dec = blackcat_decrypt_data(pchain, out, out_size, &dec_size);

        CUTE_ASSERT(dec != NULL);
        CUTE_ASSERT(dec_size == in_size);
        CUTE_ASSERT(memcmp(dec, in, in_size) == 0);

        free(out);
        free(dec);

        del_protlayer_chain_ctx(pchain);
    }

    free(key);

    if (CUTE_GET_OPTION("quick-tests") == NULL) {
        pchain = NULL;

        key = (kryptos_u8_t *) malloc(6);
        CUTE_ASSERT(key != NULL);
        memcpy(key, "secret", 6);
        key_size = 6;

        for (h = 0; h < huge_protchain_sz; h++) {
            pchain = add_protlayer_to_chain(pchain, huge_protchain[h], &key, &key_size, &handle);
        }

        free(key);

        out = blackcat_encrypt_data(pchain, in, in_size, &out_size);

        CUTE_ASSERT(out != NULL);
        CUTE_ASSERT(out_size != 0);

        dec = blackcat_decrypt_data(pchain, out, out_size, &dec_size);

        CUTE_ASSERT(dec != NULL);
        CUTE_ASSERT(dec_size == in_size);
        CUTE_ASSERT(memcmp(dec, in, in_size) == 0);

        free(out);
        free(dec);

        del_protlayer_chain_ctx(pchain);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_available_cipher_schemes_tests)
    ssize_t a;
    size_t h;
    blackcat_protlayer_chain_ctx *pchain;
    kryptos_u8_t *key;
    size_t key_size;
    struct blackcat_keychain_handle_ctx handle;

    handle.hash = NULL;
    handle.kdf_clockwork = NULL;

    CUTE_ASSERT(huge_protchain_sz == g_blackcat_ciphering_schemes_nr);

    key = (kryptos_u8_t *) malloc(6);
    CUTE_ASSERT(key != NULL);
    memcpy(key, "secret", 6);
    key_size = 6;

    for (h = 0; h < huge_protchain_sz; h++) {
        a = get_algo_index(huge_protchain[h]);

        CUTE_ASSERT(a > -1 && a < g_blackcat_ciphering_schemes_nr);

        pchain = NULL;
        pchain = add_protlayer_to_chain(pchain, huge_protchain[h], &key, &key_size, &handle);

        CUTE_ASSERT(pchain != NULL);

        switch (g_blackcat_ciphering_schemes[a].key_size) {
            case 0:
                CUTE_ASSERT(pchain->key == NULL);
                break;
            case -1:
                CUTE_ASSERT(pchain->key != NULL);
                CUTE_ASSERT(pchain->key_size != 6);
                break;
            default:
                CUTE_ASSERT(pchain->key != NULL);
                CUTE_ASSERT(pchain->key_size == g_blackcat_ciphering_schemes[a].key_size);
                break;
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

    free(key);
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

CUTE_TEST_CASE(ctx_tests)
    blackcat_protlayer_chain_ctx *pchain = NULL;
    kryptos_u8_t *key;
    size_t key_size;
    struct blackcat_keychain_handle_ctx handle;

    handle.hash = NULL;
    handle.kdf_clockwork = NULL;

    key = (kryptos_u8_t *) malloc(5);
    CUTE_ASSERT(key != NULL);
    memcpy(key, "clean", 5);
    key_size = 5;

    pchain = add_protlayer_to_chain(pchain, "hmac-aes-256-cbc", &key, &key_size, &handle);

    CUTE_ASSERT(pchain == NULL);

    pchain = add_protlayer_to_chain(pchain, get_test_protlayer(0, 1), &key, &key_size, NULL);

    CUTE_ASSERT(pchain == NULL);

    pchain = add_protlayer_to_chain(pchain, get_test_protlayer(0, 1), &key, &key_size, &handle);

    CUTE_ASSERT(pchain != NULL);

    CUTE_ASSERT(pchain->head == pchain);
    CUTE_ASSERT(pchain->tail == pchain);
    CUTE_ASSERT(pchain->key != NULL);
    CUTE_ASSERT(pchain->key_size != 0);
    CUTE_ASSERT(pchain->processor != NULL);
    CUTE_ASSERT(pchain->last == NULL);
    CUTE_ASSERT(pchain->next == NULL);

    pchain = add_protlayer_to_chain(pchain, get_test_protlayer(0, 1), &key, &key_size, &handle);

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
    free(key);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_kdf_tests)
    struct test_ctx {
        const char *name;
        blackcat_kdf_func func;
    } test_vector[] = {
        {  NULL,     NULL             },
        { "hkdf",    blackcat_hkdf    },
        { "pbkdf2",  blackcat_pbkdf2  },
        { "argon2i", blackcat_argon2i },
        { "ni!",     NULL             }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    size_t t;

    for (t = 0; t < test_vector_nr; t++) {
        CUTE_ASSERT(get_kdf(test_vector[t].name) == test_vector[t].func);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_kdf_name_tests)
    blackcat_kdf_func meow = NULL;
    struct test_ctx {
        blackcat_kdf_func func;
        const char *name;
    } test_vector[] = {
        { NULL,                           NULL      },
        { blackcat_hkdf,                  "hkdf"    },
        { blackcat_pbkdf2,                "pbkdf2"  },
        { blackcat_argon2i,               "argon2i" },
        { meow,                           NULL      }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    size_t t;
    const char *name;

    for (t = 0; t < test_vector_nr; t++) {
        name = get_kdf_name(test_vector[t].func);
        CUTE_ASSERT((test_vector[t].func == NULL || test_vector[t].func == meow) ?
                                                                    name == NULL :
                                          strcmp(name, test_vector[t].name) == 0);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_kdf_clockwork_ctx_tests)
    struct blackcat_kdf_clockwork_ctx *clockwork;
    void *nil = NULL; // WARN(Rafael): 'Eu tenho um jarro de terra, eu tenho um jarro de terra, adivinha o que tem dentro...'
                      //                                                                                  -- Jack Sparrow

    new_blackcat_kdf_clockwork_ctx(clockwork, {});
    CUTE_ASSERT(clockwork != NULL);

    clockwork->arg_data[0] = (void *) kryptos_newseg(10);
    clockwork->arg_size[0] = 10;
    clockwork->arg_data[1] = &nil;
    clockwork->arg_size[1] = 0;
    // INFO(Rafael): If it is exploding we will know.
    //               If it is not freeing memory accordingly the memory leak
    //               check system will complain at the end of the tests.
    del_blackcat_kdf_clockwork_ctx(clockwork);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_kdf_usr_params_get_next_tests)
    const char *usr_params = "hkdf:sha-224:radix-64-salt-stuff:radix-64-info-stuff";
    size_t usr_params_size = strlen(usr_params);
    char *next;
    char *out;
    size_t out_size, delta_offset = 0;

    out_size = 101;
    out = blackcat_kdf_usr_params_get_next(NULL, usr_params_size, &next, &out_size, &delta_offset);
    CUTE_ASSERT(out == NULL && out_size == 0);

    out_size = 101;
    out = blackcat_kdf_usr_params_get_next(usr_params, 0, &next, &out_size, &delta_offset);
    CUTE_ASSERT(out == NULL && out_size == 0);

    out_size = 101;
    out = blackcat_kdf_usr_params_get_next(usr_params, usr_params_size, NULL, &out_size, &delta_offset);
    CUTE_ASSERT(out == NULL && out_size == 0);

    out = blackcat_kdf_usr_params_get_next(usr_params, usr_params_size, &next, NULL, &delta_offset);
    CUTE_ASSERT(out == NULL);

    out_size = 101;
    out = blackcat_kdf_usr_params_get_next(usr_params, usr_params_size, &next, &out_size, NULL);
    CUTE_ASSERT(out == NULL && out_size == 0);

    out = blackcat_kdf_usr_params_get_next(usr_params, usr_params_size, &next, &out_size, &delta_offset);

    CUTE_ASSERT(next != NULL);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(out_size == 4);
    CUTE_ASSERT(strcmp(out, "hkdf") == 0);

    kryptos_freeseg(out, out_size);

    out = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &out_size, &delta_offset);

    CUTE_ASSERT(next != NULL);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(out_size == 7);
    CUTE_ASSERT(strcmp(out, "sha-224") == 0);

    kryptos_freeseg(out, out_size);

    out = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &out_size, &delta_offset);
    CUTE_ASSERT(next != NULL);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(out_size == 19);
    CUTE_ASSERT(strcmp(out, "radix-64-salt-stuff") == 0);

    kryptos_freeseg(out, out_size);

    out = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &out_size, &delta_offset);
    CUTE_ASSERT(next == NULL);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(out_size == 19);
    CUTE_ASSERT(strcmp(out, "radix-64-info-stuff") == 0);

    kryptos_freeseg(out, out_size);

    out = blackcat_kdf_usr_params_get_next(next, usr_params_size, &next, &out_size, &delta_offset);
    CUTE_ASSERT(next == NULL);
    CUTE_ASSERT(out == NULL);
    CUTE_ASSERT(out_size == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_hkdf_clockwork_tests)
    char *usr_params = NULL;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    char err[1024];

    CUTE_ASSERT(get_hkdf_clockwork(usr_params, 10, err) == NULL);

    usr_params = "kdf:sha-384:Zm9vYmFy:Zm9v";

    CUTE_ASSERT(get_hkdf_clockwork(usr_params, 0, err) == NULL);
    CUTE_ASSERT(get_hkdf_clockwork(usr_params, strlen(usr_params), err) == NULL);

    usr_params = "hkdf:foo-384:Zm9vYmFy:Zm9v";
    CUTE_ASSERT(get_hkdf_clockwork(usr_params, strlen(usr_params), err) == NULL);

    usr_params = "hkdf:sha-384:Zm9vYmFy:Zm9v";
    CUTE_ASSERT((kdf_clockwork = get_hkdf_clockwork(usr_params, strlen(usr_params), err)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_hkdf);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] == (void *) get_hash_processor("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] == (void *) get_hash_size("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[2] == (void *) get_hash_input_size("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == 6);
    CUTE_ASSERT(kdf_clockwork->arg_data[3] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[3], "foobar", 6) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[4]) == 6);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == 3);
    CUTE_ASSERT(kdf_clockwork->arg_data[5] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[5], "foo", 3) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[6] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[6]) == 3);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);

    //INFO(Rafael): Now with NULL error buffer.

    CUTE_ASSERT(get_hkdf_clockwork(usr_params, 10, NULL) == NULL);

    usr_params = "kdf:sha-384:Zm9vYmFy:Zm9v";

    CUTE_ASSERT(get_hkdf_clockwork(usr_params, 0, NULL) == NULL);
    CUTE_ASSERT(get_hkdf_clockwork(usr_params, strlen(usr_params), NULL) == NULL);

    usr_params = "hkdf:foo-384:Zm9vYmFy:Zm9v";
    CUTE_ASSERT(get_hkdf_clockwork(usr_params, strlen(usr_params), NULL) == NULL);

    usr_params = "hkdf:sha-384:Zm9vYmFy:Zm9v";
    CUTE_ASSERT((kdf_clockwork = get_hkdf_clockwork(usr_params, strlen(usr_params), NULL)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_hkdf);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] == (void *) get_hash_processor("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] == (void *) get_hash_size("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[2] == (void *) get_hash_input_size("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == 6);
    CUTE_ASSERT(kdf_clockwork->arg_data[3] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[3], "foobar", 6) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[4]) == 6);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == 3);
    CUTE_ASSERT(kdf_clockwork->arg_data[5] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[5], "foo", 3) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[6] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[6]) == 3);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);

    // INFO(Rafael): User parameter string with empty parameters.

    usr_params = "hkdf:sha-384::";
    CUTE_ASSERT((kdf_clockwork = get_hkdf_clockwork(usr_params, strlen(usr_params), err)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_hkdf);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] == (void *) get_hash_processor("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] == (void *) get_hash_size("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[2] == (void *) get_hash_input_size("sha-384"));
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[3] == NULL);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[4]) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[5] == NULL);
    CUTE_ASSERT(kdf_clockwork->arg_size[6] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[6]) == 0);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_pbkdf2_clockwork_tests)
    char *usr_params = NULL;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    char err[1024];

    CUTE_ASSERT(get_pbkdf2_clockwork(NULL, 9128931, err) == NULL);
    usr_params = "wtfkdf:blake2b-512:Zm9vYmFy:10";
    CUTE_ASSERT(get_pbkdf2_clockwork(usr_params, strlen(usr_params), err) == NULL);
    usr_params = "pbkdf2:who-101:Zm9vYmFy:10";
    CUTE_ASSERT(get_pbkdf2_clockwork(usr_params, strlen(usr_params), err) == NULL);

    usr_params = "pbkdf2:blake2b-512:Zm9vYmFy:10";
    CUTE_ASSERT((kdf_clockwork = get_pbkdf2_clockwork(usr_params, strlen(usr_params), err)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_pbkdf2);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] == (void *) get_hash_processor("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] == (void *) get_hash_size("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[2] == (void *) get_hash_input_size("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == 6);
    CUTE_ASSERT(kdf_clockwork->arg_data[3] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[3], "foobar", 6) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[4] != NULL);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[4]) == 6);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == sizeof(size_t));
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[5]) == 10);
    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);

    // INFO(Rafael): All once again but with NULL error buffer.

    CUTE_ASSERT(get_pbkdf2_clockwork(NULL, 9128931, NULL) == NULL);
    usr_params = "wtfkdf:blake2b-512:Zm9vYmFy:10";
    CUTE_ASSERT(get_pbkdf2_clockwork(usr_params, strlen(usr_params), NULL) == NULL);
    usr_params = "pbkdf2:who-101:Zm9vYmFy:10";
    CUTE_ASSERT(get_pbkdf2_clockwork(usr_params, strlen(usr_params), NULL) == NULL);

    usr_params = "pbkdf2:blake2b-512:Zm9vYmFy:10";
    CUTE_ASSERT((kdf_clockwork = get_pbkdf2_clockwork(usr_params, strlen(usr_params), NULL)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_pbkdf2);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] == (void *) get_hash_processor("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] == (void *) get_hash_size("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[2] == (void *) get_hash_input_size("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == 6);
    CUTE_ASSERT(kdf_clockwork->arg_data[3] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[3], "foobar", 6) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[4] != NULL);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[4]) == 6);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == sizeof(size_t));
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[5]) == 10);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);

    // INFO(Rafael): User parameter string passing an empty salt.

    usr_params = "pbkdf2:blake2b-512::10";
    CUTE_ASSERT((kdf_clockwork = get_pbkdf2_clockwork(usr_params, strlen(usr_params), err)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_pbkdf2);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] == (void *) get_hash_processor("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] == (void *) get_hash_size("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[2] == (void *) get_hash_input_size("blake2b-512"));
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[3] == NULL);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[4] != NULL);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[4]) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == sizeof(size_t));
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[5]) == 10);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_argon2i_clockwork_tests)
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    char err[1024];
    char *usr_params = NULL;

    CUTE_ASSERT(get_argon2i_clockwork(NULL, 2913, err) == NULL);
    usr_params = "argon2d:Zm9vYmFy:32:38:Zm9v:YmFy";
    CUTE_ASSERT(get_argon2i_clockwork(usr_params, strlen(usr_params), err) == NULL);
    usr_params = "argon2i:Zm9vYmFy:32:38:Zm9v:YmFy";
    CUTE_ASSERT((kdf_clockwork = get_argon2i_clockwork(usr_params, strlen(usr_params), err)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_argon2i);
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 6);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[0], "foobar", 6) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] != NULL);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[1]) == 6);
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == sizeof(kryptos_u32_t));
    CUTE_ASSERT(kdf_clockwork->arg_data[2] != NULL);
    CUTE_ASSERT(*((kryptos_u32_t *)kdf_clockwork->arg_data[2]) == 32);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == sizeof(kryptos_u32_t));
    CUTE_ASSERT(*((kryptos_u32_t *)kdf_clockwork->arg_data[3]) == 38);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 3);
    CUTE_ASSERT(kdf_clockwork->arg_data[4] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[4], "foo", 3) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[5]) == 3);
    CUTE_ASSERT(kdf_clockwork->arg_size[6] == 3);
    CUTE_ASSERT(kdf_clockwork->arg_data[6] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[6], "bar", 3) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[7] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[7]) == 3);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);

    //INFO(Rafael): Now by using a NULL error buffer.

    CUTE_ASSERT(get_argon2i_clockwork(NULL, 2913, NULL) == NULL);
    usr_params = "argon2d:Zm9vYmFy:32:38:Zm9v:YmFy";
    CUTE_ASSERT(get_argon2i_clockwork(usr_params, strlen(usr_params), NULL) == NULL);
    usr_params = "argon2i:Zm9vYmFy:32:38:Zm9v:YmFy";
    CUTE_ASSERT((kdf_clockwork = get_argon2i_clockwork(usr_params, strlen(usr_params), NULL)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_argon2i);
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 6);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[0], "foobar", 6) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] != NULL);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[1]) == 6);
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == sizeof(kryptos_u32_t));
    CUTE_ASSERT(kdf_clockwork->arg_data[2] != NULL);
    CUTE_ASSERT(*((kryptos_u32_t *)kdf_clockwork->arg_data[2]) == 32);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == sizeof(kryptos_u32_t));
    CUTE_ASSERT(*((kryptos_u32_t *)kdf_clockwork->arg_data[3]) == 38);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 3);
    CUTE_ASSERT(kdf_clockwork->arg_data[4] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[4], "foo", 3) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[5]) == 3);
    CUTE_ASSERT(kdf_clockwork->arg_size[6] == 3);
    CUTE_ASSERT(kdf_clockwork->arg_data[6] != NULL);
    CUTE_ASSERT(memcmp(kdf_clockwork->arg_data[6], "bar", 3) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[7] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[7]) == 3);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);

    // INFO(Rafael): User string parameter with null salt, key and associated data parameters.

    usr_params = "argon2i::32:38::";
    CUTE_ASSERT((kdf_clockwork = get_argon2i_clockwork(usr_params, strlen(usr_params), err)) != NULL);

    CUTE_ASSERT(kdf_clockwork->kdf == blackcat_argon2i);
    CUTE_ASSERT(kdf_clockwork->arg_size[0] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[0] == NULL);
    CUTE_ASSERT(kdf_clockwork->arg_size[1] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[1] != NULL);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[1]) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[2] == sizeof(kryptos_u32_t));
    CUTE_ASSERT(kdf_clockwork->arg_data[2] != NULL);
    CUTE_ASSERT(*((kryptos_u32_t *)kdf_clockwork->arg_data[2]) == 32);
    CUTE_ASSERT(kdf_clockwork->arg_size[3] == sizeof(kryptos_u32_t));
    CUTE_ASSERT(*((kryptos_u32_t *)kdf_clockwork->arg_data[3]) == 38);
    CUTE_ASSERT(kdf_clockwork->arg_size[4] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[4] == NULL);
    CUTE_ASSERT(kdf_clockwork->arg_size[5] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[5]) == 0);
    CUTE_ASSERT(kdf_clockwork->arg_size[6] == 0);
    CUTE_ASSERT(kdf_clockwork->arg_data[6] == NULL);
    CUTE_ASSERT(kdf_clockwork->arg_size[7] == 0);
    CUTE_ASSERT(*((size_t *)kdf_clockwork->arg_data[7]) == 0);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_kdf_clockwork_tests)
    char err[1024];
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    const char *usr_params[] = {
        "hkdf:sha-384:Zm9vYmFy:Zm9v",
        "pbkdf2:blake2b-512:Zm9vYmFy:10",
        "argon2i:Zm9vYmFy:32:38:Zm9v:YmFy"
    };
    const char **up, **up_end;

    CUTE_ASSERT(get_kdf_clockwork("alien1:bobobo:bubu", strlen("alien1:bobobo:bubu"), err) == NULL);

    // INFO(Rafael): Here we do not mind about if the kdf parsers are indeed returning correct data.
    //               It was already done in kdf function dedicated test. Here non-null means correct.

    up = usr_params;
    up_end = up + sizeof(usr_params) / sizeof(usr_params[0]);

    while (up != up_end) {
        CUTE_ASSERT((kdf_clockwork = get_kdf_clockwork(*up, strlen(*up), err)) != NULL);
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
        up++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(get_kdf_usr_params_tests)
    struct test_ctx {
        char *usr_params;
        struct blackcat_kdf_clockwork_ctx *(*get_clockwork)(const char *, const size_t, char *);
    } test_vector[] = {
        { "hkdf:sha-384:Zm9vYmFy:Zm9v",       get_hkdf_clockwork    },
        { "pbkdf2:blake2b-512:Zm9vYmFy:10",   get_pbkdf2_clockwork  },
        { "argon2i:Zm9vYmFy:32:38:Zm9v:YmFy", get_argon2i_clockwork },
        { "hkdf:sha-384::",                   get_hkdf_clockwork    },
        { "pbkdf2:blake2b-512::10",           get_pbkdf2_clockwork  },
        { "argon2i::32:38::",                 get_argon2i_clockwork }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork;
    size_t out_size, usr_params_size;
    char *out;

    CUTE_ASSERT(get_kdf_usr_params(NULL, &out_size) == NULL);

    kdf_clockwork = test_vector[0].get_clockwork(test_vector[0].usr_params, strlen(test_vector[0].usr_params), NULL);
    CUTE_ASSERT(kdf_clockwork != NULL);

    CUTE_ASSERT(get_kdf_usr_params(kdf_clockwork, NULL) == NULL);

    kdf_clockwork->kdf = NULL;
    CUTE_ASSERT(get_kdf_usr_params(kdf_clockwork, &out_size) == NULL);

    // INFO(Rafael): Alien kdf function case.

    kdf_clockwork->kdf = (void *)0xDEADBEEF;
    CUTE_ASSERT(get_kdf_usr_params(kdf_clockwork, &out_size) == NULL);

    del_blackcat_kdf_clockwork_ctx(kdf_clockwork);

    for (t = 0; t < test_vector_nr; t++) {
        usr_params_size = strlen(test_vector[t].usr_params);
        kdf_clockwork = test_vector[t].get_clockwork(test_vector[t].usr_params, usr_params_size, NULL);
        CUTE_ASSERT(kdf_clockwork != NULL);
        out = get_kdf_usr_params(kdf_clockwork, &out_size);
        CUTE_ASSERT(out_size == usr_params_size);
        CUTE_ASSERT(memcmp(out, test_vector[t].usr_params, out_size) == 0);
        kryptos_freeseg(out, out_size);
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_kdf_tests)
    struct test_ctx {
        char *usr_params;
        size_t okm_size;
        struct blackcat_kdf_clockwork_ctx *(*get_clockwork)(const char *, const size_t, char *);
    } test_vector[] = {
        { "hkdf:sha-384:Zm9vYmFy:Zm9v",        16, get_hkdf_clockwork    },
        { "pbkdf2:blake2b-512:Zm9vYmFy:10",    32, get_pbkdf2_clockwork  },
        { "argon2i:Zm9vYmFy:32:38:Zm9v:YmFy",  64, get_argon2i_clockwork },
        { "hkdf:sha-384::",                    96, get_hkdf_clockwork    },
        { "pbkdf2:blake2b-512::10",           128, get_pbkdf2_clockwork  },
        { "argon2i::32:38::",                 160, get_argon2i_clockwork }
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    struct blackcat_kdf_clockwork_ctx *kdf_clockwork = NULL;
    kryptos_u8_t *okm;

    for (t = 0; t < test_vector_nr; t++) {
        kdf_clockwork = test_vector[t].get_clockwork(test_vector[t].usr_params, strlen(test_vector[t].usr_params), NULL);
        CUTE_ASSERT(kdf_clockwork != NULL);
        okm = kdf_clockwork->kdf((kryptos_u8_t *)"meow", 4, test_vector[t].okm_size, kdf_clockwork->arg_data);
        CUTE_ASSERT(okm != NULL);
        kryptos_freeseg(okm, test_vector[t].okm_size);
        del_blackcat_kdf_clockwork_ctx(kdf_clockwork);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(blackcat_fmt_str_tests)
    struct test_ctx {
        const char *fmt;
        kryptos_u8_t *exp;
        size_t exp_size;
    } test_vector[] = {
        { "foobar",                         (kryptos_u8_t *)"foobar",                  6 },
        { "f\\x00\\obar",                   (kryptos_u8_t *)"f\x00obar",               6 },
        { "\\n\\t\\r\\xDE\\xaD\\xbe\\xEF",  (kryptos_u8_t *)"\n\t\r\xDE\xAD\xBE\xEF",  7 },
        { "\\n\\t\\r\\xDE\\xaD\\xbe\\xEF.", (kryptos_u8_t *)"\n\t\r\xDE\xAD\xBE\xEF.", 8 }
    };
    size_t t, tv_nr = sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_u8_t *out;
    size_t out_size = 101;

    CUTE_ASSERT(blackcat_fmt_str("", NULL) == NULL);
    CUTE_ASSERT(blackcat_fmt_str(NULL, &out_size) == NULL);
    CUTE_ASSERT(out_size == 0);

    for (t = 0; t < tv_nr; t++) {
        out = blackcat_fmt_str(test_vector[t].fmt, &out_size);
        CUTE_ASSERT(out != NULL);
        CUTE_ASSERT(out_size == test_vector[t].exp_size);
        CUTE_ASSERT(memcmp(out, test_vector[t].exp, out_size) == 0);
        kryptos_freeseg(out, out_size);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(token_wrap_tests)
    kryptos_u8_t *key;
    size_t key_size;
    struct token_ctx {
        kryptos_u8_t *data;
        size_t data_size;
    } tokens[] = { { (kryptos_u8_t *)"\xDE\xAD\xBE\xEF", 4 }, { (kryptos_u8_t *)"NothingIsEasy", 13 } };
    size_t tokens_nr = sizeof(tokens) / sizeof(tokens[0]), t;
    kryptos_u8_t *expected = (kryptos_u8_t *)"Nothin\xDE\xADsecret\xBE\xEFgIsEasy";
    size_t expected_size = 23;

    // INFO(Rafael): Those crazy parameters cannot explode at our faces.

    CUTE_ASSERT(token_wrap(NULL, NULL, NULL, 0) == 0);
    CUTE_ASSERT(token_wrap(NULL, &key_size, tokens[0].data, tokens[0].data_size) == 0);
    CUTE_ASSERT(token_wrap(&key, &key_size, NULL, tokens[0].data_size) == 0);
    CUTE_ASSERT(token_wrap(&key, &key_size, tokens[0].data, 0) == 0);

    key_size = 6;
    key = (kryptos_u8_t *) kryptos_newseg(key_size);

    CUTE_ASSERT(key != NULL);

    memcpy(key, "secret", 6);

    for (t = 0; t < tokens_nr; t++) {
        CUTE_ASSERT(token_wrap(&key, &key_size, tokens[t].data, tokens[t].data_size) == 1);
        CUTE_ASSERT(key != NULL);
        CUTE_ASSERT(key_size != 0 && key_size != 6);
    }

    CUTE_ASSERT(key_size == expected_size);
    CUTE_ASSERT(memcmp(key, expected, expected_size) == 0);

    kryptos_freeseg(key, key_size);
CUTE_TEST_CASE_END
