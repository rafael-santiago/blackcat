/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/ciphering_schemes.h>
#include <kryptos_random.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define is_hmac(processor, cipher) ( processor == blackcat_hmac ## _sha224_ ## cipher     ||\
                                     processor == blackcat_hmac ## _sha256_ ## cipher     ||\
                                     processor == blackcat_hmac ## _sha384_ ## cipher     ||\
                                     processor == blackcat_hmac ## _sha512_ ## cipher     ||\
                                     processor == blackcat_hmac ## _sha3_224_ ## cipher   ||\
                                     processor == blackcat_hmac ## _sha3_256_ ## cipher   ||\
                                     processor == blackcat_hmac ## _sha3_384_ ## cipher   ||\
                                     processor == blackcat_hmac ## _sha3_512_ ## cipher   ||\
                                     processor == blackcat_hmac ## _tiger_ ## cipher      ||\
                                     processor == blackcat_hmac ## _whirlpool_ ## cipher  ||\
                                     processor == blackcat_hmac ## _blake2s256_ ## cipher ||\
                                     processor == blackcat_hmac ## _blake2b512_ ## cipher )

#define is_des_family_hmac(processor) ( is_hmac(processor, des)             ||\
                                        is_hmac(processor, triple_des)      ||\
                                        is_hmac(processor, triple_des_ede) )

void blackcat_NULL(kryptos_task_ctx **ktask, const blackcat_protlayer_chain_ctx *p_layer) {
    fprintf(stderr,
            "PANIC: Hi there! You have hit a NULL cipher processor there is nothing beyond here.\n"
            "       If you are seeing this message it means that a pretty stupid developer screwed up something.\n"
            "       Please report this error to someone smarter (if possible) telling what version you are using and\n"
            "       cross your fingers.\n"
            "       Thanks!\n");
    exit(1);
}

int blackcat_NULL_args(const char *algo_params,
                       void **args, const size_t args_nr,
                       kryptos_u8_t *key, const size_t key_size,
                       size_t *argc, char *err_msg) {
    fprintf(stderr,
           "PANIC: Hi there! You have hit a NULL cipher args reader there is nothing beyond here.\n"
           "       If you are seeing this message it means that a pretty stupid developer screwed up something.\n"
           "       Please report this error to someone smarter (if possible) telling what version you are using and\n"
           "       cross your fingers.\n"
           "       Thanks!\n");
    exit(1);
    return 1;
}

ssize_t get_algo_index(const char *algo_params) {
    ssize_t a;

    if (algo_params == NULL) {
        return -1;
    }

    for (a = 0; a < g_blackcat_ciphering_schemes_nr; a++) {
        if (strstr(algo_params, g_blackcat_ciphering_schemes[a].name) == algo_params) {
            return a;
        }
    }

    return -1;
}

blackcat_hash_processor get_hash_processor(const char *name) {
    size_t h;

    if (name == NULL) {
        return NULL;
    }

    for (h = 0; h < g_blackcat_hashing_algos_nr; h++) {
        if (strcmp(g_blackcat_hashing_algos[h].name, name) == 0) {
            return g_blackcat_hashing_algos[h].processor;
        }
    }

    return NULL;
}

blackcat_hash_size_func get_hash_size(const char *name) {
    size_t h;

    if (name == NULL) {
        return NULL;
    }

    for (h = 0; h < g_blackcat_hashing_algos_nr; h++) {
        if (strcmp(g_blackcat_hashing_algos[h].name, name) == 0) {
            return g_blackcat_hashing_algos[h].size;
        }
    }

    return NULL;
}

blackcat_hash_size_func get_hash_input_size(const char *name) {
    size_t h;

    if (name == NULL) {
        return NULL;
    }

    for (h = 0; h < g_blackcat_hashing_algos_nr; h++) {
        if (strcmp(g_blackcat_hashing_algos[h].name, name) == 0) {
            return g_blackcat_hashing_algos[h].input_size;
        }
    }

    return NULL;
}


int is_hmac_processor(blackcat_cipher_processor processor) {
    return
#if defined(BLACKCAT_WITH_AES)
           is_hmac(processor, aes128)         ||
           is_hmac(processor, aes192)         ||
           is_hmac(processor, aes256)         ||
#endif
#if defined(BLACKCAT_WITH_DES)
           is_hmac(processor, des)            ||
           is_hmac(processor, triple_des)     ||
           is_hmac(processor, triple_des_ede) ||
#endif
#if defined(BLACKCAT_WITH_IDEA)
           is_hmac(processor, idea)           ||
#endif
#if defined(BLACKCAT_WITH_RC2)
           is_hmac(processor, rc2)            ||
#endif
#if defined(BLACKCAT_WITH_RC5)
           is_hmac(processor, rc5)            ||
#endif
#if defined(BLACKCAT_WITH_RC6)
           is_hmac(processor, rc6_128)        ||
           is_hmac(processor, rc6_192)        ||
           is_hmac(processor, rc6_256)        ||
#endif
#if defined(BLACKCAT_WITH_FEAL)
           is_hmac(processor, feal)           ||
#endif
#if defined(BLACKCAT_WITH_CAST5)
           is_hmac(processor, cast5)          ||
#endif
#if defined(BLACKCAT_WITH_CAMELLIA)
           is_hmac(processor, camellia128)    ||
           is_hmac(processor, camellia192)    ||
           is_hmac(processor, camellia256)    ||
#endif
#if defined(BLACKCAT_WITH_SAFERK64)
           is_hmac(processor, saferk64)       ||
#endif
#if defined(BLACKCAT_WITH_BLOWFISH)
           is_hmac(processor, blowfish)       ||
#endif
#if defined(BLACKCAT_WITH_SERPENT)
           is_hmac(processor, serpent)        ||
#endif
#if defined(BLACKCAT_WITH_TEA)
           is_hmac(processor, tea)            ||
#endif
#if defined(BLACKCAT_WITH_XTEA)
           is_hmac(processor, xtea)           ||
#endif
#if defined(BLACKCAT_WITH_MISTY1)
           is_hmac(processor, misty1)         ||
#endif
#if defined(BLACKCAT_WITH_MARS)
           is_hmac(processor, mars128)        ||
           is_hmac(processor, mars192)        ||
           is_hmac(processor, mars256)        ||
#endif
#if defined(BLACKCAT_WITH_PRESENT)
           is_hmac(processor, present80)      ||
           is_hmac(processor, present128)     ||
#endif
#if defined(BLACKCAT_WITH_SHACAL1)
           is_hmac(processor, shacal1)        ||
#endif
#if defined(BLACKCAT_WITH_SHACAL2)
           is_hmac(processor, shacal2)        ||
#endif
#if defined(BLACKCAT_WITH_NOEKEON)
           is_hmac(processor, noekeon)        ||
           is_hmac(processor, noekeon_d)
#endif
    ;
}

int is_weak_hash_funcs_usage(blackcat_hash_processor h1, blackcat_hash_processor h2) {
    struct forbidden_hash_func_usage {
        blackcat_hash_processor h1, h2;
    };
#define register_forbidden_usage(hash_1, hash_2) { kryptos_ ## hash_1 ## _hash, kryptos_ ## hash_2 ## _hash }
    static struct forbidden_hash_func_usage fhfu[] = {
        register_forbidden_usage(sha224, sha224),
        register_forbidden_usage(sha256, sha256),
        register_forbidden_usage(sha384, sha384),
        register_forbidden_usage(sha512, sha512),
        register_forbidden_usage(sha224, sha256),
        register_forbidden_usage(sha256, sha224),
        register_forbidden_usage(sha384, sha512),
        register_forbidden_usage(sha512, sha384),
        register_forbidden_usage(sha3_224, sha3_224),
        register_forbidden_usage(sha3_256, sha3_256),
        register_forbidden_usage(sha3_384, sha3_384),
        register_forbidden_usage(sha3_512, sha3_512),
        register_forbidden_usage(sha3_224, sha3_256),
        register_forbidden_usage(sha3_224, sha3_384),
        register_forbidden_usage(sha3_224, sha3_512),
        register_forbidden_usage(sha3_256, sha3_224),
        register_forbidden_usage(sha3_256, sha3_384),
        register_forbidden_usage(sha3_256, sha3_512),
        register_forbidden_usage(sha3_384, sha3_224),
        register_forbidden_usage(sha3_384, sha3_256),
        register_forbidden_usage(sha3_384, sha3_512),
        register_forbidden_usage(sha3_512, sha3_224),
        register_forbidden_usage(sha3_512, sha3_256),
        register_forbidden_usage(sha3_512, sha3_384),
        register_forbidden_usage(tiger, tiger),
        register_forbidden_usage(whirlpool, whirlpool),
        register_forbidden_usage(blake2s256, blake2s256),
        register_forbidden_usage(blake2b512, blake2b512)
    };
#undef register_forbidden_usage
    size_t fhfu_nr = sizeof(fhfu) / sizeof(fhfu[0]), f;
    int is_weak = 0;

    for (f = 0; f < fhfu_nr && !is_weak; f++) {
        is_weak = (fhfu[f].h1 == h1 && fhfu[f].h2 == h2);
    }

    return is_weak;
}

const char *get_hash_processor_name(blackcat_hash_processor processor) {
    size_t h;

    if (processor == NULL) {
        return NULL;
    }

    for (h = 0; h < g_blackcat_hashing_algos_nr; h++) {
        if (processor == g_blackcat_hashing_algos[h].processor) {
            return &g_blackcat_hashing_algos[h].name[0];
        }
    }

    return NULL;
}

const struct blackcat_hmac_catalog_algorithms_ctx *get_hmac_catalog_scheme(const char *name) {
    size_t s;

    for (s = 0; s < g_blackcat_hmac_catalog_schemes_nr; s++) {
        if (strcmp(name, g_blackcat_hmac_catalog_schemes[s].name) == 0) {
            return &g_blackcat_hmac_catalog_schemes[s];
        }
    }

    return NULL;
}

const struct blackcat_hmac_catalog_algorithms_ctx *get_random_hmac_catalog_scheme(void) {
    size_t s = ((size_t) kryptos_get_random_byte() << 24) |
               ((size_t) kryptos_get_random_byte() << 16) |
               ((size_t) kryptos_get_random_byte() <<  8) |
               ((size_t) kryptos_get_random_byte());

    s = s % g_blackcat_hmac_catalog_schemes_nr;

#if defined(BLACKCAT_WITH_DES)
    // WARN(Rafael): We will not use DES family algorithms anymore, however for backward compability,
    //               we will decrypt catalogs previously encrypted by using them.
    while (is_des_family_hmac(g_blackcat_hmac_catalog_schemes[s].processor)) {
        s = ((size_t) kryptos_get_random_byte() << 24) |
            ((size_t) kryptos_get_random_byte() << 16) |
            ((size_t) kryptos_get_random_byte() <<  8) |
            ((size_t) kryptos_get_random_byte());

        s = s % g_blackcat_hmac_catalog_schemes_nr;
    }
#endif

    return &g_blackcat_hmac_catalog_schemes[s];
}

size_t get_hmac_key_size(blackcat_cipher_processor hmac) {
    size_t h, key_size = 0;

    if (!is_hmac_processor(hmac)) {
        return 0;
    }

    for (h = 0; key_size == 0 && h < g_blackcat_ciphering_schemes_nr; h++) {
        if (g_blackcat_ciphering_schemes[h].processor == hmac) {
            key_size = (size_t)g_blackcat_ciphering_schemes[h].key_size;
        }
    }

    return key_size;
}

blackcat_encoder get_encoder(const char *name) {
    size_t e;

    if (name == NULL) {
        return NULL;
    }

    for (e = 0; e < g_blackcat_encoding_algos_nr; e++) {
        if (strcmp(name, g_blackcat_encoding_algos[e].name) == 0) {
            return g_blackcat_encoding_algos[e].encoder;
        }
    }

    return NULL;
}

const char *get_encoder_name(blackcat_encoder encoder) {
    size_t e;

    if (encoder == NULL) {
        return NULL;
    }

    for (e = 0; e < g_blackcat_encoding_algos_nr; e++) {
        if (encoder == g_blackcat_encoding_algos[e].encoder) {
            return &g_blackcat_encoding_algos[e].name[0];
        }
    }

    return NULL;
}

void blackcat_bcrypt(kryptos_task_ctx **ktask, const int verify) {
    int cost;
    kryptos_u8_t *temp = NULL;
    size_t temp_size;

    if (ktask == NULL) {
        return;
    }

    if ((*ktask)->in == NULL || (*ktask)->in_size == 0 || (*ktask)->arg[0] == NULL) {
        (*ktask)->result = kKryptosInvalidParams;
        goto blackcat_bcrypt_epilogue;
    }

    if (!verify) {
        if ((temp = kryptos_get_random_block(16)) == NULL) {
            (*ktask)->result = kKryptosProcessError;
            goto blackcat_bcrypt_epilogue;
        }
        cost = *((int *)(*ktask)->arg[0]);
        (*ktask)->out = kryptos_bcrypt(cost, temp, 16, (*ktask)->in, (*ktask)->in_size, &(*ktask)->out_size);
        (*ktask)->result = ((*ktask)->out != NULL) ? kKryptosSuccess : kKryptosProcessError;
    } else {
        temp = (*ktask)->arg[0];
        temp_size = *(size_t *)(*ktask)->arg[1];
        //temp_size = strlen(temp);
        if (kryptos_bcrypt_verify(temp, temp_size, (*ktask)->in, (*ktask)->in_size)) {
            (*ktask)->result = kKryptosSuccess;
        } else {
            (*ktask)->result = kKryptosProcessError;
        }
        temp = NULL;
        temp_size = 0;
    }

blackcat_bcrypt_epilogue:

    if (!verify) {
        cost = 0;
        if (temp != NULL) {
            kryptos_freeseg(temp, 16);
        }
    }
}

size_t blackcat_bcrypt_size(void) {
    return 60;
}

size_t blackcat_bcrypt_input_size(void) {
    return 72; // WARN(Rafael): Here for bcrypt this is useless but let's return the maximum supported size.
}

int is_pht(blackcat_hash_processor h) {
    return (h == blackcat_bcrypt);
}

blackcat_kdf_func get_kdf(const char *name) {
    size_t k;

    if (name == NULL) {
        return NULL;
    }

    for (k = 0; k < g_blackcat_kdf_algos_nr; k++) {
        if (strcmp(g_blackcat_kdf_algos[k].name, name) == 0) {
            return g_blackcat_kdf_algos[k].kdf;
        }
    }

    return NULL;
}

const char *get_kdf_name(blackcat_kdf_func kdf) {
    size_t k;

    if (kdf == NULL) {
        return NULL;
    }

    for (k = 0; k < g_blackcat_kdf_algos_nr; k++) {
        if (g_blackcat_kdf_algos[k].kdf == kdf) {
            return &g_blackcat_kdf_algos[k].name[0];
        }
    }

    return NULL;
}

#define IMPL_BLACKCAT_GET_AVAIL(what, data_vector)\
kryptos_u8_t *blackcat_get_avail_ ## what(size_t *size) {\
    size_t s, c;\
    kryptos_u8_t *data, *dp;\
    if (size == NULL) {\
        return NULL;\
    }\
    s = 0;\
    for (c = 0; c < data_vector ## _nr; c++) {\
        s += strlen(data_vector[c].name) + 1;\
    }\
    data = (kryptos_u8_t *)kryptos_newseg(s + 1);\
    if (data == NULL) {\
        return NULL;\
    }\
    *size = s;\
    memset(data, 0, s + 1);\
    dp = data;\
    for (c = 0; c < data_vector ## _nr; c++) {\
        s = strlen(data_vector[c].name);\
        memcpy(dp, data_vector[c].name, s);\
        dp += s;\
        *dp = '\n';\
        dp++;\
    }\
    return data;\
}\

IMPL_BLACKCAT_GET_AVAIL(ciphers, g_blackcat_ciphering_schemes)

IMPL_BLACKCAT_GET_AVAIL(hmacs, g_blackcat_hmac_catalog_schemes)

IMPL_BLACKCAT_GET_AVAIL(hashes, g_blackcat_hashing_algos)

IMPL_BLACKCAT_GET_AVAIL(encoders, g_blackcat_encoding_algos)

IMPL_BLACKCAT_GET_AVAIL(kdfs, g_blackcat_kdf_algos)

#undef IMPL_BLACKCAT_GET_AVAIL

#undef is_hmac

#undef is_des_family_hmac
