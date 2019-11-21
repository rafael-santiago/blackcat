/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/keychain.h>
#include <keychain/ciphering_schemes.h>
#include <kryptos.h>
#include <ctype.h>

static kryptos_u8_t *keychain_hash_user_weak_key(kryptos_u8_t **key, size_t *key_size, ssize_t *wanted_size,
                                                 struct blackcat_keychain_handle_ctx *handle);

static kryptos_u8_t *blackcat_key_crunching(const size_t algo, kryptos_u8_t **key, size_t *key_size,
                                            size_t *derived_size,
                                            struct blackcat_keychain_handle_ctx *handle);

int blackcat_set_keychain(blackcat_protlayer_chain_ctx **protlayer,
                          const char *algo_params, kryptos_u8_t **key, size_t *key_size,
                          const size_t args_nr,
                          struct blackcat_keychain_handle_ctx *handle,
                          char *err_mesg) {
    ssize_t algo = get_algo_index(algo_params);
    blackcat_protlayer_chain_ctx *p;
    int no_error = 1;
    blackcat_cipher_args_reader args_reader;

    if (algo == -1 || protlayer == NULL) {
        return 0;
    }

    p = (*protlayer);

    p->key = blackcat_key_crunching(algo, key, key_size, &p->key_size, handle);
    p->processor = g_blackcat_ciphering_schemes[algo].processor;
    p->is_hmac = is_hmac_processor(p->processor);
    p->mode = g_blackcat_ciphering_schemes[algo].mode;

    args_reader = g_blackcat_ciphering_schemes[algo].args;

    if (!is_null_arg_handler(args_reader)) {
        no_error = args_reader(algo_params, p->arg, args_nr, (*key), *key_size, &p->argc, err_mesg);
    }

    return no_error;
}

void blackcat_keychain_arg_init(const char *algo_params, const size_t algo_params_size, const char **begin, const char **end) {
    if (begin == NULL || end == NULL) {
        return;
    }

    if (algo_params == NULL) {
        *begin = NULL;
        *end = NULL;
        return;
    }

    *begin = algo_params;
    *end = algo_params + algo_params_size;

    while (*begin != *end && **begin != '/' && **begin != 0) {
        (*begin) += 1;
    }

    if (*begin != *end) {
        (*begin) += (**begin == '/');
    }
}

char *blackcat_keychain_arg_next(const char **begin, const char *end, char *err_mesg,
                                 blackcat_keychain_arg_verifier verifier) {
    const char *bp, *bp_next;
    char *arg = NULL, *str = NULL;
    size_t arg_size, str_size;

    bp = bp_next = *begin;

    if (bp == end) {
        goto blackcat_keychain_arg_next_epilogue;
    }

    while (bp_next != end && *bp_next != 0 && *bp_next != '-') {
        bp_next++;
    }

    str_size = (bp_next - bp);
    str = (char *) kryptos_newseg(str_size + 1);
    if (str == NULL) {
        fprintf(stderr, "ERROR: Not enough memory to parse cipher argument.\n");
        goto blackcat_keychain_arg_next_epilogue;
    }
    memset(str, 0, str_size + 1);
    memcpy(str, bp, str_size);

    if ((arg = blackcat_fmt_str(str, &arg_size)) == NULL) {
        fprintf(stderr, "ERROR: Unable to format the cipher argument.\n");
        goto blackcat_keychain_arg_next_epilogue;
    }

    if (verifier != NULL) {
        if (verifier(arg, arg_size, err_mesg) == 0) {
            free(arg);
            arg = NULL;
            goto blackcat_keychain_arg_next_epilogue;
        }
    }

    if (bp_next != end) {
        bp_next += (*bp_next == '-');
    }

    *begin = bp_next;

blackcat_keychain_arg_next_epilogue:

    if (str != NULL) {
        kryptos_freeseg(str, str_size);
        str_size = 0;
    }

    return arg;
}

int blackcat_is_dec(const char *buf, const size_t buf_size) {
    const char *bp;
    const char *bp_end;

    if (buf == NULL || buf_size == 0) {
        return 0;
    }

    bp = buf;
    bp_end = bp + buf_size;

    while (bp != bp_end) {
        if (!isdigit(*bp)) {
            return 0;
        }
        bp++;
    }

    return 1;
}

void blackcat_xor_keychain_protkey(blackcat_protlayer_chain_ctx *protlayer,
                                   const kryptos_u8_t *seed, const size_t seed_size) {
    const kryptos_u8_t *sp, *sp_end;
    blackcat_protlayer_chain_ctx *p;
    kryptos_u8_t *kp, *kp_end;

    if (protlayer == NULL || seed == NULL || seed_size == 0) {
        return;
    }

    for (p = protlayer; p != NULL; p = p->next) {
        sp = seed;
        sp_end = sp + seed_size;
        kp = p->key;
        kp_end = kp + p->key_size;
        while (kp != kp_end) {
            *kp ^= *sp;
            sp = ((sp + 1) != sp_end) ? sp + 1 : seed;
            kp++;
        }
    }
}

static kryptos_u8_t *blackcat_key_crunching(const size_t algo, kryptos_u8_t **key, size_t *key_size,
                                            size_t *derived_size,
                                            struct blackcat_keychain_handle_ctx *handle) {
    if (key == NULL || derived_size == NULL || algo > g_blackcat_ciphering_schemes_nr) {
        return NULL;
    }

    *derived_size = g_blackcat_ciphering_schemes[algo].key_size;

    return keychain_hash_user_weak_key(key, key_size, (ssize_t *)derived_size, handle);
}

static kryptos_u8_t *keychain_hash_user_weak_key(kryptos_u8_t **key, size_t *key_size,
                                                 ssize_t *wanted_size,
                                                 struct blackcat_keychain_handle_ctx *handle) {
    kryptos_u8_t *kp = NULL, *skey = NULL;
    kryptos_task_ctx t, *ktask = &t;
    size_t kp_size, curr_size;

    if (*wanted_size == 0) {
        return NULL;
    }

    if (handle->kdf_clockwork == NULL) {
        if (*wanted_size == - 1) {
            kryptos_task_init_as_null(ktask);

            ktask->in = (kryptos_u8_t *) kryptos_newseg(*key_size);
            ktask->in_size = *key_size;
            memcpy(ktask->in, *key, *key_size);

            if (handle->hash == NULL) {
                kryptos_hash(sha3_512, ktask, (kryptos_u8_t *)ktask->in, ktask->in_size, 0);
            } else {
                handle->hash(&ktask, 0);
            }

            if (!kryptos_last_task_succeed(ktask)) {
                return NULL;
            }

            *wanted_size = ktask->out_size + ktask->out[0] + ktask->in_size;

            kp = skey = (kryptos_u8_t *) kryptos_newseg(*wanted_size);
            kp_size = *wanted_size;

            kryptos_task_free(ktask, KRYPTOS_TASK_IN);
            kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        } else {
            kp = skey = (kryptos_u8_t *) kryptos_newseg(*wanted_size);
            kp_size = *wanted_size;

            kryptos_task_init_as_null(ktask);

            ktask->in = (kryptos_u8_t *) kryptos_newseg(*key_size);
            ktask->in_size = *key_size;
            memcpy(ktask->in, *key, *key_size);

            if (handle->hash == NULL) {
                kryptos_hash(sha3_512, ktask, (kryptos_u8_t *)ktask->in, ktask->in_size, 0);
            } else {
                handle->hash(&ktask, 0);
            }

            if (!kryptos_last_task_succeed(ktask)) {
                return NULL;
            }

            kryptos_freeseg(ktask->in, ktask->in_size);
            ktask->in_size = ktask->out_size + *key_size;
            ktask->in = (kryptos_u8_t *) kryptos_newseg(ktask->in_size);
            if (ktask->in == NULL) {
                return NULL;
            }

            memcpy(ktask->in, ktask->out, ktask->out_size >> 1);
            memcpy(ktask->in + (ktask->out_size >> 1), *key, *key_size);
            memcpy(ktask->in + (ktask->out_size >> 1) + *key_size, ktask->out + (ktask->out_size >> 1), ktask->out_size >> 1);

            kryptos_freeseg(ktask->out, ktask->out_size);
            ktask->out = NULL;

            if (handle->hash == NULL) {
                kryptos_hash(sha3_512, ktask, (kryptos_u8_t *)ktask->in, ktask->in_size, 0);
            } else {
                handle->hash(&ktask, 0);
            }

            kryptos_freeseg(ktask->in, ktask->in_size);
            ktask->in = NULL;
            ktask->in_size = 0;

            if (!kryptos_last_task_succeed(ktask)) {
                return NULL;
            }

            ktask->in = ktask->out;
            ktask->in_size = ktask->out_size;
            ktask->out = NULL;
            ktask->out_size = 0;
        }

        while (kp_size > 0) {
            if (handle->hash == NULL) {
                kryptos_hash(sha3_512, ktask, (kryptos_u8_t *)ktask->in, ktask->in_size, 0);
            } else {
                handle->hash(&ktask, 0);
            }
            curr_size = (ktask->out_size < kp_size) ? ktask->out_size : kp_size;
            memcpy(kp, ktask->out, curr_size);
            if (ktask->in == (*key)) {
                ktask->in = NULL;
                ktask->in_size = 0;
            }
            kryptos_task_free(ktask, KRYPTOS_TASK_IN);
            kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
            kp_size -= curr_size;
            kp += curr_size;
        }

        kryptos_freeseg(*key, *key_size);

        // INFO(Rafael): Refreshing the key buffer for the next key derivation.
        (*key) = ktask->out;
        *key_size = ktask->out_size;
    } else {
        if (*wanted_size == -1) {
            *wanted_size = (*key_size) << 1;
        }

        skey = handle->kdf_clockwork->kdf(*key, *key_size, *wanted_size, handle->kdf_clockwork->arg_data);

        kryptos_freeseg(*key, *key_size);

        // INFO(Rafael): Refreshing the key buffer for the next key derivation.
        *key_size = *wanted_size;
        (*key) = handle->kdf_clockwork->kdf(skey, *wanted_size, *key_size, handle->kdf_clockwork->arg_data);
    }

    return skey;
}

kryptos_u8_t *blackcat_fmt_str(const char *str, size_t *out_size) {
    kryptos_u8_t buf[65535];
    kryptos_u8_t *bp, *bp_end;
    const char *sp, *sp_end;
    kryptos_u8_t *out = NULL;

    if (out_size == NULL) {
        return NULL;
    }

    if (str == NULL) {
        *out_size = 0;
        return NULL;
    }

    memset(buf, 0, sizeof(buf));

    bp = &buf[0];
    bp_end = bp + sizeof(buf);

    sp = &str[0];
    sp_end = sp + strlen(sp);

#define get_nibble(n) ( ((n) >= '0' && (n) <= '9') ? (n) - '0' : toupper((n)) - 55 )

    while (bp < bp_end && sp < sp_end) {
        if (*sp == '\\') {
            sp++;
            switch (*sp) {
                case 'n':
                    *bp = '\n';
                    break;

                case 't':
                    *bp = '\t';
                    break;

                case 'r':
                    *bp = '\r';
                    break;

                case 'x':
                    sp++;
                    while (bp < bp_end && sp < sp_end && isxdigit(*sp)) {
                        *bp = (kryptos_u8_t) get_nibble(*sp);
                        sp++;
                        if (isxdigit(*sp)) {
                            *bp = *bp << 4 | get_nibble(*sp);
                            sp++;
                            bp++;
                        }
                    }
                    sp--;
                    bp--;
                    break;

                default:
                    *bp = *sp;
                    break;
            }
        } else {
            *bp = *sp;
        }
        bp++;
        sp++;
    }

#undef get_nibble

    *out_size = 0;

    out = (kryptos_u8_t *) kryptos_newseg((bp - &buf[0]) + 1);

    if (out != NULL) {
        *out_size = bp - &buf[0];
        memset(out, 0, *out_size + 1);
        memcpy(out, buf, *out_size);
    }

    return out;
}
