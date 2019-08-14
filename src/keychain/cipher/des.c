/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/des.h>
#include <keychain/keychain.h>
#include <kryptos.h>
#include <stdio.h>

static int read_extra_des_keys(const char *algo_params,
                               void **args, const size_t args_nr,
                               kryptos_u8_t *key, const size_t key_size,
                               size_t *argc, char *err_mesg);

IMPL_BLACKCAT_CIPHER_PROCESSOR(des, ktask, p_layer,
                               kryptos_run_cipher(des, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(des, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(triple_des, ktask, p_layer,
                               kryptos_run_cipher(triple_des, *ktask,
                                                  p_layer->key, p_layer->key_size,
                                                  p_layer->mode,
                                                  (kryptos_u8_t *)p_layer->arg[0],
                                                  (size_t *)p_layer->arg[1],
                                                  (kryptos_u8_t *)p_layer->arg[2],
                                                  (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_triple_des, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher(triple_des_ede, *ktask,
                                                  p_layer->key, p_layer->key_size,
                                                  p_layer->mode,
                                                  (kryptos_u8_t *)p_layer->arg[0],
                                                  (size_t *)p_layer->arg[1],
                                                  (kryptos_u8_t *)p_layer->arg[2],
                                                  (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size,
                                                       p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher_hmac(triple_des_ede, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (kryptos_u8_t *)p_layer->arg[0],
                                                       (size_t *)p_layer->arg[1],
                                                       (kryptos_u8_t *)p_layer->arg[2],
                                                       (size_t *)p_layer->arg[3]))

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(triple_des, algo_params, args, args_nr, key, key_size, argc, err_mesg) {
    return read_extra_des_keys(algo_params, args, args_nr, key, key_size, argc, err_mesg);
}

static int read_extra_des_keys(const char *algo_params,
                               void **args, const size_t args_nr,
                               kryptos_u8_t *key, const size_t key_size,
                               size_t *argc, char *err_mesg) {
    void *ap = args, *ap_end;

    blackcat_keychain_verify_argv_bounds(args_nr, 4, err_mesg);

    args[0] = (kryptos_u8_t *) kryptos_newseg(sizeof(kryptos_u8_t) << 3);
    memcpy(args[0], key + 8, 8);

    args[1] = (size_t *) kryptos_newseg(sizeof(size_t));
    *(size_t *)args[1] = 8;

    args[2] = (kryptos_u8_t *) kryptos_newseg(sizeof(kryptos_u8_t) << 3);
    memcpy(args[2], key + 16, 8);

    args[3] = (size_t *) kryptos_newseg(sizeof(size_t));
    *(size_t *)args[3] = 8;

    *argc = 4;

    return 1;
}
