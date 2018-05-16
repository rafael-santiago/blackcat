/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/des.h>
#include <kryptos.h>

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

