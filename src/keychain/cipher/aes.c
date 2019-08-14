/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/aes.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(aes128, ktask, p_layer,
                               kryptos_run_cipher(aes128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_aes128, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes128, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(aes192, ktask, p_layer,
                               kryptos_run_cipher(aes192, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_aes192, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes192, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(aes256, ktask, p_layer,
                               kryptos_run_cipher(aes256, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_aes256, ktask, p_layer,
                               kryptos_run_cipher_hmac(aes256, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
