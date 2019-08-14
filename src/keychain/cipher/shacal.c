/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/shacal.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(shacal1, ktask, p_layer,
                               kryptos_run_cipher(shacal1, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_shacal1, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal1, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(shacal2, ktask, p_layer,
                               kryptos_run_cipher(shacal2, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_shacal2, ktask, p_layer,
                               kryptos_run_cipher_hmac(shacal2, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
