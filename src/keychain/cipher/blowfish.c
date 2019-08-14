/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/blowfish.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(blowfish, ktask, p_layer,
                               kryptos_run_cipher(blowfish, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_blowfish, ktask, p_layer,
                               kryptos_run_cipher_hmac(blowfish, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
