/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/misty1.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(misty1, ktask, p_layer,
                               kryptos_run_cipher(misty1, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_misty1, ktask, p_layer,
                               kryptos_run_cipher_hmac(misty1, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
