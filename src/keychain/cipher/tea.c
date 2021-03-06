/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/tea.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(tea, ktask, p_layer,
                               kryptos_run_cipher(tea, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_tea, ktask, p_layer,
                               kryptos_run_cipher_hmac(tea, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
