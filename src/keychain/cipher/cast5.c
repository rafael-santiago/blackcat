/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/cast5.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(cast5, ktask, p_layer,
                               kryptos_run_cipher(cast5, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_cast5, ktask, p_layer,
                               kryptos_run_cipher_hmac(cast5, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
