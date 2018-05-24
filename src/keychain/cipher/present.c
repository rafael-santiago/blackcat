/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/present.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(present80, ktask, p_layer,
                               kryptos_run_cipher(present80, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_present80, ktask, p_layer,
                               kryptos_run_cipher_hmac(present80, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(present128, ktask, p_layer,
                               kryptos_run_cipher(present128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_present128, ktask, p_layer,
                               kryptos_run_cipher_hmac(present128, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
