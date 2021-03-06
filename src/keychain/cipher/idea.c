/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/idea.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(idea, ktask, p_layer,
                               kryptos_run_cipher(idea, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, blake2s256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_idea, ktask, p_layer,
                               kryptos_run_cipher_hmac(idea, blake2b512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))
