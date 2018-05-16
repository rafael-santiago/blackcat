/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/mars.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(mars128, ktask, p_layer,
                               kryptos_run_cipher(mars128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_mars128, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars128, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(mars192, ktask, p_layer,
                               kryptos_run_cipher(mars192, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_mars192, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars192, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(mars256, ktask, p_layer,
                               kryptos_run_cipher(mars256, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_mars256, ktask, p_layer,
                               kryptos_run_cipher_hmac(mars256, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode))
