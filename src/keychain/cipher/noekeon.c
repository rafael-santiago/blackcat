/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/noekeon.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(noekeon, ktask, p_layer,
                               kryptos_run_cipher(noekeon, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_noekeon, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(noekeon_d, ktask, p_layer,
                               kryptos_run_cipher(noekeon_d, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, blake2s256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_noekeon_d, ktask, p_layer,
                               kryptos_run_cipher_hmac(noekeon_d, blake2b512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
