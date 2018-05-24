/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/camellia.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(camellia128, ktask, p_layer,
                               kryptos_run_cipher(camellia128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(camellia192, ktask, p_layer,
                               kryptos_run_cipher(camellia192, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(camellia256, ktask, p_layer,
                               kryptos_run_cipher(camellia256, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_camellia128, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia128, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_camellia192, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia192, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_camellia256, ktask, p_layer,
                               kryptos_run_cipher_hmac(camellia256, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
