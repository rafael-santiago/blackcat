/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/serpent.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(serpent, ktask, p_layer,
                               kryptos_run_cipher(serpent, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha3_224,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha3_256,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha3_384,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, sha3_512,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, tiger,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_serpent, ktask, p_layer,
                               kryptos_run_cipher_hmac(serpent, whirlpool,
                                                       *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
