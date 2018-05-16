/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/feal.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(feal, ktask, p_layer,
                               kryptos_run_cipher(feal, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_224, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_256, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_384, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, sha3_512, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, tiger, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_feal, ktask, p_layer,
                               kryptos_run_cipher_hmac(feal, whirlpool, *ktask,
                                                       p_layer->key, p_layer->key_size, p_layer->mode,
                                                       (int *)p_layer->arg[0]))
