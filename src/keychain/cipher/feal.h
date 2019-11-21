/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_FEAL_H
#define BLACKCAT_KEYCHAIN_CIPHER_FEAL_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_feal, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_feal, ktask, p_layer)

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(feal, algo_params, algo_params_size, args, args_nr, key, key_size, argc, err_mesg);

#endif
