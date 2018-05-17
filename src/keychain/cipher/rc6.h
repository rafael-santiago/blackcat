/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_RC6_H
#define BLACKCAT_KEYCHAIN_CIPHER_RC6_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(rc6_128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc6_128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc6_128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(rc6_192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc6_192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc6_192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(rc6_256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_rc6_256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_rc6_256, ktask, p_layer)

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(rc6, algo_params, args, args_nr, key, key_size, argc, err_mesg);

#endif