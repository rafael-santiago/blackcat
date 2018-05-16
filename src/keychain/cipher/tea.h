/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_TEA_H
#define BLACKCAT_KEYCHAIN_CIPHER_TEA_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_tea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_tea, ktask, p_layer)

#endif
