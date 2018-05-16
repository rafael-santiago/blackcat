/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_SERPENT_H
#define BLACKCAT_KEYCHAIN_CIPHER_SERPENT_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_serpent, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_serpent, ktask, p_layer)

#endif
