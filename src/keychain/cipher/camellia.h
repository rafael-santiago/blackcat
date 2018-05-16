/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_CAMELLIA_H
#define BLACKCAT_KEYCHAIN_CIPHER_CAMELLIA_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(camellia128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(camellia192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(camellia256, ktask, p_layer)


DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_camellia256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_camellia128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_camellia192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_camellia256, ktask, p_layer)

#endif
