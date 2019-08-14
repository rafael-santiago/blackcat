/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_MARS_H
#define BLACKCAT_KEYCHAIN_CIPHER_MARS_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(mars128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_mars128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_mars128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_mars128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_mars128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_mars128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_mars128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_mars128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_mars128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_mars128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_mars128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_mars128, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_mars128, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(mars192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_mars192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_mars192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_mars192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_mars192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_mars192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_mars192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_mars192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_mars192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_mars192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_mars192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_mars192, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_mars192, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(mars256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_mars256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_mars256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_mars256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_mars256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_mars256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_mars256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_mars256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_mars256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_mars256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_mars256, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_mars256, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_mars256, ktask, p_layer)

#endif
