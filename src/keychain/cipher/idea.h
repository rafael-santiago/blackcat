/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_IDEA_H
#define BLACKCAT_KEYCHAIN_CIPHER_IDEA_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2s256_idea, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_blake2b512_idea, ktask, p_layer)

#endif
