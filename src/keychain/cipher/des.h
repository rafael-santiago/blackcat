/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_DES_H
#define BLACKCAT_KEYCHAIN_CIPHER_DES_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(des, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_des, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(triple_des, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_triple_des, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_triple_des, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(triple_des_ede, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha224_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha256_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha384_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha512_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_224_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_256_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_384_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_sha3_512_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_tiger_triple_des_ede, ktask, p_layer)
DECL_BLACKCAT_CIPHER_PROCESSOR(hmac_whirlpool_triple_des_ede, ktask, p_layer)

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(triple_des, algo_params, args, args_nr, key, key_size, argc, err_mesg);

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(triple_des_ede, algo_params, args, args_nr, key, key_size, argc, err_mesg);

#endif
