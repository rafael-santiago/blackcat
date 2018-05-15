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

DECL_BLACKCAT_CIPHER_PROCESSOR(triple_des, ktask, p_layer)

DECL_BLACKCAT_CIPHER_PROCESSOR(triple_des_ede, ktask, p_layer)

#endif
