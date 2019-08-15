/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_KDF_ARGON2I_H
#define BLACKCAT_KEYCHAIN_KDF_ARGON2I_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_KDF_PROCESSOR(argon2i, ikm, ikm_size, okm_size, args)

#endif
