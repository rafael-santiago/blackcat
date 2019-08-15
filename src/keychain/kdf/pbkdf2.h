/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_KDF_PBKDF2_H
#define BLACKCAT_KEYCHAIN_KDF_PBKDF2_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_KDF_PROCESSOR(pbkdf2, ikm, ikm_size, okm_size, args)

#endif
