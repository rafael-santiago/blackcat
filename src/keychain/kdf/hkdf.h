/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_KDF_HKDF_H
#define BLACKCAT_KEYCHAIN_KDF_HKDF_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_KDF_PROCESSOR(hkdf, ikm, ikm_size, okm_size, args)

struct blackcat_kdf_clockwork_ctx *get_hkdf_clockwork(const char *usr_params, const size_t usr_params_size,
                                                      char *err_msg);

char *get_hkdf_usr_params(const struct blackcat_kdf_clockwork_ctx *kdf_clockwork, size_t *out_size);

#endif
