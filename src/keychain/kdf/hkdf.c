/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/kdf/hkdf.h>
#include <kryptos.h>

IMPL_BLACKCAT_KDF_PROCESSOR(hkdf, ikm, ikm_size, okm_size, args,
                            {
                                return kryptos_do_hkdf(ikm, ikm_size,
                                                       (kryptos_hash_func)args[0],
                                                       (kryptos_hash_size_func)args[1],
                                                       (kryptos_hash_size_func)args[2],
                                                       (kryptos_u8_t *)args[3],
                                                       *((size_t *)args[4]),
                                                       (kryptos_u8_t *)args[5],
                                                       *((size_t *)args[6]),
                                                       okm_size);
                            })
