/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/kdf/argon2i.h>
#include <kryptos.h>

IMPL_BLACKCAT_KDF_PROCESSOR(argon2i, ikm, ikm_size, okm_size, args,
                            {
                                return kryptos_do_argon2(ikm, ikm_size,
                                                         (kryptos_u8_t *)args[0],
                                                         *((size_t *)args[1]),
                                                         1, // WARN(Rafael): Libkryptos' argon implementation
                                                            // allows greater parallelism, but timing attacks
                                                            // are possible in this case. Let's avoid it.
                                                         (kryptos_u32_t)okm_size,
                                                         *((kryptos_u32_t *)args[2]),
                                                         *((kryptos_u32_t *)args[3]),
                                                         (kryptos_u8_t *)args[4],
                                                         *((size_t *)args[5]),
                                                         (kryptos_u8_t *)args[6],
                                                         *((size_t *)args[7]),
                                                         kArgon2i);
                            })

//TODO(Rafael): Write get_argon2i_clockwork().
