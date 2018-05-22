/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_PROCESSOR_H
#define BLACKCAT_KEYCHAIN_PROCESSOR_H 1

#include <basedefs/defs.h>

kryptos_u8_t *blackcat_encrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                    kryptos_u8_t *in, size_t in_size,
                                    size_t *out_size);

kryptos_u8_t *blackcat_decrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                    kryptos_u8_t *in, size_t in_size,
                                    size_t *out_size);

#endif
