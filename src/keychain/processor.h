/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_PROCESSOR_H
#define BLACKCAT_KEYCHAIN_PROCESSOR_H 1

#include <basedefs/defs.h>

#define BLACKCAT_OTP_D "BC OTP D"

kryptos_u8_t *blackcat_encrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                    kryptos_u8_t *in, size_t in_size,
                                    size_t *out_size);

kryptos_u8_t *blackcat_decrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                    kryptos_u8_t *in, size_t in_size,
                                    size_t *out_size);

kryptos_u8_t *blackcat_otp_encrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                        kryptos_u8_t *in, size_t in_size,
                                        size_t *out_size);

kryptos_u8_t *blackcat_otp_decrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                        kryptos_u8_t *in, size_t in_size,
                                        size_t *out_size);

#endif
