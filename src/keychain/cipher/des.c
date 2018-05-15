/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/des.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(des, ktask, p_layer,
                               kryptos_run_cipher(des, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(triple_des, ktask, p_layer,
                               kryptos_run_cipher(triple_des, *ktask,
                                                  p_layer->key, p_layer->key_size,
                                                  p_layer->mode,
                                                  (kryptos_u8_t *)p_layer->arg[0],
                                                  (size_t *)p_layer->arg[1],
                                                  (kryptos_u8_t *)p_layer->arg[2],
                                                  (size_t *)p_layer->arg[3]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(triple_des_ede, ktask, p_layer,
                               kryptos_run_cipher(triple_des_ede, *ktask,
                                                  p_layer->key, p_layer->key_size,
                                                  p_layer->mode,
                                                  (kryptos_u8_t *)p_layer->arg[0],
                                                  (size_t *)p_layer->arg[1],
                                                  (kryptos_u8_t *)p_layer->arg[2],
                                                  (size_t *)p_layer->arg[3]))

