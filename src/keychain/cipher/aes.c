/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/aes.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(aes128, ktask, p_layer,
                               kryptos_run_cipher(aes128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(aes192, ktask, p_layer,
                               kryptos_run_cipher(aes192, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(aes256, ktask, p_layer,
                               kryptos_run_cipher(aes256, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
