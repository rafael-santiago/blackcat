/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/mars.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(mars128, ktask, p_layer,
                               kryptos_run_cipher(mars128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(mars192, ktask, p_layer,
                               kryptos_run_cipher(mars192, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(mars256, ktask, p_layer,
                               kryptos_run_cipher(mars256, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
