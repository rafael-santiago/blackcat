/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/noekeon.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(noekeon, ktask, p_layer,
                               kryptos_run_cipher(noekeon, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))

IMPL_BLACKCAT_CIPHER_PROCESSOR(noekeon_d, ktask, p_layer,
                               kryptos_run_cipher(noekeon_d, *ktask, p_layer->key, p_layer->key_size, p_layer->mode))
