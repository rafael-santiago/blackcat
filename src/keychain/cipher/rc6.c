/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/rc5.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc6_128, ktask, p_layer,
                               kryptos_run_cipher(rc6_128, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc6_192, ktask, p_layer,
                               kryptos_run_cipher(rc6_192, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))

IMPL_BLACKCAT_CIPHER_PROCESSOR(rc6_256, ktask, p_layer,
                               kryptos_run_cipher(rc6_256, *ktask, p_layer->key, p_layer->key_size, p_layer->mode,
                                                  (int *)p_layer->arg[0]))
