/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <keychain/cipher/seal.h>
#include <kryptos.h>
#include <stdlib.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(seal, ktask, p_layer,
                               kryptos_run_cipher(seal, *ktask, p_layer->key, p_layer->key_size,
                                                  (kryptos_seal_version_t *)p_layer->arg[0],
                                                  (size_t *)p_layer->arg[1],
                                                  (size_t *)p_layer->arg[2]))
