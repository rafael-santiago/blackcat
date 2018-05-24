/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/cipher/arc4.h>
#include <kryptos.h>

IMPL_BLACKCAT_CIPHER_PROCESSOR(arc4, ktask, p_layer,
                               kryptos_run_cipher(arc4, *ktask, p_layer->key, p_layer->key_size))
