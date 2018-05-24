/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_KEYCHAIN_CIPHER_SEAL_H
#define BLACKCAT_KEYCHAIN_CIPHER_SEAL_H 1

#include <basedefs/defs.h>

DECL_BLACKCAT_CIPHER_PROCESSOR(seal, ktask, p_layer)

BLACKCAT_CIPHER_ARGS_READER_PROTOTYPE(seal, algo_params, args, args_nr, key, key_size, argc, err_mesg);

#endif
