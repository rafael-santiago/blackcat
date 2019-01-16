/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_NET_DH_DH_H
#define BLACKCAT_NET_DH_DH_H 1

#include <kryptos.h>
#include <stdlib.h>

struct skey_xchg_ctx {
    char *addr;
    unsigned short port;
    size_t key_size, s_bits;
    kryptos_u8_t *k_priv, *k_pub;
    size_t k_priv_size, k_pub_size;
    kryptos_u8_t *session_key;
    size_t session_key_size;
    int ret;
};

typedef int (*skey_xchg_trap)(struct skey_xchg_ctx *arg);

int skey_xchg_server(struct skey_xchg_ctx *sx);

int skey_xchg_client(struct skey_xchg_ctx *sx);

#endif
