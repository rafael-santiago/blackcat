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
    char addr[255];
    unsigned short port;
    size_t key_size, s_bits;
    kryptos_u8_t *k_priv, *k_pub;
    size_t k_priv_size, k_pub_size;
    kryptos_u8_t *session_key;
    size_t session_key_size;
    int ret, verbose, keep_sk_open, sockfd;
    int (*libc_socket)(int domain, int type, int protocol);
#if !defined(__NetBSD__)
    ssize_t (*libc_recv)(int sockfd, void *buf, size_t len, int flags);
    ssize_t (*libc_send)(int sockfd, const void *buf, size_t len, int flags);
#else
    ssize_t (*libc_recv)(int sockfd, void *buf, size_t len, int flags,
                         struct sockaddr *src_addr, socklen_t *addrlen);
    ssize_t (*libc_send)(int sockfd, const void *buf, size_t len, int flags,
                         const struct sockaddr *dest_addr, socklen_t addrlen);
#endif
};

typedef int (*skey_xchg_trap)(struct skey_xchg_ctx *arg);

int skey_xchg_server(struct skey_xchg_ctx *sx);

int skey_xchg_client(struct skey_xchg_ctx *sx);

kryptos_u8_t *encrypt_decrypt_dh_kpriv(kryptos_u8_t *in, const size_t in_size,
                                       kryptos_u8_t *key, const size_t key_size,
                                       size_t *out_size, const int decrypt);

#define encrypt_dh_kpriv(i, is, k, ks, os) encrypt_decrypt_dh_kpriv(i, is, k, ks, os, 0)

#define decrypt_dh_kpriv(i, is, k, ks, os) encrypt_decrypt_dh_kpriv(i, is, k, ks, os, 1)

#endif
