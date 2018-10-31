/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#ifndef BLACKCAT_NET_BASE_TYPES_H
#define BLACKCAT_NET_BASE_TYPES_H 1

#include <basedefs/defs.h>
#include <sys/socket.h>
#include <stdlib.h>

typedef enum bnt_channel_rule_level {
    kAF_INET  = AF_INET,
    kAF_INET6 = AF_INET6,
    kSOCKET   = AF_INET | AF_INET6
}bnt_channel_rule_level_t;

struct bnt_channel_rule_assertion {
    bnt_channel_rule_level_t family;
    unsigned int addr4;
    unsigned char addr6[16];
    unsigned short port_floor, port_ceil;
};

typedef struct bnt_channel_rule {
    struct bnt_channel_rule *head, *tail;
    char *ruleid;
    size_t ruleid_size;
    struct bnt_channel_rule_assertion assertion;
    blackcat_protlayer_chain_ctx *pchain;
    struct bnt_channel_rule *next, *last;
}bnt_channel_rule_ctx;

#endif