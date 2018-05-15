/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef BLACKCAT_BASEDEFS_DEFS_H
#define BLACKCAT_BASEDEFS_DEFS_H 1

#include <kryptos_types.h>

typedef enum {
    kBlackcatProtLayerARC4,
    kBlackcatProtLayerSEAL,
    kBlackcatProtLayerRABBIT,
    kBlackcatProtLayerAES128,
    kBlackcatProtLayerAES192,
    kBlackcatProtLayerAES256,
    kBlackcatProtLayerDES,
    kBlackcatProtLayer3DES,
    kBlackcatProtLayer3DESEDE,
    kBlackcatProtLayerIDEA,
    kBlackcatProtLayerRC2,
    kBlackcatProtLayerRC5,
    kBlackcatProtLayerRC6128,
    kBlackcatProtLayerRC6192,
    kBlackcatProtLayerRC6256,
    kBlackcatProtLayerFEAL,
    kBlackcatProtLayerCAST5,
    kBlackcatProtLayerCAMELLIA128,
    kBlackcatProtLayerCAMELLIA192,
    kBlackcatProtLayerCAMELLIA256,
    kBlackcatProtLayerSAFERK64,
    kBlackcatProtLayerBLOWFISH,
    kBlackcatProtLayerSERPENT,
    kBlackcatProtLayerTEA,
    kBlackcatProtLayerXTEA,
    kBlackcatProtLayerMISTY1,
    kBlackcatProtLayerMARS128,
    kBlackcatProtLayerMARS192,
    kBlackcatProtLayerMARS256,
    kBlackcatProtLayerPRESENT80,
    kBlackcatProtLayerPRESENT128,
    kBlackcatProtLayerSHACAL1,
    kBlackcatProtLayerSHACAL2,
    kBlackcatProtLayerNOEKEON,
    kBlackcatProtLayerNOEKEOND,
    kBlackcatProtLayerAES128HMAC,
    kBlackcatProtLayerAES192HMAC,
    kBlackcatProtLayerAES256HMAC,
    kBlackcatProtLayerDESHMAC,
    kBlackcatProtLayer3DESHMAC,
    kBlackcatProtLayer3DESEDEHMAC,
    kBlackcatProtLayerIDEAHMAC,
    kBlackcatProtLayerRC2HMAC,
    kBlackcatProtLayerRC5HMAC,
    kBlackcatProtLayerRC6128HMAC,
    kBlackcatProtLayerRC6192HMAC,
    kBlackcatProtLayerRC6256HMAC,
    kBlackcatProtLayerFEALHMAC,
    kBlackcatProtLayerCAST5HMAC,
    kBlackcatProtLayerCAMELLIA128HMAC,
    kBlackcatProtLayerCAMELLIA192HMAC,
    kBlackcatProtLayerCAMELLIA256HMAC,
    kBlackcatProtLayerSAFERK64HMAC,
    kBlackcatProtLayerBLOWFISHHMAC,
    kBlackcatProtLayerSERPENTHMAC,
    kBlackcatProtLayerTEAHMAC,
    kBlackcatProtLayerXTEAHMAC,
    kBlackcatProtLayerMISTY1HMAC,
    kBlackcatProtLayerMARS128HMAC,
    kBlackcatProtLayerMARS192HMAC,
    kBlackcatProtLayerMARS256HMAC,
    kBlackcatProtLayerPRESENT80HMAC,
    kBlackcatProtLayerPRESENT128HMAC,
    kBlackcatProtLayerSHACAL1HMAC,
    kBlackcatProtLayerSHACAL2HMAC,
    kBlackcatProtLayerNOEKEONHMAC,
    kBlackcatProtLayerNOEKEONDHMAC,
    kBlackcatProtLayerNoProtection,
    kBlackcatProtLayerNr
}blackcat_protlayer_t;

typedef enum {
    kBlackcatHashSHA3,
    kBlackcatHashSHA224,
    kBlackcatHashSHA256,
    kBlackcatHashSHA384,
    kBlackcatHashSHA512,
    kBlackcatHashWHIRLPOOL,
    kBlackcatHashNone,
    kBlackcatHashNr
}blackcat_hash_t;

typedef struct blackcat_protlayer_chain {
    struct blackcat_protlayer_chain *head, *tail;
    blackcat_protlayer_t symm_algo;
    blackcat_hash_t hash_algo;
    kryptos_u8_t *key;
    size_t key_size;
    struct blackcat_protlayer_chain *last, *next;
}blackcat_protlayer_chain_ctx;

#endif
