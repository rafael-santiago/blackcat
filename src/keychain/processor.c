/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/processor.h>
#include <kryptos.h>
#include <ctype.h>

static kryptos_u8_t *blackcat_meta_processor(const blackcat_protlayer_chain_ctx *protlayer,
                                             kryptos_u8_t *in, size_t in_size,
                                             size_t *out_size, kryptos_action_t action);

kryptos_u8_t *blackcat_encrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                    kryptos_u8_t *in, size_t in_size,
                                    size_t *out_size) {
    return blackcat_meta_processor(protlayer, in, in_size, out_size, kKryptosEncrypt);
}

kryptos_u8_t *blackcat_decrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                    kryptos_u8_t *in, size_t in_size,
                                    size_t *out_size) {
    return blackcat_meta_processor(protlayer, in, in_size, out_size, kKryptosDecrypt);
}

/*static void print_data(const kryptos_u8_t *bytes, size_t bytes_total) {
    const kryptos_u8_t *bp, *bp_end;

    bp = bytes;
    bp_end = bp + bytes_total;

    while (bp != bp_end) {
        if (isprint(*bp)) {
            printf("%c", *bp);
        } else {
            printf(".");
        }
        bp++;
    }
    printf("\n");
}*/

static kryptos_u8_t *blackcat_meta_processor(const blackcat_protlayer_chain_ctx *protlayer,
                                             kryptos_u8_t *in, size_t in_size,
                                             size_t *out_size, kryptos_action_t action) {
    const blackcat_protlayer_chain_ctx *p;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *out;
    int done, is_hmac = 0;

    if (protlayer == NULL || in == NULL || in_size == 0 || out_size == NULL) {
        return NULL;
    }

    out = NULL;
    *out_size = 0;

    kryptos_task_init_as_null(ktask);
    ktask->action = action;

    if (action == kKryptosDecrypt) {
        for (p = protlayer->head; p != NULL && !is_hmac; p = p->next) {
            is_hmac = p->is_hmac;
        }
    }

    if (!is_hmac) {
        kryptos_task_set_in(ktask, in, in_size);
    } else {
        // INFO(Rafael): The HMAC when well succeeded changes the allocation of the input, by removing the
        //               hash from the entire cryptogram during the decryption. Let's preserve the original.

        ktask->in = (kryptos_u8_t *) kryptos_newseg(in_size);

        if (ktask->in == NULL) {
            goto blackcat_meta_processor_epilogue;
        }

        memcpy(ktask->in, in, in_size);
        ktask->in_size = in_size;
    }

    if (action == kKryptosEncrypt) {
        p = protlayer->head;
    } else {
        p = protlayer->tail;
    }

    if (protlayer->head->encoder != NULL && action == kKryptosDecrypt) {
        kryptos_task_set_decode_action(ktask);

        protlayer->head->encoder(&ktask);
        done = kryptos_last_task_succeed(ktask);

        if (ktask->in != in) {
            kryptos_task_free(ktask, KRYPTOS_TASK_IN);
        }

        if (!done) {
            if (ktask->out != NULL) {
                kryptos_freeseg(ktask->out, ktask->out_size);
            }
            goto blackcat_meta_processor_epilogue;
        }

        ktask->action = action;
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);

        ktask->out = NULL;
        ktask->out_size = 0;
    }

    while (p != NULL) {
        p->processor(&ktask, p);

        done = kryptos_last_task_succeed(ktask);

        if (ktask->in != in) {
            kryptos_task_free(ktask, KRYPTOS_TASK_IN);
        }

        if (!done) {
            if (ktask->out != NULL) {
                kryptos_freeseg(ktask->out, ktask->out_size);
            }
            goto blackcat_meta_processor_epilogue;
        }

        ktask->action = action;
        kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
        ktask->iv = NULL;

        if (action == kKryptosEncrypt) {
            p = p->next;
        } else {
            p = p->last;
        }
    }

    if (protlayer->head->encoder != NULL && action == kKryptosEncrypt) {
        kryptos_task_set_encode_action(ktask);
        protlayer->head->encoder(&ktask);
        done = kryptos_last_task_succeed(ktask);

        if (ktask->in != in) {
            kryptos_task_free(ktask, KRYPTOS_TASK_IN);
        }

        if (!done) {
            if (ktask->out != NULL) {
                kryptos_freeseg(ktask->out, ktask->out_size);
            }
            goto blackcat_meta_processor_epilogue;
        }
    }

    out = ktask->out;
    *out_size = ktask->out_size;

blackcat_meta_processor_epilogue:

    kryptos_task_init_as_null(ktask);

    return out;
}
