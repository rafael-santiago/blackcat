/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <keychain/processor.h>
#include <util/random.h>
#include <kryptos.h>
#include <ctype.h>

#define BLACKCAT_OTP_K "BC OTP K"
#define BLACKCAT_OTP_C "BC OTP C"
#define BLACKCAT_OTP_D "BC OTP D"

struct blackcat_otp_chain_regs {
    blackcat_protlayer_chain_ctx *protlayer;
    blackcat_protlayer_chain_ctx *tail;
    blackcat_protlayer_chain_ctx *middle;
    blackcat_protlayer_chain_ctx *first_cascade_end;
};

static kryptos_u8_t *blackcat_meta_processor(const blackcat_protlayer_chain_ctx *protlayer,
                                             kryptos_u8_t *in, size_t in_size,
                                             size_t *out_size, kryptos_action_t action);

static kryptos_u8_t *blackcat_otp_meta_processor(const blackcat_protlayer_chain_ctx *protlayer,
                                                 kryptos_u8_t *in, size_t in_size,
                                                 size_t *out_size, kryptos_action_t action);

static void blackcat_otp_chain_regs_init(struct blackcat_otp_chain_regs *regs);

static void blackcat_otp_chain_regs_deinit(struct blackcat_otp_chain_regs *regs);

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

kryptos_u8_t *blackcat_otp_encrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                        kryptos_u8_t *in, size_t in_size,
                                        size_t *out_size) {
    return blackcat_otp_meta_processor(protlayer, in, in_size, out_size, kKryptosEncrypt);
}

kryptos_u8_t *blackcat_otp_decrypt_data(const blackcat_protlayer_chain_ctx *protlayer,
                                        kryptos_u8_t *in, size_t in_size,
                                        size_t *out_size) {
    return blackcat_otp_meta_processor(protlayer, in, in_size, out_size, kKryptosDecrypt);
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

static void blackcat_otp_chain_regs_init(struct blackcat_otp_chain_regs *regs) {
    size_t protlayer_nr = 0, p;

    regs->tail = regs->protlayer->tail;

    for (regs->middle = regs->protlayer; regs->middle != NULL; regs->middle = regs->middle->next) {
        protlayer_nr += 1;
    }

    if (protlayer_nr > 1) {
        protlayer_nr = protlayer_nr >> 1;
        p = 0;

        for (regs->middle = regs->protlayer; p < protlayer_nr && regs->middle != NULL; regs->middle = regs->middle->next) {
            p += 1;
        }

        regs->first_cascade_end = regs->middle->last;
        regs->first_cascade_end->next = NULL;
        regs->protlayer->tail = regs->first_cascade_end;
        if (regs->middle != NULL) {
            regs->middle->head = regs->middle;
            for (regs->middle->tail = regs->middle;
                 regs->middle->tail->next != NULL;
                 regs->middle->tail = regs->middle->tail->next)
                ;
            regs->middle->last = NULL;
        }
    } else {
        regs->middle = regs->protlayer;
    }
}

static void blackcat_otp_chain_regs_deinit(struct blackcat_otp_chain_regs *regs) {
    if (regs->tail != NULL) {
        regs->protlayer->tail = regs->tail;
        regs->tail = NULL;
    }
    if (regs->first_cascade_end != NULL) {
        regs->first_cascade_end->next = regs->middle;
        if (regs->middle != NULL) {
            regs->middle->last = regs->first_cascade_end;
        }
        regs->first_cascade_end = NULL;
    }

    if (regs->middle != NULL && regs->middle != regs->protlayer) {
        regs->middle->head = NULL;
        regs->middle->tail = NULL;
        regs->middle = NULL;
    }
}

static kryptos_u8_t *blackcat_otp_meta_processor(const blackcat_protlayer_chain_ctx *protlayer,
                                                 kryptos_u8_t *in, size_t in_size,
                                                 size_t *out_size, kryptos_action_t action) {
    // INFO(Rafael): This meta processor implements the idea given by Bruce Schneier in his
    //               book "Applied Cryptography" with some additional steps.
    //
    //               The encryption "roadmap" is:
    //                  - find the middle m of the cascade (btw, protlayer is the cascade here);
    //                  - generate a random block r of in_size bytes;
    //                  - encrypt in -> (in ^ r) -> (in ^ r)';
    //                  - encrypt r with the cascade from protlayer until m -> (r');
    //                  - encrypt (in ^ r) with the cascade from m until its end;
    //                  - [Additional step]: encode (in ^ r)' and r' as PEM -> ep'
    //                  - [Additional step]: generate random random pads with random lengths l and r;
    //                  - [Additional step]: concatenate l || ep' || r -> LEPR'
    //                  - [Additional step]: encrypt LEPR' with the entire cascade -> C';
    //
    kryptos_u8_t *out = NULL, *temp = NULL;
    kryptos_u8_t *r = NULL, *xp = NULL, *ip_end, *ip, *data = NULL;
    size_t protlayer_nr = 0, p, xp_size, data_size, temp_size = 0, ip_size;
    kryptos_task_ctx t, *ktask = &t;
    struct blackcat_otp_chain_regs regs;

    regs.protlayer = (blackcat_protlayer_chain_ctx *)protlayer;
    regs.middle = regs.first_cascade_end = NULL;

    kryptos_task_init_as_null(ktask);

    if (action == kKryptosEncrypt) {
        blackcat_otp_chain_regs_init(&regs);

        // INFO(Rafael): Xoring in ^ r.

        if ((r = kryptos_get_random_block(in_size)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        if ((xp = (kryptos_u8_t *)kryptos_newseg(in_size)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        xp_size = in_size;

        ip = in;
        ip_end = in + in_size;

        while (ip != ip_end) {
            *xp = *ip ^ *r;
            xp++;
            ip++;
            r++;
        }

        r -= in_size;
        xp -= xp_size;

        ip = NULL;

        // INFO(Rafael): Encrypting r.

        data = blackcat_meta_processor(regs.protlayer, r, in_size, &data_size, kKryptosEncrypt);

        if (data == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        if (kryptos_pem_put_data(&temp, &temp_size, BLACKCAT_OTP_K, data, data_size) != kKryptosSuccess) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        kryptos_freeseg(data, data_size);

        // INFO(Rafael): Encrypting in ^ r.

        data = blackcat_meta_processor(regs.middle, xp, xp_size, &data_size, kKryptosEncrypt);

        if (data == NULL) {
            kryptos_freeseg(temp, temp_size);
            temp = NULL;
            temp_size = 0;
            goto blackcat_otp_meta_processor_epilogue;
        }

        kryptos_freeseg(xp, xp_size);
        xp = NULL;

        if (kryptos_pem_put_data(&temp, &temp_size, BLACKCAT_OTP_C, data, data_size) != kKryptosSuccess) {
            kryptos_freeseg(temp, temp_size);
            temp = NULL;
            temp_size = 0;
            goto blackcat_otp_meta_processor_epilogue;
        }

        kryptos_freeseg(data, data_size);
        data = NULL;

        // INFO(Rafael): Random padding LR and PEM encoding.

        if ((xp = random_printable_padding(&xp_size)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        if ((data = random_printable_padding(&data_size)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        *out_size = temp_size + xp_size + data_size;

        if ((out = (kryptos_u8_t *)kryptos_newseg(*out_size)) == NULL) {
            *out_size = 0;
            goto blackcat_otp_meta_processor_epilogue;
        }

        memcpy(out, xp, xp_size);
        memcpy(out + xp_size, temp, temp_size);
        memcpy(out + xp_size + temp_size, data, data_size);

        kryptos_freeseg(data, data_size);
        data = NULL;

        kryptos_freeseg(xp, xp_size);
        xp = NULL;

        kryptos_freeseg(temp, temp_size);
        temp = out;
        temp_size = *out_size;
        out = NULL;
        *out_size = 0;

        blackcat_otp_chain_regs_deinit(&regs);

        // INFO(Rafael): Encrypt by using the entire cascade.

        if ((data = blackcat_meta_processor(protlayer, temp, temp_size, &data_size, kKryptosEncrypt)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        kryptos_freeseg(temp, temp_size);
        temp = NULL;

        if (kryptos_pem_put_data(&out, out_size, BLACKCAT_OTP_D, data, data_size) != kKryptosSuccess) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        if (protlayer->encoder != NULL) {
            ktask->in = out;
            ktask->in_size = *out_size;

            kryptos_task_set_encode_action(ktask);
            protlayer->head->encoder(&ktask);

            if (!kryptos_last_task_succeed(ktask)) {
                goto blackcat_otp_meta_processor_epilogue;
            }

            out = ktask->out;
            *out_size = ktask->out_size;

            ktask->out = NULL;
            ktask->out_size = 0;
        }
    } else if (action == kKryptosDecrypt) {
        if (protlayer->encoder != NULL) {
            ktask->in = in;
            ktask->in_size = in_size;

            kryptos_task_set_decode_action(ktask);
            protlayer->head->encoder(&ktask);

            ktask->in = NULL;
            ktask->in_size = 0;

            if (!kryptos_last_task_succeed(ktask)) {
                goto blackcat_otp_meta_processor_epilogue;
            }

            temp = kryptos_pem_get_data(BLACKCAT_OTP_D, ktask->out, ktask->out_size, &temp_size);
            kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
        } else {
            temp = kryptos_pem_get_data(BLACKCAT_OTP_D, in, in_size, &temp_size);
        }

        if (temp == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        if ((data = blackcat_meta_processor(protlayer, temp, temp_size, &data_size, kKryptosDecrypt)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        kryptos_freeseg(temp, temp_size);

        if ((temp = kryptos_pem_get_data(BLACKCAT_OTP_K, data, data_size, &temp_size)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        blackcat_otp_chain_regs_init(&regs);

        if ((xp = blackcat_meta_processor(regs.protlayer, temp, temp_size, &xp_size, kKryptosDecrypt)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        kryptos_freeseg(temp, temp_size);

        if ((temp = kryptos_pem_get_data(BLACKCAT_OTP_C, data, data_size, &temp_size)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        if ((ip = blackcat_meta_processor(regs.middle, temp, temp_size, &ip_size, kKryptosDecrypt)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        kryptos_freeseg(temp, temp_size);

        ip_end = ip + ip_size;

        if ((out = (kryptos_u8_t *)kryptos_newseg(ip_size)) == NULL) {
            goto blackcat_otp_meta_processor_epilogue;
        }

        *out_size = ip_size;

        temp = out;

        while (ip != ip_end) {
            *temp = *ip ^ *xp;
            xp++;
            ip++;
            temp++;
        }

        temp = NULL;

        xp -= xp_size;
        ip -= ip_size;
    }

blackcat_otp_meta_processor_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN);

    blackcat_otp_chain_regs_deinit(&regs);

    if (temp != NULL) {
        kryptos_freeseg(temp, temp_size);
    }

    if (r != NULL) {
        kryptos_freeseg(r, in_size);
    }

    if (xp != NULL) {
        kryptos_freeseg(xp, xp_size);
    }

    if (ip != NULL) {
        kryptos_freeseg(ip, ip_size);
    }

    if (data != NULL) {
        kryptos_freeseg(data, data_size);
    }

    ip = ip_end = NULL;


    return out;
}

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

#undef BLACKCAT_OTP_K
#undef BLACKCAT_OTP_C
#undef BLACKCAT_OTP_D
