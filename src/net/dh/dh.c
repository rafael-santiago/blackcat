/*
 *                          Copyright (C) 2019 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <net/dh/dh.h>
#include <kbd/kbd.h>
#include <kryptos_endianness_utils.h>
#include <accacia.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BLACKCAT_SESSION_KEY "BC SESSION KEY"

static kryptos_u8_t *encrypt_decrypt_session_key(kryptos_u8_t *session_key, const size_t session_key_size,
                                                 kryptos_u8_t *key, const size_t key_size, size_t *out_size,
                                                 const int decrypt);

static kryptos_u8_t *get_mp_as_raw_buf(kryptos_mp_value_t *mp, size_t *buf_size);

#define encrypt_session_key(s, s_sz, k, k_sz, o_sz) encrypt_decrypt_session_key(s, s_sz, k, k_sz, o_sz, 0)

#define decrypt_session_key(s, s_sz, k, k_sz, o_sz) encrypt_decrypt_session_key(s, s_sz, k, k_sz, o_sz, 1)

int skey_xchg_server(struct skey_xchg_ctx *sx) {
    int err = EINVAL;
    kryptos_u8_t *skey[2] = { NULL, NULL };
    size_t skey_size[2];
    int sockfd = -1, csockfd = -1;
    struct sockaddr_in sk_in;
    socklen_t sk_in_len;
    struct kryptos_dh_xchg_ctx dh_ctx, *dh = &dh_ctx;
    kryptos_u8_t *epk = NULL, *enc_session_key = NULL;
    size_t epk_size, enc_session_key_size;

    sx->session_key = NULL;
    sx->session_key_size = 0;
    sx->ret = err;

    kryptos_dh_init_xchg_ctx(dh);

    // INFO(Rafael): Reading the user session key.

    accacia_savecursorposition();

    if (sx->key_size == 0) {
        fprintf(stdout, "Session key: ");
        if ((skey[0] = blackcat_getuserkey(&skey_size[0])) == NULL) {
            fprintf(stderr, "ERROR: NULL session key.\n");
            fflush(stderr);
            err = EFAULT;
            goto skey_xchg_server_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        fprintf(stdout, "Re-type the session key: ");
        if ((skey[1] = blackcat_getuserkey(&skey_size[1])) == NULL) {
            fprintf(stderr, "ERROR: NULL session key.\n");
            fflush(stderr);
            err = EFAULT;
            goto skey_xchg_server_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        if (skey_size[0] != skey_size[1] || memcmp(skey[0], skey[1], skey_size[0]) != 0) {
            fprintf(stderr, "ERROR: The key does not match with its confirmation.\n");
            err = EFAULT;
            goto skey_xchg_server_epilogue;
        }
    } else {
        if ((skey[0] = kryptos_get_random_block(sx->key_size)) == NULL) {
            err = EFAULT;
            fprintf(stderr, "ERROR: Unable to get a random block.\n");
            goto skey_xchg_server_epilogue;
        }
    }

    // INFO(Rafael): Listening to incoming connections. With DH modified, we will not authenticate anything.
    //               Supposing that only the client will actually have her/his private key.

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd == -1) {
        err = errno;
        fprintf(stderr, "ERROR: When creating the socket.\n");
        goto skey_xchg_server_epilogue;
    }

    sk_in.sin_family = AF_INET;
    sk_in.sin_port = htons(sx->port);
    sk_in.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&sk_in, sizeof(sk_in)) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: When binding the socket.\n");
        goto skey_xchg_server_epilogue;
    }

    if (listen(sockfd, 1) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: When listening.\n");
        goto skey_xchg_server_epilogue;
    }

    sk_in_len = sizeof(sk_in);
    csockfd = accept(sockfd, (struct sockaddr *)&sk_in, &sk_in_len);

    if (csockfd == -1) {
        err = errno;
        fprintf(stderr, "ERROR: When accepting the incoming connection.\n");
        goto skey_xchg_server_epilogue;
    }

    // INFO(Rafael): Calculating the ephemeral key.

    dh->in = sx->k_pub;
    dh->in_size = sx->k_pub_size;
    dh->s_bits = sx->s_bits;

    kryptos_dh_process_modxchg(&dh);

    if (!kryptos_last_task_succeed(dh)) {
        err = EFAULT;
        fprintf(stderr, "ERROR: Error when evaluating values to key exchange.\n");
        goto skey_xchg_server_epilogue;
    }

    // INFO(Rafael): Encrypting the session key by using the ephemeral key.

    if ((epk = get_mp_as_raw_buf(dh->k, &epk_size)) == NULL) {
        err = EFAULT;
        fprintf(stderr, "ERROR: Unable to access the session key.\n");
        goto skey_xchg_server_epilogue;
    }

    enc_session_key = encrypt_session_key(skey[0], skey_size[0], epk, epk_size, &enc_session_key_size);

    if (kryptos_pem_put_data(&dh->out,
                             &dh->out_size, BLACKCAT_SESSION_KEY, enc_session_key, enc_session_key_size) != kKryptosSuccess) {
        err = EFAULT;
        fprintf(stderr, "ERROR: When preparing to exchange the session key.\n");
        goto skey_xchg_server_epilogue;
    }

    // INFO(Rafael): Sending (as PEM data) the DH parameters besides the encrypted session key.

    if (send(csockfd, dh->out, dh->out_size, 0) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: While exchanging the session key.\n");
        goto skey_xchg_server_epilogue;
    }

    err = 0;

skey_xchg_server_epilogue:

    if (csockfd != -1) {
        close(csockfd);
    }

    if (sockfd != -1) {
        close(sockfd);
    }

    kryptos_clear_dh_xchg_ctx(dh);

    if (skey[0] != NULL) {
        kryptos_freeseg(skey[0], skey_size[0]);
    }

    if (skey[1] != NULL) {
        kryptos_freeseg(skey[1], skey_size[1]);
    }

    if (enc_session_key != NULL) {
        kryptos_freeseg(enc_session_key, enc_session_key_size);
    }

    if (epk != NULL) {
        kryptos_freeseg(epk, epk_size);
    }

    sx->ret = err;

    return err;
}

int skey_xchg_client(struct skey_xchg_ctx *sx) {
    int err = EINVAL;
    int sockfd;
    struct sockaddr_in sk_in;
    struct hostent *hp;
    kryptos_u8_t buf[0xFFFF];
    ssize_t buf_size;
    struct kryptos_dh_xchg_ctx dh_ctx, *dh = &dh_ctx;
    kryptos_u8_t *epk = NULL, *enc_session_key;
    size_t epk_size, enc_session_key_size;

    sx->session_key = NULL;
    sx->session_key_size = 0;
    sx->ret = err;

    kryptos_dh_init_xchg_ctx(dh);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd == -1) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to create a socket.\n");
        goto skey_xchg_client_epilogue;
    }

    sk_in.sin_family = AF_INET;
    sk_in.sin_port = htons(sx->port);

    if ((hp = gethostbyname(sx->addr)) == NULL) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to resolve the host name.\n");
        goto skey_xchg_client_epilogue;
    }

    sk_in.sin_addr.s_addr = ((struct in_addr *)hp->h_addr_list[0])->s_addr;

    if (connect(sockfd, (struct sockaddr *)&sk_in, sizeof(sk_in)) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to connect to the host.\n");
        goto skey_xchg_client_epilogue;
    }

    if ((buf_size = recv(sockfd, buf, sizeof(buf) - 1, 0)) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to receive data.\n");
        goto skey_xchg_client_epilogue;
    }

    dh->in_size = buf_size + sx->k_priv_size;
    if ((dh->in = (kryptos_u8_t *)kryptos_newseg(dh->in_size)) == NULL) {
        err = ENOMEM;
        fprintf(stderr, "ERROR: Not enough memory.\n");
        goto skey_xchg_client_epilogue;
    }

    enc_session_key = kryptos_pem_get_data(BLACKCAT_SESSION_KEY, buf, buf_size, &enc_session_key_size);

    if (enc_session_key == NULL) {
        err = EFAULT;
        fprintf(stderr, "ERROR: The message seems not contain the encrypted session key.\n");
        goto skey_xchg_client_epilogue;
    }

    memcpy(dh->in, buf, buf_size);
    memcpy(dh->in + buf_size, sx->k_priv, sx->k_priv_size);
    dh->s_bits = sx->s_bits;

    kryptos_dh_process_modxchg(&dh);

    if (!kryptos_last_task_succeed(dh)) {
        err = EFAULT;
        fprintf(stderr, "ERROR: Unable to calculate the session key.\n");
        goto skey_xchg_client_epilogue;
    }

    if ((epk = get_mp_as_raw_buf(dh->k, &epk_size)) == NULL) {
        err = EFAULT;
        fprintf(stderr, "ERROR: Unable to access the session key.\n");
        goto skey_xchg_client_epilogue;
    }

    sx->session_key = decrypt_session_key(enc_session_key, enc_session_key_size, epk, epk_size, &sx->session_key_size);

    if (sx->session_key == NULL) {
        err = EFAULT;
        fprintf(stderr, "ERROR: Unable to decrypt the session key.\n");
    }

    err = 0;

skey_xchg_client_epilogue:

    if (sockfd != -1) {
        close(sockfd);
    }

    kryptos_clear_dh_xchg_ctx(dh);

    if (epk != NULL) {
        kryptos_freeseg(epk, epk_size);
    }

    if (enc_session_key != NULL) {
        kryptos_freeseg(enc_session_key, enc_session_key_size);
    }

    sx->ret = err;

    memset(buf, 0, sizeof(buf));

    return err;
}

static kryptos_u8_t *encrypt_decrypt_session_key(kryptos_u8_t *session_key, const size_t session_key_size,
                                                 kryptos_u8_t *key, const size_t key_size, size_t *out_size,
                                                 const int decrypt) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *fkey = NULL;
    size_t fkey_size = 32;

    kryptos_task_init_as_null(ktask);

    fkey = kryptos_hkdf(key, key_size, sha3_512, "", 0, "", 0, fkey_size);

    if (fkey == NULL) {
        goto encrypt_session_key_epilogue;
    }

    ktask->in = session_key;
    ktask->in_size = session_key_size;

    if (!decrypt) {
        kryptos_task_set_encrypt_action(ktask);
    } else {
        kryptos_task_set_decrypt_action(ktask);
    }

    kryptos_run_cipher_hmac(aes256, sha3_512, ktask, fkey, fkey_size, kKryptosCBC);

encrypt_session_key_epilogue:

    if (fkey != NULL) {
        kryptos_freeseg(fkey, fkey_size);
    }

    return ktask->out;
}

static kryptos_u8_t *get_mp_as_raw_buf(kryptos_mp_value_t *mp, size_t *buf_size) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *o;
    ssize_t o_size, d;

    kryptos_task_init_as_null(ktask);

    kryptos_mp_as_task_out(&ktask, mp, o, o_size, d, get_mp_as_raw_buf_epilogue);

get_mp_as_raw_buf_epilogue:

    *buf_size = ktask->out_size;

    return ktask->out;
}

#undef BLACKCAT_SESSION_KEY
#undef encrypt_session_key
#undef decrypt_session_key
