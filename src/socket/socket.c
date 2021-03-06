/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <socket/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/base/types.h>
#include <net/ctx/ctx.h>
#include <net/db/db.h>
#include <net/dh/dh.h>
#include <keychain/ciphering_schemes.h>
#include <keychain/processor.h>
#include <kbd/kbd.h>
#include <kryptos.h>
#include <accacia.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#if defined(BCSCK_THREAD_SAFE)
# include <pthread.h>
#endif
#include <errno.h>

#ifndef RTLD_NEXT
# define RTLD_NEXT ((void *)-1)
#endif

struct bcsck_handle_ctx {
    int (*libc_socket)(int domain, int type, int protocol);
    ssize_t (*libc_recv)(int sockfd, void *buf, size_t len, int flags);
    ssize_t (*libc_recvfrom)(int sockfd, void *buf, size_t len, int flags,
                             struct sockaddr *src_addr, socklen_t *addrlen);
    ssize_t (*libc_recvmsg)(int sockfd, struct msghdr *msg, int flags);
    ssize_t (*libc_read)(int fd, void *buf, size_t count);
    ssize_t (*libc_send)(int sockfd, const void *buf, size_t len, int flags);
    ssize_t (*libc_sendto)(int sockfd, const void *buf, size_t len, int flags,
                           const struct sockaddr *dest_addr, socklen_t addrlen);
    ssize_t (*libc_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
    ssize_t (*libc_write)(int fd, const void *buf, size_t count);
    bnt_channel_rule_ctx *rule;
#if defined(BCSCK_THREAD_SAFE)
    pthread_mutex_t mtx_recv_func, mtx_recvfrom_func, mtx_recvmsg_func, mtx_read_func,
                    mtx_send_func, mtx_sendto_func, mtx_sendmsg_func, mtx_write_func,
                    mtx_socket_func, mtx_set_protlayer_by_seqno_func;
#endif
    int libc_loaded, e2ee_conn, sockfd;
    char xchg_addr[255];
    unsigned short xchg_port;
    bnt_keyset_ctx *keyset;
};

struct bcsck_handle_ctx *g_bcsck_handle = NULL;

bnt_keyset_ctx ks[2];

#if !defined(__NetBSD__)
# define SOCKET_FUNC_ENDPOINT "socket"
#else
// WARN(Rafael): If you call socket() in NetBSD you will get a stack overflow, because
//               socket is just a stub for __socket30().
# define SOCKET_FUNC_ENDPOINT "__socket30"
#endif

#if defined(BCSCK_THREAD_SAFE)

#define __bcsck_prologue(return_stmt) {\
    if (!g_bcsck_handle->libc_loaded) {\
        g_bcsck_handle->libc_socket = dlsym(RTLD_NEXT, SOCKET_FUNC_ENDPOINT);\
        g_bcsck_handle->libc_recv = dlsym(RTLD_NEXT, "recv");\
        g_bcsck_handle->libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");\
        g_bcsck_handle->libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");\
        g_bcsck_handle->libc_read = dlsym(RTLD_NEXT, "read");\
        g_bcsck_handle->libc_send = dlsym(RTLD_NEXT, "send");\
        g_bcsck_handle->libc_sendto = dlsym(RTLD_NEXT, "sendto");\
        g_bcsck_handle->libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");\
        g_bcsck_handle->libc_write = dlsym(RTLD_NEXT, "write");\
        g_bcsck_handle->libc_loaded = (g_bcsck_handle->libc_socket != NULL) &&\
                                     (g_bcsck_handle->libc_recv != NULL) &&\
                                     (g_bcsck_handle->libc_recvfrom != NULL) &&\
                                     (g_bcsck_handle->libc_recvmsg != NULL) &&\
                                     (g_bcsck_handle->libc_read != NULL) &&\
                                     (g_bcsck_handle->libc_send != NULL) &&\
                                     (g_bcsck_handle->libc_sendto != NULL) &&\
                                     (g_bcsck_handle->libc_sendmsg != NULL) &&\
                                     (g_bcsck_handle->libc_write != NULL) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_recv_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_recvfrom_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_recvmsg_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_read_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_send_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_sendto_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_sendmsg_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_write_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_socket_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle->mtx_set_protlayer_by_seqno_func, NULL) == 0);\
    }\
    if (!g_bcsck_handle->libc_loaded) {\
        return_stmt;\
    }\
    if (g_bcsck_handle->rule == NULL) {\
        if (bcsck_read_rule() != 0) {\
            return_stmt;\
        }\
    }\
}

#define __bcsck_epilogue {\
    g_bcsck_handle->libc_loaded = 0;\
    g_bcsck_handle->libc_socket = NULL;\
    g_bcsck_handle->libc_recv = NULL;\
    g_bcsck_handle->libc_recvfrom = NULL;\
    g_bcsck_handle->libc_recvmsg = NULL;\
    g_bcsck_handle->libc_read = NULL;\
    g_bcsck_handle->libc_send = NULL;\
    g_bcsck_handle->libc_sendto = NULL;\
    g_bcsck_handle->libc_sendmsg = NULL;\
    g_bcsck_handle->libc_write = NULL;\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_recv_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_recvfrom_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_recvmsg_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_read_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_send_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_sendto_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_sendmsg_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_write_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_socket_func);\
    pthread_mutex_destroy(&g_bcsck_handle->mtx_set_protlayer_by_seqno_func);\
}

#define __bcsck_enter(sock_func) {\
    pthread_mutex_lock(&g_bcsck_handle->mtx_ ## sock_func ## _func);\
}

#define __bcsck_leave(sock_func) {\
    pthread_mutex_unlock(&g_bcsck_handle->mtx_ ## sock_func ## _func);\
}

#else

#define __bcsck_prologue(return_stmt) {\
    if (!g_bcsck_handle->libc_loaded) {\
        g_bcsck_handle->libc_socket = dlsym(RTLD_NEXT, SOCKET_FUNC_ENDPOINT);\
        g_bcsck_handle->libc_recv = dlsym(RTLD_NEXT, "recv");\
        g_bcsck_handle->libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");\
        g_bcsck_handle->libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");\
        g_bcsck_handle->libc_read = dlsym(RTLD_NEXT, "read");\
        g_bcsck_handle->libc_send = dlsym(RTLD_NEXT, "send");\
        g_bcsck_handle->libc_sendto = dlsym(RTLD_NEXT, "sendto");\
        g_bcsck_handle->libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");\
        g_bcsck_handle->libc_write = dlsym(RTLD_NEXT, "write");\
        g_bcsck_handle->libc_loaded = (g_bcsck_handle->libc_socket != NULL) &&\
                                     (g_bcsck_handle->libc_recv != NULL) &&\
                                     (g_bcsck_handle->libc_recvfrom != NULL) &&\
                                     (g_bcsck_handle->libc_recvmsg != NULL) &&\
                                     (g_bcsck_handle->libc_read != NULL) &&\
                                     (g_bcsck_handle->libc_send != NULL) &&\
                                     (g_bcsck_handle->libc_sendto != NULL) &&\
                                     (g_bcsck_handle->libc_sendmsg != NULL) &&\
                                     (g_bcsck_handle->libc_write != NULL);\
    }\
    if (!g_bcsck_handle->libc_loaded) {\
        return_stmt;\
    }\
    if (g_bcsck_handle->rule == NULL) {\
        if (bcsck_read_rule() != 0) {\
            return_stmt;\
        }\
    }\
}

#define __bcsck_epilogue {\
    g_bcsck_handle->libc_loaded = 0;\
    g_bcsck_handle->libc_socket = NULL;\
    g_bcsck_handle->libc_recv = NULL;\
    g_bcsck_handle->libc_recvfrom = NULL;\
    g_bcsck_handle->libc_recvmsg = NULL;\
    g_bcsck_handle->libc_read = NULL;\
    g_bcsck_handle->libc_send = NULL;\
    g_bcsck_handle->libc_sendto = NULL;\
    g_bcsck_handle->libc_sendmsg = NULL;\
    g_bcsck_handle->libc_write = NULL;\
}

#define __bcsck_enter(sock_func) {};

#define __bcsck_leave(sock_func) {};

#endif // defined(BCSCK_THREAD_SAFE)

#define bcsck_encrypt(ibuf, ibuf_size, obuf, obuf_size, esc_stmt) {\
    if ((obuf = blackcat_encrypt_data(g_bcsck_handle->rule->pchain,\
                                      (kryptos_u8_t *)ibuf, ibuf_size, &obuf_size)) == NULL) {\
        esc_stmt;\
    }\
}

#define bcsck_decrypt(ibuf, ibuf_size, obuf, obuf_size, esc_stmt) {\
    if ((obuf = blackcat_decrypt_data(g_bcsck_handle->rule->pchain,\
                                      (kryptos_u8_t *)ibuf, ibuf_size, &obuf_size)) == NULL) {\
        esc_stmt;\
    }\
}

#define bcsck_e2ee_decrypt_setup(offset, buf, buf_size, esc_stmt) {\
    if (g_bcsck_handle->e2ee_conn) {\
        offset = sizeof(kryptos_u64_t);\
        if (set_protlayer_by_recvd_buf(buf, buf_size, &g_bcsck_handle->keyset->recv_chain) == 0) {\
            esc_stmt;\
        }\
    } else {\
        offset = 0;\
    }\
}

#define bcsck_e2ee_encrypt_setup(send_buf, send_buf_size, esc_stmt) {\
    if (g_bcsck_handle->e2ee_conn) {\
        send_buf = (kryptos_u8_t *) kryptos_newseg(0xFFFF);\
        send_buf_size = 0xFFFF;\
        if (send_buf == NULL) {\
            esc_stmt;\
        }\
        if (set_protlayer_by_seqno(send_buf, send_buf_size, &g_bcsck_handle->keyset->send_chain) == 0) {\
            esc_stmt;\
        }\
    } else {\
        send_buf = NULL;\
    }\
}

#define bcsck_e2ee_post_proc(send_buf, send_buf_size, out_buf, out_buf_size, esc_stmt) {\
    if (g_bcsck_handle->e2ee_conn) {\
        if (send_buf_size < out_buf_size) {\
            esc_stmt;\
        }\
        memcpy(send_buf + sizeof(kryptos_u64_t), out_buf, out_buf_size);\
        kryptos_freeseg(out_buf, out_buf_size);\
        out_buf = send_buf;\
        out_buf_size += sizeof(kryptos_u64_t);\
    }\
}

#define BCSCK_DBPATH      "BCSCK_DBPATH"
#define BCSCK_RULE        "BCSCK_RULE"
#define BCSCK_E2EE        "BCSCK_E2EE"
#define BCSCK_XCHG_PORT   "BCSCK_PORT"
#define BCSCK_XCHG_ADDR   "BCSCK_ADDR"
#define BCSCK_KPRIV       "BCSCK_KPRIV"
#define BCSCK_KPUB        "BCSCK_KPUB"
#define BCSCK_S_BITS      "BCSCK_S_BITS"

#define BCSCK_SEQNO_WINDOW_SIZE 100

static void __attribute__((constructor)) bcsck_init(void);

static void __attribute__((destructor)) bcsck_deinit(void);

static int bcsck_read_rule(void);

static int do_xchg_server(void);

static int do_xchg_client(void);

static int set_protlayer_by_recvd_buf(const kryptos_u8_t *buf, const ssize_t buf_size, bnt_keychain_ctx **keychain);

static int set_protlayer_by_seqno(kryptos_u8_t *buf, const size_t buf_size, bnt_keychain_ctx **keychain);

int socket(int domain, int type, int protocol) {
    int err = -1;

__bcsck_enter(socket)

__bcsck_prologue(goto socket_epilogue)

    err = g_bcsck_handle->libc_socket(domain, type, protocol);

socket_epilogue:

__bcsck_leave(socket)

    return err;
}

static int set_protlayer_by_seqno(kryptos_u8_t *buf, const size_t buf_size, bnt_keychain_ctx **keychain) {
    kryptos_u64_t seqno;
    int no_error = 0;

__bcsck_enter(set_protlayer_by_seqno)

    if (buf_size <= sizeof(kryptos_u64_t)) {
        fprintf(stderr, "ERROR: Encrypting buffer is tiny.\n");
        goto set_protlayer_by_seqno_epilogue;
    }

    seqno = g_bcsck_handle->keyset->send_seqno;
    if (step_bnt_keyset(&g_bcsck_handle->keyset, seqno + 1, g_bcsck_handle->keyset->send_chain)) {
        g_bcsck_handle->keyset->send_seqno += 1;
    }

    if (set_protlayer_key_by_keychain_seqno(seqno, g_bcsck_handle->rule->pchain, keychain, &g_bcsck_handle->keyset) == 0) {
        fprintf(stderr, "ERROR: While setting up the encryption process.\n");
        goto set_protlayer_by_seqno_epilogue;
    }

    buf[0] = (seqno >> 56) & 0xFF;
    buf[1] = (seqno >> 48) & 0xFF;
    buf[2] = (seqno >> 40) & 0xFF;
    buf[3] = (seqno >> 32) & 0xFF;
    buf[4] = (seqno >> 24) & 0xFF;
    buf[5] = (seqno >> 16) & 0xFF;
    buf[6] = (seqno >>  8) & 0xFF;
    buf[7] = seqno & 0xFF;

    no_error = 1;

set_protlayer_by_seqno_epilogue:

__bcsck_leave(set_protlayer_by_seqno)

    return no_error;
}

static int set_protlayer_by_recvd_buf(const kryptos_u8_t *buf, const ssize_t buf_size, bnt_keychain_ctx **keychain) {
    kryptos_u64_t seqno;

    if (buf_size < sizeof(kryptos_u64_t) ) {
        return 0;
    }

    seqno = (((kryptos_u64_t)buf[0]) << 56) |
            (((kryptos_u64_t)buf[1]) << 48) |
            (((kryptos_u64_t)buf[2]) << 40) |
            (((kryptos_u64_t)buf[3]) << 32) |
            (((kryptos_u64_t)buf[4]) << 24) |
            (((kryptos_u64_t)buf[5]) << 16) |
            (((kryptos_u64_t)buf[6]) <<  8) | buf[7];

    if (seqno > g_bcsck_handle->keyset->recv_seqno) {
        if (step_bnt_keyset(&g_bcsck_handle->keyset, seqno, g_bcsck_handle->keyset->recv_chain) == 0) {
            fprintf(stderr, "WARN: A possible replay attack was detected.\n");
            return 0;
        }
    }

    if (set_protlayer_key_by_keychain_seqno(seqno, g_bcsck_handle->rule->pchain, keychain, &g_bcsck_handle->keyset) == 0) {
        if (get_bnt_keychain(seqno, *keychain) == NULL) {
            fprintf(stderr, "WARN: A possible replay attack was detected.\n");
        }
        return 0;
    }

    g_bcsck_handle->keyset->recv_seqno += 1;

    return 1;
}

#if !defined(__NetBSD__)

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    kryptos_u8_t *obuf = NULL, *rbuf = NULL;
    size_t obuf_size = 0, rbuf_size = 0;
    ssize_t bytes_nr;
    size_t rbuf_offset;

__bcsck_enter(recv)

    if ((rbuf = (kryptos_u8_t *) kryptos_newseg(0xFFFF)) == NULL) {
        errno = ENOMEM;
        bytes_nr = -1;
        goto recv_epilogue;
    }

    if ((rbuf_size = g_bcsck_handle->libc_recv(sockfd, rbuf, 0xFFFF, flags)) == -1) {
        bytes_nr = -1;
        goto recv_epilogue;
    }

    bcsck_e2ee_decrypt_setup(rbuf_offset, rbuf, rbuf_size, { errno = EFAULT; bytes_nr = -1; goto recv_epilogue; });

    bcsck_decrypt(rbuf + rbuf_offset, rbuf_size - rbuf_offset, obuf, obuf_size,
                  { bytes_nr = -1; errno = EFAULT; goto recv_epilogue; });

    if (obuf_size > len) {
        errno = EFAULT;
        bytes_nr = -1;
        goto recv_epilogue;
    }

    memcpy(buf, obuf, obuf_size);
    bytes_nr = obuf_size;

recv_epilogue:

    if (rbuf != NULL) {
        kryptos_freeseg(rbuf, 0xFFFF);
        rbuf = NULL;
        rbuf_size = 0;
    }

    if (obuf != NULL) {
        kryptos_freeseg(obuf, obuf_size);
        obuf = NULL;
        obuf_size = 0;
    }

__bcsck_leave(recv)

    return bytes_nr;
}

#else

// WARN(Rafael): Emulating the stub behavior of the original recv in NetBSD.

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    ssize_t bytes_nr;

__bcsck_enter(recv)

    bytes_nr = recvfrom(sockfd, buf, len, flags, NULL, 0);

__bcsck_leave(recv)

    return bytes_nr;
}

#endif

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    kryptos_u8_t *obuf = NULL, *rbuf = NULL;
    size_t obuf_size = 0, rbuf_size = 0;
    ssize_t bytes_nr;
    size_t rbuf_offset;

__bcsck_enter(recvfrom)

    if ((rbuf = (kryptos_u8_t *) kryptos_newseg(0xFFFF)) == NULL) {
        errno = ENOMEM;
        bytes_nr = -1;
        goto recvfrom_epilogue;
    }

    if ((rbuf_size = g_bcsck_handle->libc_recvfrom(sockfd, rbuf, 0xFFFF, flags, src_addr, addrlen)) == -1) {
        bytes_nr = -1;
        goto recvfrom_epilogue;
    }

    bcsck_e2ee_decrypt_setup(rbuf_offset, rbuf, rbuf_size, { errno = EFAULT; bytes_nr = -1; goto recvfrom_epilogue; });

    bcsck_decrypt(rbuf + rbuf_offset, rbuf_size - rbuf_offset, obuf, obuf_size,
                  { bytes_nr = -1; errno = EFAULT; goto recvfrom_epilogue; });

    if (obuf_size > len) {
        errno = EFAULT;
        bytes_nr = -1;
        goto recvfrom_epilogue;
    }

    memcpy(buf, obuf, obuf_size);
    bytes_nr = obuf_size;

recvfrom_epilogue:

    if (rbuf != NULL) {
        kryptos_freeseg(rbuf, 0xFFFF);
        rbuf = NULL;
        rbuf_size = 0;
    }

    if (obuf != NULL) {
        kryptos_freeseg(obuf, obuf_size);
        obuf = NULL;
        obuf_size = 0;
    }

__bcsck_leave(recvfrom)

    return bytes_nr;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    kryptos_u8_t *rbuf = NULL, *obuf = NULL, *ob, *ob_end;
    size_t rbuf_size = 0, obuf_size = 0, ob_size, temp_size;
    ssize_t bytes_nr;
    size_t iov_c;
    struct msghdr rmsg;
    struct iovec iov;
    size_t rbuf_offset;

    if (msg == NULL) {
        errno = EINVAL;
        return -1;
    }

__bcsck_enter(recvmsg)

    if ((rbuf = (kryptos_u8_t *) kryptos_newseg(0xFFFF)) == NULL) {
        errno = ENOMEM;
        bytes_nr = -1;
        goto recvmsg_epilogue;
    }

    rmsg.msg_name = msg->msg_name;
    rmsg.msg_namelen = msg->msg_namelen;
    rmsg.msg_iov = &iov;
    rmsg.msg_iovlen = 1;
#if !defined(__sun__)
    rmsg.msg_control = msg->msg_control;
    rmsg.msg_controllen = msg->msg_controllen;
#elif defined(__sun__) && defined(_XPG4_2)
    rmsg.msg_control = msg->msg_control;
    rmsg.msg_controllen = msg->msg_controllen;
    rmsg.msg_flags = msg->msg_flags;
#elif defined(__sun__) && !defined(_XPG_2)
    rmsg.msg_accrights = msg->msg_accrights;
    rmsg.msg_accrightslen = msg->msg_accrightslen;
#endif

    iov.iov_base = rbuf;
    iov.iov_len = 0xFFFF;

    if ((rbuf_size = g_bcsck_handle->libc_recvmsg(sockfd, &rmsg, flags)) == -1) {
        errno = EFAULT;
        bytes_nr = -1;
        goto recvmsg_epilogue;
    }

    memset(&rmsg, 0, sizeof(rmsg));
    memset(&iov, 0, sizeof(iov));

    bcsck_e2ee_decrypt_setup(rbuf_offset, rbuf, rbuf_size, { errno = EFAULT; bytes_nr = -1; goto recvmsg_epilogue; });

    bcsck_decrypt(rbuf + rbuf_offset, rbuf_size - rbuf_offset, obuf, obuf_size,
                  { errno = EFAULT; bytes_nr = -1; goto recvmsg_epilogue; });

    bytes_nr = 0;

    for (iov_c = 0; iov_c < msg->msg_iovlen; iov_c++) {
        bytes_nr += msg->msg_iov[iov_c].iov_len;
    }

    if (obuf_size > bytes_nr) {
        // INFO(Rafael): The message will not fit into the user's data ancillary stuff.
        bytes_nr = -1;
        errno = EFAULT;
        goto recvmsg_epilogue;
    }

    bytes_nr = obuf_size;

    ob = obuf;
    ob_end = ob + obuf_size;
    temp_size = obuf_size;

    for (iov_c = 0; ob < ob_end && iov_c < msg->msg_iovlen; iov_c++) {
        ob_size = MIN(msg->msg_iov[iov_c].iov_len, temp_size);
        memcpy(msg->msg_iov[iov_c].iov_base, ob, ob_size);
        ob += ob_size;
        temp_size -= ob_size;
    }

    temp_size = 0;

recvmsg_epilogue:

    if (rbuf != NULL) {
        kryptos_freeseg(rbuf, rbuf_size);
        rbuf = NULL;
        rbuf_size = 0;
    }

    if (obuf != NULL) {
        kryptos_freeseg(obuf, obuf_size);
        obuf = NULL;
        obuf_size = 0;
    }

__bcsck_leave(recvmsg)

    return bytes_nr;
}

ssize_t read(int fd, void *buf, size_t count) {
    kryptos_u8_t *rbuf = NULL, *obuf = NULL;
    ssize_t rbuf_size = 0, obuf_size = 0;
    ssize_t bytes_nr;
    struct sockaddr addr;
    socklen_t addrl;
    struct stat st;
    int is_sock = 0;
    size_t rbuf_offset;

    if (fstat(fd, &st) == 0 && (is_sock = S_ISSOCK(st.st_mode))) {

        // WARN(Rafael): Otherwise you will get a deadlock.
        __bcsck_enter(read)
        if ((rbuf = (kryptos_u8_t *) kryptos_newseg(0xFFFF)) == NULL) {
            errno = ENOMEM;
            bytes_nr = -1;
            goto read_epilogue;
        }

        if ((rbuf_size = g_bcsck_handle->libc_read(fd, rbuf, 0xFFFF)) == -1) {
            bytes_nr = -1;
            goto read_epilogue;
        }

        bcsck_e2ee_decrypt_setup(rbuf_offset, rbuf, rbuf_size, { errno = EFAULT; bytes_nr = -1; goto read_epilogue; })

        bcsck_decrypt(rbuf + rbuf_offset, rbuf_size - rbuf_offset,
                      obuf, obuf_size, { bytes_nr = -1; errno = EFAULT; goto read_epilogue; });

        if (obuf_size > count) {
            errno = EFAULT;
            bytes_nr = -1;
        }

        memcpy(buf, obuf, obuf_size);
        bytes_nr = obuf_size;
    } else {
        bytes_nr = g_bcsck_handle->libc_read(fd, buf, count);
    }

read_epilogue:

    if (rbuf != NULL) {
        kryptos_freeseg(rbuf, rbuf_size);
        rbuf = NULL;
        rbuf_size = 0;
    }

    if (obuf != NULL) {
        kryptos_freeseg(obuf, obuf_size);
        obuf = NULL;
        obuf_size = 0;
    }

    if (is_sock) {
        __bcsck_leave(read)
    }

    return bytes_nr;
}

#if !defined(__NetBSD__)

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    kryptos_u8_t *obuf = NULL;
    size_t obuf_size;
    ssize_t bytes_nr;
    kryptos_u8_t *sbuf = NULL;
    ssize_t sbuf_size;

__bcsck_enter(send)

    bcsck_e2ee_encrypt_setup(sbuf, sbuf_size, { bytes_nr = -1; goto send_epilogue; });

    bcsck_encrypt(buf, len, obuf, obuf_size, { bytes_nr = -1; goto send_epilogue; });

    bcsck_e2ee_post_proc(sbuf, sbuf_size, obuf, obuf_size, { bytes_nr = -1; goto send_epilogue; });

    if (obuf_size > 0xFFFF) {
        // INFO(Rafael): The effective message became too long. The user application will caught it
        //               retrying with a short buffer and hopefully we will got the encrypted data flowing
        //               to its destination at the next time.
        errno = EMSGSIZE;
        bytes_nr = -1;
        goto send_epilogue;
    }

    if ((bytes_nr = g_bcsck_handle->libc_send(sockfd, obuf, obuf_size, flags)) != -1) {
        bytes_nr = len;
    }

send_epilogue:

    if (obuf != NULL && obuf != sbuf) {
        kryptos_freeseg(obuf, obuf_size);
    }

    obuf = NULL;
    obuf_size = 0;


    if (sbuf != NULL) {
        kryptos_freeseg(sbuf, sbuf_size);
        sbuf = NULL;
        sbuf_size = 0;
    }

__bcsck_leave(send)

    return bytes_nr;
}

#else

// WARN(Rafael): Emulating the stub behavior of the original send in NetBSD.

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    ssize_t bytes_nr;

__bcsck_enter(send)

    bytes_nr = sendto(sockfd, buf, len, flags, NULL, 0);

__bcsck_leave(send)

    return bytes_nr;
}

#endif

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    kryptos_u8_t *obuf = NULL;
    size_t obuf_size;
    ssize_t bytes_nr;
    kryptos_u8_t *sbuf = NULL;
    ssize_t sbuf_size;

__bcsck_enter(sendto)

    bcsck_e2ee_encrypt_setup(sbuf, sbuf_size, { bytes_nr = -1; goto sendto_epilogue; });

    bcsck_encrypt(buf, len, obuf, obuf_size, { bytes_nr = -1; goto sendto_epilogue; });

    bcsck_e2ee_post_proc(sbuf, sbuf_size, obuf, obuf_size, { bytes_nr = -1; goto sendto_epilogue; });

    if (obuf_size > 0xFFFF) {
        // INFO(Rafael): The effective message became too long. The user application will caught it
        //               retrying with a short buffer and hopefully we will got the encrypted data flowing
        //               to its destination at the next time.
        errno = EMSGSIZE;
        bytes_nr = -1;
        goto sendto_epilogue;
    }

    if ((bytes_nr = g_bcsck_handle->libc_sendto(sockfd, obuf, obuf_size, flags, dest_addr, addrlen)) != -1) {
        bytes_nr = len;
    }

sendto_epilogue:

    if (obuf != NULL && obuf != sbuf) {
        kryptos_freeseg(obuf, obuf_size);
    }

    obuf = NULL;
    obuf_size = 0;

    if (sbuf != NULL) {
        kryptos_freeseg(sbuf, sbuf_size);
        sbuf = NULL;
        sbuf_size = 0;
    }

__bcsck_leave(sendto)

    return bytes_nr;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    kryptos_u8_t *obuf = NULL, *ibuf, *ib;
    size_t obuf_size, ibuf_size;
    ssize_t bytes_nr;
    size_t iov_c, iov_len;
    struct msghdr omsg;
    struct iovec iov;
    kryptos_u8_t *sbuf = NULL;
    ssize_t sbuf_size;

__bcsck_prologue(return -1)

    if (msg == NULL) {
        errno = EINVAL;
        return -1;
    }

__bcsck_enter(sendmsg)

    ibuf_size = 0;

    for (iov_c = 0; iov_c < msg->msg_iovlen; iov_c++) {
        ibuf_size += msg->msg_iov[iov_c].iov_len;
    }

    if ((ibuf = (kryptos_u8_t *) kryptos_newseg(ibuf_size)) == NULL) {
        bytes_nr = -1;
        goto sendmsg_epilogue;
    }

    ib = ibuf;

    for (iov_c = 0; iov_c < msg->msg_iovlen; iov_c++) {
        iov_len = msg->msg_iov[iov_c].iov_len;
        memcpy(ib, msg->msg_iov[iov_c].iov_base, iov_len);
        ib += iov_len;
    }

    bcsck_e2ee_encrypt_setup(sbuf, sbuf_size, { bytes_nr = -1;
                                               goto sendmsg_epilogue; });

    bcsck_encrypt(ibuf, ibuf_size, obuf, obuf_size, { bytes_nr = -1;
                                                      goto sendmsg_epilogue; });

    bcsck_e2ee_post_proc(sbuf, sbuf_size, obuf, obuf_size, { bytes_nr = -1;
                                                            goto sendmsg_epilogue; });

    if (obuf_size > 0xFFFF) {
        // INFO(Rafael): The effective message became too long. The user application will caught it
        //               retrying with a short buffer and hopefully we will got the encrypted data flowing
        //               to its destination at the next time.
        errno = EMSGSIZE;
        bytes_nr = -1;
        goto sendmsg_epilogue;
    }

    omsg.msg_name = msg->msg_name;
    omsg.msg_namelen = msg->msg_namelen;
    omsg.msg_iov = &iov;
    omsg.msg_iovlen = 1;
#if !defined(__sun__)
    omsg.msg_control = msg->msg_control;
    omsg.msg_controllen = msg->msg_controllen;
#elif defined(__sun__) && defined(_XPG4_2)
    omsg.msg_control = msg->msg_control;
    omsg.msg_controllen = msg->msg_controllen;
    omsg.msg_flags = msg->msg_flags;
#elif defined(__sun__) && !defined(_XPG4_2)
    omsg.msg_accrights = msg->msg_accrights;
    omsg.msg_accrightslen = msg->msg_accrightslen;
#endif

    iov.iov_base = obuf;
    iov.iov_len = obuf_size;

    if ((bytes_nr = g_bcsck_handle->libc_sendmsg(sockfd, &omsg, flags)) != -1) {
        bytes_nr = ibuf_size;
    }

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));

sendmsg_epilogue:

    if (ibuf != NULL) {
        kryptos_freeseg(ibuf, ibuf_size);
        ibuf = NULL;
        ibuf_size = 0;
    }

    if (obuf != NULL && obuf != sbuf) {
        kryptos_freeseg(obuf, obuf_size);
    }

    obuf = NULL;
    obuf_size = 0;

    if (sbuf != NULL) {
        kryptos_freeseg(sbuf, sbuf_size);
        sbuf = NULL;
        sbuf_size = 0;
    }

__bcsck_leave(sendmsg)

    return bytes_nr;
}

ssize_t write(int fd, const void *buf, size_t count) {
    kryptos_u8_t *obuf = NULL;
    size_t obuf_size;
    ssize_t bytes_nr;
    struct sockaddr addr;
    socklen_t addrl;
    struct stat st;
    int is_sock = 0;
    kryptos_u8_t *sbuf = NULL;
    ssize_t sbuf_size;

    if (fstat(fd, &st) == 0 && (is_sock = S_ISSOCK(st.st_mode))) {
        // WARN(Rafael): Otherwise you will get a deadlock.
        __bcsck_enter(write)
        bcsck_e2ee_encrypt_setup(sbuf, sbuf_size, { bytes_nr = -1; goto write_epilogue; });
        bcsck_encrypt(buf, count, obuf, obuf_size, { bytes_nr = -1; goto write_epilogue; });
        bcsck_e2ee_post_proc(sbuf, sbuf_size, obuf, obuf_size, { bytes_nr = -1; goto write_epilogue; });
    } else {
        obuf = (kryptos_u8_t *)buf;
        obuf_size = count;
    }

    if ((bytes_nr = g_bcsck_handle->libc_write(fd, obuf, obuf_size)) != -1) {
        bytes_nr = count;
    }

write_epilogue:

    if (obuf != NULL && obuf != buf && obuf != sbuf) {
        kryptos_freeseg(obuf, obuf_size);
    }

    obuf = NULL;
    obuf_size = 0;

    if (sbuf != NULL) {
        kryptos_freeseg(sbuf, sbuf_size);
        sbuf = NULL;
        sbuf_size = 0;
    }

    if (is_sock) {
        __bcsck_leave(write)
    }

    return bytes_nr;
}

static void bcsck_init(void) {
    g_bcsck_handle = (struct bcsck_handle_ctx *) malloc(sizeof(struct bcsck_handle_ctx));
    if (g_bcsck_handle == NULL) {
        fprintf(stderr, "ERROR: Not enough memory!\n");
        exit(1);
    }
__bcsck_prologue({
                    fprintf(stderr, "ERROR: during libbcsck.so initializing. Aborted.\n");
                    exit(1);
                 })
}

static void bcsck_deinit(void) {
__bcsck_epilogue
    if (g_bcsck_handle != NULL) {
        free(g_bcsck_handle);
    }
}

static int bcsck_read_rule(void) {
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // WARN(Rafael): For the sake of simplicity some getenv() calls are done in two times -> 1. temp,  2. snprintf(..temp); !
    //               The getenv function can be implemented differently from a system to another. Some systems will return  !
    //               the pointer to data while others just a copy. Here is important ensure a copy, otherwise the           !
    //               'setenv(" ") + unset()' will break the workflow implemented here. Because we will end up working with  !
    //               null values... As a result, random malfunctions will be in the way. And I know... You love it! ;)      !
    // !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // TIP(Rafael): 'At first sight' useless 'temp_size = strlen(temp)' is only a paranoid care for ensuring temp's cleaning up,
    //              when routine abruptly exits due to some fault (considering that code can be edited, extended, etc. It is
    //              there because someone extremely tired of so many programming bugs spread out there, trying to make
    //              'a-paranoid-proof-trinket' by putting it there, most important: from the future!).
    //              Please, do not drop those strlens away. Thanks!

    kryptos_u8_t *db_key = NULL, *temp = NULL, *session_key = NULL, rule_id[255], *kpriv = NULL, *kpub = NULL;
    kryptos_u8_t *kpriv_key = NULL;
    size_t kpriv_key_size;
    char db_path[4096], *port = NULL;
    int err = 0;
    size_t session_key_size = 0, temp_size = 0, db_size = 0, db_path_size = 0, db_key_size = 0;
    int (*do_xchg)(void) = NULL;
    struct skey_xchg_ctx sx;
    skey_xchg_trap sx_trap = NULL;
    FILE *fp = NULL;

    sx.libc_socket = g_bcsck_handle->libc_socket;
#if !defined(__NetBSD__)
    sx.libc_send = g_bcsck_handle->libc_send;
    sx.libc_recv = g_bcsck_handle->libc_recv;
#else
    sx.libc_send = g_bcsck_handle->libc_sendto;
    sx.libc_recv = g_bcsck_handle->libc_recvfrom;
#endif
    sx.k_priv = sx.k_pub = NULL;

    if ((temp = getenv(BCSCK_DBPATH)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    temp_size = strlen(temp);

    snprintf(db_path, sizeof(db_path) - 1, "%s", temp);
    temp = NULL;

    setenv(BCSCK_DBPATH, " ", 1);
    unsetenv(BCSCK_DBPATH);

    db_path_size = strlen(db_path);

    if ((temp = getenv(BCSCK_RULE)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    temp_size = strlen(temp);

    snprintf(rule_id, sizeof(rule_id) - 1, "%s", temp);
    temp = NULL;

    setenv(BCSCK_RULE, " ", 1);
    unsetenv(BCSCK_RULE);

    accacia_savecursorposition();

    fprintf(stdout, "Netdb key: ");
    if ((db_key = blackcat_getuserkey(&db_key_size)) == NULL) {
        fprintf(stderr, "ERROR: NULL Netdb key.\n");
        fflush(stderr);
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    accacia_restorecursorposition();
    accacia_delline();
    fflush(stdout);

    if ((kpriv = getenv(BCSCK_KPRIV)) == NULL && (kpub = getenv(BCSCK_KPUB)) == NULL) {
        accacia_savecursorposition();

        fprintf(stdout, "Session key: ");
        if ((session_key = blackcat_getuserkey(&session_key_size)) == NULL) {
            fprintf(stderr, "ERROR: NULL session key.\n");
            fflush(stderr);
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        accacia_savecursorposition();

        fprintf(stdout, "Confirm the session key: ");
        if ((temp = blackcat_getuserkey(&temp_size)) == NULL) {
            fprintf(stderr, "ERROR: NULL session key confirmation.\n");
            fflush(stderr);
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        if (temp_size != session_key_size || memcmp(session_key, temp, session_key_size) != 0) {
            fprintf(stderr, "ERROR: The key does not match with its confirmation.\n");
            fflush(stderr);
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        kryptos_freeseg(temp, temp_size);
        temp = NULL;
        temp_size = 0;
    } else if (kpriv != NULL && kpub != NULL) {
        fprintf(stderr, "ERROR: You cannot pass kpriv and kpub together.\n");
        err = EINVAL;
        goto bcsck_read_rule_epilogue;
    } else if (kpriv != NULL) {
        accacia_savecursorposition();

        fprintf(stdout, "Kpriv key: ");
        if ((kpriv_key = blackcat_getuserkey(&kpriv_key_size)) == NULL) {
            fprintf(stderr, "ERROR: NULL kpriv key.\n");
            fflush(stderr);
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        accacia_restorecursorposition();
        accacia_delline();
        fflush(stdout);

        if ((fp = fopen(kpriv, "r")) == NULL) {
            fprintf(stderr, "ERROR: Unable to read the private parameter file.\n");
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        fseek(fp, 0L, SEEK_END);
        temp_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        if ((temp = (kryptos_u8_t *)kryptos_newseg(temp_size)) == NULL) {
            fprintf(stderr, "ERROR: Not enough memory.\n");
            err = ENOMEM;
            goto bcsck_read_rule_epilogue;
        }

        fread(temp, temp_size, 1, fp);
        fclose(fp);
        fp = NULL;

        sx.k_priv = decrypt_dh_kpriv(temp, temp_size, kpriv_key, kpriv_key_size, &sx.k_priv_size);

        if (sx.k_priv == NULL) {
            fprintf(stderr, "ERROR: Invalid Kpriv key.\n");
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        kryptos_freeseg(temp, temp_size);
        temp = NULL;

        sx_trap = skey_xchg_client;

        fprintf(stderr, "[blackcat] INFO: Estabilishing a session key... please wait...\n");
    } else if (kpub != NULL) {
        if ((temp = getenv(BCSCK_S_BITS)) == NULL) {
            fprintf(stderr, "ERROR: BCSCK_S_BITS was not provided.\n");
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        sx.key_size = kryptos_unbiased_rand_mod_u16(8192);

        if (sx.key_size == 0) {
            sx.key_size = 32;
        }

        sx.s_bits = strtoul(temp, NULL, 10);
        temp = NULL;

        if ((fp = fopen(kpub, "r")) == NULL) {
            fprintf(stderr, "ERROR: Unable to read the public parameter file.\n");
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        fseek(fp, 0L, SEEK_END);
        sx.k_pub_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);

        if ((sx.k_pub = (kryptos_u8_t *)kryptos_newseg(sx.k_pub_size)) == NULL) {
            fprintf(stderr, "ERROR: Not enough memory.\n");
            err = ENOMEM;
            goto bcsck_read_rule_epilogue;
        }

        fread(sx.k_pub, sx.k_pub_size, 1, fp);
        fclose(fp);
        fp = NULL;

        sx_trap = skey_xchg_server;
        fprintf(stderr, "[blackcat] INFO: Estabilishing a session key... please wait...\n");
    }

    if ((sx.keep_sk_open = (sx_trap != NULL))) {
        // INFO(Rafael): Estabilishing a session key.
        if ((temp = getenv(BCSCK_XCHG_ADDR)) == NULL) {
            memset(sx.addr, 0, sizeof(sx.addr));
        } else {
            temp_size = strlen(temp);
            snprintf(sx.addr, sizeof(sx.addr) - 1, "%s", temp);
            temp = NULL;
        }

        if ((port = getenv(BCSCK_XCHG_PORT)) == NULL) {
            fprintf(stderr, "ERROR: The port for the connection parameters exchanging is lacking.\n");
            err = EFAULT;
            goto bcsck_read_rule_epilogue;
        }

        sx.port = atoi(port);

        if ((err = sx_trap(&sx)) != 0) {
            goto bcsck_read_rule_epilogue;
        }

        session_key = sx.session_key;
        session_key_size = sx.session_key_size;

        fprintf(stderr, "[blackcat] INFO: Session key estabilished.\n");
    }

    g_bcsck_handle->sockfd = (sx.keep_sk_open) ? sx.sockfd : -1;

    if ((err = blackcat_netdb_load(db_path, 0)) == 0) {
        g_bcsck_handle->rule = blackcat_netdb_select(rule_id, db_key, db_key_size, &session_key, &session_key_size);
        err = blackcat_netdb_unload();
    }

    if (g_bcsck_handle->rule == NULL) {
        fprintf(stderr, "ERROR: The specified rule seems not exist or the Netdb password is wrong.\n");
        fflush(stderr);
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    if (!(g_bcsck_handle->e2ee_conn = (getenv(BCSCK_E2EE) != NULL))) {
        goto bcsck_read_rule_epilogue;
    }

    setenv(BCSCK_E2EE, " ", 1);
    unsetenv(BCSCK_E2EE);

    // INFO(Rafael): If the user has indicated a e2ee communication, we will strengthen a little more the encryption by
    //               preventing replay attacks and mitigating a session key disclosure situation by making it more ephemeral.

    if (port == NULL && (port = getenv(BCSCK_XCHG_PORT)) == NULL) {
        fprintf(stderr, "ERROR: The port for the connection parameters exchanging is lacking.\n");
        fflush(stderr);
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    g_bcsck_handle->xchg_port = atoi(port);

    setenv(BCSCK_XCHG_PORT, " ", 1);
    unsetenv(BCSCK_E2EE);

    if ((temp = getenv(BCSCK_XCHG_ADDR)) == NULL) {
        memset(g_bcsck_handle->xchg_addr, 0, sizeof(g_bcsck_handle->xchg_addr));
        do_xchg = do_xchg_server;
    } else {
        temp_size = strlen(temp);
        do_xchg = do_xchg_client;
        snprintf(g_bcsck_handle->xchg_addr, sizeof(g_bcsck_handle->xchg_addr) - 1, "%s", temp);
        temp = NULL;
    }

    setenv(BCSCK_XCHG_ADDR, " ", 1);
    unsetenv(BCSCK_XCHG_ADDR);

    if ((err = do_xchg()) != 0) {
        fprintf(stderr, "ERROR: During connection parameters exchanging. Aborted.\n");
        fflush(stderr);
        goto bcsck_read_rule_epilogue;
    }

bcsck_read_rule_epilogue:

    if (kpriv_key != NULL) {
        kryptos_freeseg(kpriv_key, kpriv_key_size);
        kpriv_key_size = 0;
    }

    if (sx.k_priv != NULL) {
        kryptos_freeseg(sx.k_priv, sx.k_priv_size);
        sx.k_priv_size = 0;
    }

    if (sx.k_pub != NULL) {
        kryptos_freeseg(sx.k_pub, sx.k_pub_size);
        sx.k_pub_size = 0;
    }

    if (err != 0 && g_bcsck_handle->rule != NULL) {
        del_bnt_channel_rule_ctx(g_bcsck_handle->rule);
        g_bcsck_handle->rule = NULL;
    }

    if (temp != NULL) {
        memset(temp, 0, temp_size);
        temp_size = 0;
    }

    if (db_key != NULL) {
        kryptos_freeseg(db_key, db_key_size);
        db_key_size = 0;
    }

    if (session_key != NULL) {
        kryptos_freeseg(session_key, session_key_size);
        session_key_size = 0;
    }

    if (fp != NULL) {
        fclose(fp);
    }

    memset(db_path, 0, sizeof(db_path));
    memset(rule_id, 0, sizeof(rule_id));

    db_key = temp = session_key = NULL;

    setenv(BCSCK_DBPATH, " ", 1);
    setenv(BCSCK_RULE, " ", 1);

    unsetenv(BCSCK_DBPATH);
    unsetenv(BCSCK_RULE);

    setenv(BCSCK_E2EE, " ", 1);
    unsetenv(BCSCK_E2EE);

    setenv(BCSCK_XCHG_PORT, " ", 1);
    unsetenv(BCSCK_XCHG_PORT);

    setenv(BCSCK_XCHG_ADDR, " ", 1);
    unsetenv(BCSCK_XCHG_ADDR);

    return err;
}

/*void print_data(kryptos_u8_t *bytes, size_t size) {
    size_t s;
    for (s = 0; s < size; s++) {
        printf("%.2X ", bytes[s]);
    }
    printf("\n");
}*/

static int do_xchg_server(void) {
    int err = -1;
    int lsockfd = -1, csockfd = -1;
    kryptos_u8_t *send_seed = NULL, *out_buf = NULL;
    size_t send_seed_size, out_buf_size;
    char buf[65535];
    const char *hash = NULL;
    ssize_t buf_size;
    struct sockaddr_in sin;
    socklen_t slen;
    unsigned int yeah_butt_head = 1;
    size_t seed_sizes[5];

    // INFO(Rafael): Seeds from 32 up to 512 bits.
    seed_sizes[0] = 4;
    seed_sizes[1] = 8;
    seed_sizes[2] = 16;
    seed_sizes[3] = 32;
    seed_sizes[4] = 64;

    // INFO(Rafael): Depending on the system, libkryptos randomness functions will call read.
    //               Due to it, let's avoid a deadlock by doing it before anything.

    send_seed_size = seed_sizes[kryptos_unbiased_rand_mod_u8(sizeof(seed_sizes) / sizeof(seed_sizes[0]))];
    send_seed = kryptos_get_random_block(send_seed_size);

    // INFO(Rafael): Ensuring that any hooked socket function will not be used by the user application.

__bcsck_enter(read)
__bcsck_enter(write)
__bcsck_enter(recv)
__bcsck_enter(send)
__bcsck_enter(recvfrom)
__bcsck_enter(sendto)
__bcsck_enter(recvmsg)
__bcsck_enter(sendmsg)

    // WARN(Rafael): From now on, never ever, call any hooked socket function directly here,
    //               otherwise the Terminator never 'will be back'.

    if (g_bcsck_handle->sockfd == -1) {
        if ((lsockfd = g_bcsck_handle->libc_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            err = errno;
            fprintf(stderr, "ERROR: Unable to create the listen socket.\n");
            goto do_xchg_server_epilogue;
        }

        setsockopt(lsockfd, SOL_SOCKET, SO_REUSEADDR, &yeah_butt_head, sizeof(yeah_butt_head));

        sin.sin_family = AF_INET;
        sin.sin_port = htons(g_bcsck_handle->xchg_port);
        sin.sin_addr.s_addr = INADDR_ANY;

        if ((bind(lsockfd, (struct sockaddr *)&sin, sizeof(sin))) == -1) {
            err = errno;
            fprintf(stderr, "ERROR: Unable to bind the listen socket.\n");
            goto do_xchg_server_epilogue;
        }

        listen(lsockfd, 1);

        slen = sizeof(sin);
        if ((csockfd = accept(lsockfd, (struct sockaddr *)&sin, &slen)) == -1) {
            err = errno;
            perror("accept");
            fprintf(stderr, "ERROR: Unable to accept the client during session parameters exchanging.\n");
            goto do_xchg_server_epilogue;
        }
    } else {
        csockfd = g_bcsck_handle->sockfd;
    }

    fprintf(stderr, "[blackcat] INFO: Encrypting and sending the random seed...\n");

    bcsck_encrypt(send_seed, send_seed_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to encrypt the sending seed.\n");
                    err = EFAULT;
                    goto do_xchg_server_epilogue;
                  })

#if !defined(__NetBSD__)
    if (g_bcsck_handle->libc_send(csockfd, out_buf, out_buf_size, 0) != out_buf_size) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to send the sending seed.\n");
        goto do_xchg_server_epilogue;
    }
#else
    // WARN(Rafael): Avoiding another clumsy stub.
    if (g_bcsck_handle->libc_sendto(csockfd, out_buf, out_buf_size, 0, NULL, 0) != out_buf_size) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to send the sending seed.\n");
        goto do_xchg_server_epilogue;
    }
#endif

    fprintf(stderr, "[blackcat] INFO: Done.\n");

    kryptos_freeseg(out_buf, out_buf_size);
    out_buf = NULL;
    out_buf_size = 0;

    fprintf(stderr, "[blackcat] INFO: Receiving and decrypting the random seed... please wait...\n");

#if !defined(__NetBSD__)
    if ((buf_size = g_bcsck_handle->libc_recv(csockfd, buf, sizeof(buf), 0)) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to receive the sending seed.\n");
        goto do_xchg_server_epilogue;
    }
#else
    // WARN(Rafael): Avoiding another clumsy stub.
    if ((buf_size = g_bcsck_handle->libc_recvfrom(csockfd, buf, sizeof(buf), 0, NULL, 0)) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to receive the sending seed.\n");
        goto do_xchg_server_epilogue;
    }
#endif

    bcsck_decrypt(buf, buf_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to decrypt the receiving seed.\n");
                    err = EFAULT;
                    goto do_xchg_server_epilogue;
                  })

    fprintf(stderr, "[blackcat] INFO: Done.\n"
                    "[blackcat] INFO: Initializing the double ratchet...\n");

    hash = g_bcsck_handle->rule->hash_algo;

    // INFO(Rafael): It seems tricky but the 'sending seed' for us is actually the 'receiving seed'...

    g_bcsck_handle->keyset = &ks[0];

    if (init_bnt_keyset(&g_bcsck_handle->keyset, g_bcsck_handle->rule->pchain, BCSCK_SEQNO_WINDOW_SIZE,
                        get_hash_processor(hash), get_hash_input_size(hash), get_hash_size(hash),
                        NULL, send_seed, send_seed_size, out_buf, out_buf_size) == 0) {
        fprintf(stderr, "ERROR: Unable to initialize the keyset.\n");
        err = EFAULT;
        goto do_xchg_server_epilogue;
    }

    err = 0; // INFO(Rafael): ...and we done, now we got the two session key chains ('send' and 'recv') well configured.

    fprintf(stderr, "[blackcat] INFO: Done. Now all network data from this application is using end to end encryption.\n");

do_xchg_server_epilogue:

    if (lsockfd != -1) {
        shutdown(lsockfd, SHUT_WR);
        close(lsockfd);
    }

    if (csockfd != -1) {
        shutdown(csockfd, SHUT_WR);
        close(csockfd);
    }

    hash = NULL;

    memset(buf, 0, sizeof(buf));
    buf_size = 0;

    if (out_buf != NULL) {
        kryptos_freeseg(out_buf, out_buf_size);
        out_buf = NULL;
        out_buf_size = 0;
    }

    if (send_seed != NULL) {
        kryptos_freeseg(send_seed, send_seed_size);
        send_seed_size = 0;
        send_seed = NULL;
    }

__bcsck_leave(sendmsg)
__bcsck_leave(recvmsg)
__bcsck_leave(sendto)
__bcsck_leave(recvfrom)
__bcsck_leave(send)
__bcsck_leave(recv)
__bcsck_leave(write)
__bcsck_leave(read)

    return err;
}

static int do_xchg_client(void) {
    int err = -1;
    int sockfd = -1;
    kryptos_u8_t *send_seed = NULL, *out_buf = NULL;
    size_t send_seed_size, out_buf_size;
    char buf[65535];
    const char *hash = NULL;
    ssize_t buf_size;
    struct sockaddr_in sin;
    socklen_t slen;
    size_t seed_sizes[5];
    struct hostent *hp;

    // INFO(Rafael): Seeds from 32 up to 512 bits.
    seed_sizes[0] = 4;
    seed_sizes[1] = 8;
    seed_sizes[2] = 16;
    seed_sizes[3] = 32;
    seed_sizes[4] = 64;

    // INFO(Rafael): Depending on the system, libkryptos randomness functions will call read.
    //               Due to it, let's avoid a deadlock by doing it before anything.

    send_seed_size = seed_sizes[kryptos_unbiased_rand_mod_u8(sizeof(seed_sizes) / sizeof(seed_sizes[0]))];
    send_seed = kryptos_get_random_block(send_seed_size);

    // INFO(Rafael): Ensuring that any hooked socket function will not be used by the user application.
__bcsck_enter(read)
__bcsck_enter(write)
__bcsck_enter(recv)
__bcsck_enter(send)
__bcsck_enter(recvfrom)
__bcsck_enter(sendto)
__bcsck_enter(recvmsg)
__bcsck_enter(sendmsg)

    // WARN(Rafael): From now on, never ever, call any hooked socket function directly here,
    //               otherwise the Terminator never 'will be back'.

    if (g_bcsck_handle->sockfd == -1) {
        if ((sockfd = g_bcsck_handle->libc_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            err = errno;
            fprintf(stderr, "ERROR: Unable to create a socket.\n");
            goto do_xchg_client_epilogue;
        }

        sin.sin_family = AF_INET;
        sin.sin_port = htons(g_bcsck_handle->xchg_port);

        if ((hp = gethostbyname(g_bcsck_handle->xchg_addr)) == NULL) {
            err = errno;
            fprintf(stderr, "ERROR: Unable to resolve the host name.\n");
            goto do_xchg_client_epilogue;
        }

        sin.sin_addr.s_addr = ((struct in_addr *)hp->h_addr_list[0])->s_addr;

        if (connect(sockfd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
            err = errno;
            fprintf(stderr, "ERROR: Unable to connect to the host.\n");
            goto do_xchg_client_epilogue;
        }
    } else {
        sockfd = g_bcsck_handle->sockfd;
    }

    fprintf(stderr, "[blackcat] INFO: Receiving and decrypting the random seed...\n");

#if !defined(__NetBSD__)
    if ((buf_size = g_bcsck_handle->libc_recv(sockfd, buf, sizeof(buf), 0)) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to get the receiving seed.\n");
        goto do_xchg_client_epilogue;
    }
#else
    // WARN(Rafael): Avoiding another clumsy stub.
    if ((buf_size = g_bcsck_handle->libc_recvfrom(sockfd, buf, sizeof(buf), 0, NULL, 0)) == -1) {
        err = errno;
        fprintf(stderr, "ERROR: Unable to get the receiving seed.\n");
        goto do_xchg_client_epilogue;
    }
#endif

    bcsck_decrypt(buf, buf_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to decrypt the receiving seed.\n");
                    err = EFAULT;
                    goto do_xchg_client_epilogue;
                  })

    fprintf(stderr, "[blackcat] INFO: Done.\n"
                    "[blackcat] INFO: Initializing the double ratchet...\n");

    hash = g_bcsck_handle->rule->hash_algo;
    g_bcsck_handle->keyset = &ks[1];

    if (init_bnt_keyset(&g_bcsck_handle->keyset, g_bcsck_handle->rule->pchain, BCSCK_SEQNO_WINDOW_SIZE,
                        get_hash_processor(hash), get_hash_input_size(hash), get_hash_size(hash),
                        NULL, send_seed, send_seed_size, out_buf, out_buf_size) == 0) {
        fprintf(stderr, "ERROR: Unable to initialize the keyset.\n");
        err = EFAULT;
        goto do_xchg_client_epilogue;
    }

    kryptos_freeseg(out_buf, out_buf_size);

    fprintf(stderr, "[blackcat] INFO: Done.\n"
                    "[blackcat] INFO: Encrypting and sending the random seed...\n");

    bcsck_encrypt(send_seed, send_seed_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to encrypt the sending seed.\n");
                    err = EFAULT;
                    goto do_xchg_client_epilogue;
                  })

#if !defined(__NetBSD__)
    if (g_bcsck_handle->libc_send(sockfd, out_buf, out_buf_size, 0) != out_buf_size) {
        fprintf(stderr, "ERROR: Unable to send the sending seed.\n");
        err = EFAULT;
        goto do_xchg_client_epilogue;
    }
#else
    // WARN(Rafael): Avoiding another clumsy stub.
    if (g_bcsck_handle->libc_sendto(sockfd, out_buf, out_buf_size, 0, NULL, 0) != out_buf_size) {
        fprintf(stderr, "ERROR: Unable to send the sending seed.\n");
        err = EFAULT;
        goto do_xchg_client_epilogue;
    }
#endif

    err = 0;

    fprintf(stderr, "[blackcat] INFO: Done. Now all network data from this application is using end to end encryption.\n");

do_xchg_client_epilogue:

    if (sockfd != -1) {
        shutdown(sockfd, SHUT_WR);
        close(sockfd);
    }

    hash = NULL;

    memset(buf, 0, sizeof(buf));
    buf_size = 0;

    if (out_buf != NULL) {
        kryptos_freeseg(out_buf, out_buf_size);
        out_buf = NULL;
        out_buf_size = 0;
    }

    if (send_seed != NULL) {
        kryptos_freeseg(send_seed, send_seed_size);
        send_seed_size = 0;
        send_seed = NULL;
    }

__bcsck_leave(sendmsg)
__bcsck_leave(recvmsg)
__bcsck_leave(sendto)
__bcsck_leave(recvfrom)
__bcsck_leave(send)
__bcsck_leave(recv)
__bcsck_leave(write)
__bcsck_leave(read)

    return err;
}

#undef __bcsck_prologue
#undef __bcsck_epilogue
#undef __bcsck_enter
#undef __bcsck_leave
#undef bcsck_encrypt
#undef bcsck_decrypt
#undef bcsck_e2ee_decrypt_setup

#undef BCSCK_DBPATH
#undef BCSCK_RULE
#undef BCSCK_E2EE
#undef BCSCK_XCHG_PORT
#undef BCSCK_XCHG_ADDR
#undef BCSCK_KPRIV
#undef BCSCK_KPUB
#undef BCSCK_S_BITS

#undef BCSCK_SEQNO_WINDOW_SIZE

#undef SOCKET_FUNC_ENDPOINT
