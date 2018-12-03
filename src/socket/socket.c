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
                    mtx_socket_func;
#endif
    int libc_loaded, p2p_conn;
    const char *xchg_addr;
    unsigned short xchg_port;
    bnt_keyset_ctx ks, *keyset;
};

#if defined(BCSCK_THREAD_SAFE)

static struct bcsck_handle_ctx g_bcsck_handle = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0,
                                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#define __bcsck_prologue(return_stmt) {\
    if (!g_bcsck_handle.libc_loaded) {\
        g_bcsck_handle.libc_socket = dlsym(RTLD_NEXT, "socket");\
        g_bcsck_handle.libc_recv = dlsym(RTLD_NEXT, "recv");\
        g_bcsck_handle.libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");\
        g_bcsck_handle.libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");\
        g_bcsck_handle.libc_read = dlsym(RTLD_NEXT, "read");\
        g_bcsck_handle.libc_send = dlsym(RTLD_NEXT, "send");\
        g_bcsck_handle.libc_sendto = dlsym(RTLD_NEXT, "sendto");\
        g_bcsck_handle.libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");\
        g_bcsck_handle.libc_write = dlsym(RTLD_NEXT, "write");\
        g_bcsck_handle.libc_loaded = (g_bcsck_handle.libc_socket != NULL) &&\
                                     (g_bcsck_handle.libc_recv != NULL) &&\
                                     (g_bcsck_handle.libc_recvfrom != NULL) &&\
                                     (g_bcsck_handle.libc_recvmsg != NULL) &&\
                                     (g_bcsck_handle.libc_read != NULL) &&\
                                     (g_bcsck_handle.libc_send != NULL) &&\
                                     (g_bcsck_handle.libc_sendto != NULL) &&\
                                     (g_bcsck_handle.libc_sendmsg != NULL) &&\
                                     (g_bcsck_handle.libc_write != NULL) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_recv_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_recvfrom_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_recvmsg_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_read_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_send_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_sendto_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_sendmsg_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_write_func, NULL) == 0) &&\
                                     (pthread_mutex_init(&g_bcsck_handle.mtx_socket_func, NULL) == 0);\
    }\
    if (!g_bcsck_handle.libc_loaded) {\
        return_stmt;\
    }\
    if (g_bcsck_handle.rule == NULL) {\
        if (bcsck_read_rule() != 0) {\
            return_stmt;\
        }\
    }\
}

#define __bcsck_epilogue {\
    g_bcsck_handle.libc_loaded = 0;\
    g_bcsck_handle.libc_socket = NULL;\
    g_bcsck_handle.libc_recv = NULL;\
    g_bcsck_handle.libc_recvfrom = NULL;\
    g_bcsck_handle.libc_recvmsg = NULL;\
    g_bcsck_handle.libc_read = NULL;\
    g_bcsck_handle.libc_send = NULL;\
    g_bcsck_handle.libc_sendto = NULL;\
    g_bcsck_handle.libc_sendmsg = NULL;\
    g_bcsck_handle.libc_write = NULL;\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_recv_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_recvfrom_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_recvmsg_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_read_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_send_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_sendto_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_sendmsg_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_write_func);\
    pthread_mutex_destroy(&g_bcsck_handle.mtx_socket_func);\
}

#define __bcsck_enter(sock_func) {\
    pthread_mutex_lock(&g_bcsck_handle.mtx_ ## sock_func ## _func);\
}

#define __bcsck_leave(sock_func) {\
    pthread_mutex_unlock(&g_bcsck_handle.mtx_ ## sock_func ## _func);\
}

#else

static struct bcsck_handle_ctx g_bcsck_handle = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0 };

#define __bcsck_prologue(return_stmt) {\
    if (!g_bcsck_handle.libc_loaded) {\
        g_bcsck_handle.libc_socket = dlsym(RTLD_NEXT, "socket");\
        g_bcsck_handle.libc_recv = dlsym(RTLD_NEXT, "recv");\
        g_bcsck_handle.libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");\
        g_bcsck_handle.libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");\
        g_bcsck_handle.libc_read = dlsym(RTLD_NEXT, "read");\
        g_bcsck_handle.libc_send = dlsym(RTLD_NEXT, "send");\
        g_bcsck_handle.libc_sendto = dlsym(RTLD_NEXT, "sendto");\
        g_bcsck_handle.libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");\
        g_bcsck_handle.libc_write = dlsym(RTLD_NEXT, "write");\
        g_bcsck_handle.libc_loaded = (g_bcsck_handle.libc_socket != NULL) &&\
                                     (g_bcsck_handle.libc_recv != NULL) &&\
                                     (g_bcsck_handle.libc_recvfrom != NULL) &&\
                                     (g_bcsck_handle.libc_recvmsg != NULL) &&\
                                     (g_bcsck_handle.libc_read != NULL) &&\
                                     (g_bcsck_handle.libc_send != NULL) &&\
                                     (g_bcsck_handle.libc_sendto != NULL) &&\
                                     (g_bcsck_handle.libc_sendmsg != NULL) &&\
                                     (g_bcsck_handle.libc_write != NULL);\
    }\
    if (!g_bcsck_handle.libc_loaded) {\
        return_stmt;\
    }\
    if (g_bcsck_handle.rule == NULL) {\
        if (bcsck_read_rule() != 0) {\
            return_stmt;\
        }\
    }\
}

#define __bcsck_epilogue {\
    g_bcsck_handle.libc_loaded = 0;\
    g_bcsck_handle.libc_socket = NULL;\
    g_bcsck_handle.libc_recv = NULL;\
    g_bcsck_handle.libc_recvfrom = NULL;\
    g_bcsck_handle.libc_recvmsg = NULL;\
    g_bcsck_handle.libc_read = NULL;\
    g_bcsck_handle.libc_send = NULL;\
    g_bcsck_handle.libc_sendto = NULL;\
    g_bcsck_handle.libc_sendmsg = NULL;\
    g_bcsck_handle.libc_write = NULL;\
}

#define __bcsck_enter(sock_func) {};

#define __bcsck_leave(sock_func) {};

#endif // defined(BCSCK_THREAD_SAFE)

#define bcsck_encrypt(ibuf, ibuf_size, obuf, obuf_size, esc_stmt) {\
    if ((obuf = blackcat_encrypt_data(g_bcsck_handle.rule->pchain,\
                                      (kryptos_u8_t *)ibuf, ibuf_size, &obuf_size)) == NULL) {\
        esc_stmt;\
    }\
}

#define bcsck_decrypt(ibuf, ibuf_size, obuf, obuf_size, esc_stmt) {\
    if ((obuf = blackcat_decrypt_data(g_bcsck_handle.rule->pchain,\
                                      (kryptos_u8_t *)ibuf, ibuf_size, &obuf_size)) == NULL) {\
        esc_stmt;\
    }\
}

#define BCSCK_DBPATH      "BCSCK_DBPATH"
#define BCSCK_RULE        "BCSCK_RULE"
#define BCSCK_P2P         "BCSCK_P2P"
#define BCSCK_XCHG_PORT   "BCSCK_PORT"
#define BCSCK_XCHG_ADDR   "BCSCK_ADDR"

#define BCSCK_SEQNO_WINDOW_SIZE 100

static void __attribute__((constructor)) bcsck_init(void);

static void __attribute__((destructor)) bcsck_deinit(void);

static int bcsck_read_rule(void);

static int do_xchg_server(void);

static int do_xchg_client(void);

int socket(int domain, int type, int protocol) {
    int err = -1;

__bcsck_enter(socket)

__bcsck_prologue(goto socket_epilogue)

    err = g_bcsck_handle.libc_socket(domain, type, protocol);

socket_epilogue:

__bcsck_leave(socket)

    return err;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    kryptos_u8_t *obuf = NULL, *rbuf = NULL;
    size_t obuf_size = 0, rbuf_size = 0;
    ssize_t bytes_nr;

__bcsck_enter(recv)

    if ((rbuf = (kryptos_u8_t *) kryptos_newseg(0xFFFF)) == NULL) {
        errno = ENOMEM;
        bytes_nr = -1;
        goto recv_epilogue;
    }

    if ((rbuf_size = g_bcsck_handle.libc_recv(sockfd, rbuf, 0xFFFF, flags)) == -1) {
        bytes_nr = -1;
        goto recv_epilogue;
    }

    bcsck_decrypt(rbuf, rbuf_size, obuf, obuf_size, { bytes_nr = -1; errno = EFAULT; goto recv_epilogue; });

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

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    kryptos_u8_t *obuf = NULL, *rbuf = NULL;
    size_t obuf_size = 0, rbuf_size = 0;
    ssize_t bytes_nr;

__bcsck_enter(recvfrom)

    if ((rbuf = (kryptos_u8_t *) kryptos_newseg(0xFFFF)) == NULL) {
        errno = ENOMEM;
        bytes_nr = -1;
        goto recvfrom_epilogue;
    }

    if ((rbuf_size = g_bcsck_handle.libc_recvfrom(sockfd, rbuf, 0xFFFF, flags, src_addr, addrlen)) == -1) {
        bytes_nr = -1;
        goto recvfrom_epilogue;
    }

    bcsck_decrypt(rbuf, rbuf_size, obuf, obuf_size, { bytes_nr = -1; errno = EFAULT; goto recvfrom_epilogue; });

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
    rmsg.msg_control = msg->msg_control;
    rmsg.msg_controllen = msg->msg_controllen;

    iov.iov_base = rbuf;
    iov.iov_len = 0xFFFF;

    if ((rbuf_size = g_bcsck_handle.libc_recvmsg(sockfd, &rmsg, flags)) == -1) {
        errno = EFAULT;
        bytes_nr = -1;
        goto recvmsg_epilogue;
    }

    memset(&rmsg, 0, sizeof(rmsg));
    memset(&iov, 0, sizeof(iov));

    bcsck_decrypt(rbuf, rbuf_size, obuf, obuf_size, { errno = EFAULT; bytes_nr = -1; goto recvmsg_epilogue; });

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

    if (fstat(fd, &st) == 0 && (is_sock = S_ISSOCK(st.st_mode))) {
        // WARN(Rafael): Otherwise you will get a deadlock.
        __bcsck_enter(read)
        if ((rbuf = (kryptos_u8_t *) kryptos_newseg(0xFFFF)) == NULL) {
            errno = ENOMEM;
            bytes_nr = -1;
            goto read_epilogue;
        }

        if ((rbuf_size = g_bcsck_handle.libc_read(fd, rbuf, 0xFFFF)) == -1) {
            bytes_nr = -1;
            goto read_epilogue;
        }

        bcsck_decrypt(rbuf, rbuf_size, obuf, obuf_size, { bytes_nr = -1; errno = EFAULT; goto read_epilogue; });

        if (obuf_size > count) {
            errno = EFAULT;
            bytes_nr = -1;
        }

        memcpy(buf, obuf, obuf_size);
        bytes_nr = obuf_size;
    } else {
        bytes_nr = g_bcsck_handle.libc_read(fd, buf, count);
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

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    kryptos_u8_t *obuf;
    size_t obuf_size;
    ssize_t bytes_nr;

__bcsck_enter(send)

    bcsck_encrypt(buf, len, obuf, obuf_size, { bytes_nr = -1; goto send_epilogue; });

    if (obuf_size > 0xFFFF) {
        // INFO(Rafael): The effective message became too long. The user application will caught it
        //               retrying with a short buffer and hopefully we will got the encrypted data flowing
        //               to its destination at the next time.
        errno = EMSGSIZE;
        bytes_nr = -1;
        goto send_epilogue;
    }

    if ((bytes_nr = g_bcsck_handle.libc_send(sockfd, obuf, obuf_size, flags)) != -1) {
        bytes_nr = len;
    }

send_epilogue:

    kryptos_freeseg(obuf, obuf_size);
    obuf = NULL;
    obuf_size = 0;

__bcsck_leave(send)

    return bytes_nr;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    kryptos_u8_t *obuf;
    size_t obuf_size;
    ssize_t bytes_nr;

__bcsck_enter(sendto)

    bcsck_encrypt(buf, len, obuf, obuf_size, { bytes_nr = -1; goto sendto_epilogue; });

    if (obuf_size > 0xFFFF) {
        // INFO(Rafael): The effective message became too long. The user application will caught it
        //               retrying with a short buffer and hopefully we will got the encrypted data flowing
        //               to its destination at the next time.
        errno = EMSGSIZE;
        bytes_nr = -1;
        goto sendto_epilogue;
    }

    if ((bytes_nr = g_bcsck_handle.libc_sendto(sockfd, obuf, obuf_size, flags, dest_addr, addrlen)) != -1) {
        bytes_nr = len;
    }

sendto_epilogue:

    kryptos_freeseg(obuf, obuf_size);
    obuf = NULL;
    obuf_size = 0;

__bcsck_leave(sendto)

    return bytes_nr;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    kryptos_u8_t *obuf, *ibuf, *ib;
    size_t obuf_size, ibuf_size;
    ssize_t bytes_nr;
    size_t iov_c, iov_len;
    struct msghdr omsg;
    struct iovec iov;

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

    bcsck_encrypt(ibuf, ibuf_size, obuf, obuf_size, { bytes_nr = -1;
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
    omsg.msg_control = msg->msg_control;
    omsg.msg_controllen = msg->msg_controllen;

    iov.iov_base = obuf;
    iov.iov_len = obuf_size;

    if ((bytes_nr = g_bcsck_handle.libc_sendmsg(sockfd, &omsg, flags)) != -1) {
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

    if (obuf != NULL) {
        kryptos_freeseg(obuf, obuf_size);
        obuf = NULL;
        obuf_size = 0;
    }

__bcsck_leave(sendmsg)

    return bytes_nr;
}

ssize_t write(int fd, const void *buf, size_t count) {
    kryptos_u8_t *obuf;
    size_t obuf_size;
    ssize_t bytes_nr;
    struct sockaddr addr;
    socklen_t addrl;
    struct stat st;
    int is_sock = 0;

    if (fstat(fd, &st) == 0 && (is_sock = S_ISSOCK(st.st_mode))) {
        // WARN(Rafael): Otherwise you will get a deadlock.
        __bcsck_enter(write)
        bcsck_encrypt(buf, count, obuf, obuf_size, { bytes_nr = -1; goto write_epilogue; });
    } else {
        obuf = (kryptos_u8_t *)buf;
        obuf_size = count;
    }

    if ((bytes_nr = g_bcsck_handle.libc_write(fd, obuf, obuf_size)) != -1) {
        bytes_nr = count;
    }

write_epilogue:

    if (obuf != NULL && obuf != buf) {
        kryptos_freeseg(obuf, obuf_size);
        obuf = NULL;
        obuf_size = 0;
    }

    if (is_sock) {
        __bcsck_leave(write)
    }

    return bytes_nr;
}

static void bcsck_init(void) {
__bcsck_prologue({
                    printf("ERROR: during libbcsck.so initializing. Aborted.\n");
                    exit(1);
                 })
}

static void bcsck_deinit(void) {
__bcsck_epilogue
}

static int bcsck_read_rule(void) {
    kryptos_u8_t *db_key = NULL, *temp = NULL, *session_key = NULL, *rule_id = NULL;
    char *db_path = NULL, *port;
    int err = 0;
    size_t session_key_size = 0, temp_size = 0, db_size = 0, db_path_size = 0, db_key_size = 0;
    int (*do_xchg)(void) = NULL;

    if ((db_path = getenv(BCSCK_DBPATH)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    setenv(BCSCK_DBPATH, " ", 1);
    unsetenv(BCSCK_DBPATH);

    db_path_size = strlen(db_path);

    if ((rule_id = getenv(BCSCK_RULE)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

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

    if ((err = blackcat_netdb_load(db_path, 0)) == 0) {
        g_bcsck_handle.rule = blackcat_netdb_select(rule_id, db_key, db_key_size, &session_key, &session_key_size);
        err = blackcat_netdb_unload();
    }

    if (g_bcsck_handle.rule == NULL) {
        fprintf(stderr, "ERROR: The specified rule seems not exist or the Netdb password is wrong.\n");
        fflush(stderr);
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    if (!(g_bcsck_handle.p2p_conn = (getenv(BCSCK_P2P) != NULL))) {
        goto bcsck_read_rule_epilogue;
    }

    setenv(BCSCK_P2P, " ", 1);
    unsetenv(BCSCK_P2P);

    // INFO(Rafael): If the user has indicated a p2p communication, we will strengthen a little more the encryption by
    //               preventing replay attacks and mitigating a session key disclosure situation by making it more ephemeral.

    if ((port = getenv(BCSCK_XCHG_PORT)) == NULL) {
        fprintf(stderr, "ERROR: The port for the connection parameters exchanging is lacking.\n");
        fflush(stderr);
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    setenv(BCSCK_XCHG_PORT, " ", 1);
    unsetenv(BCSCK_P2P);

    g_bcsck_handle.xchg_port = atoi(port);

    g_bcsck_handle.xchg_addr = getenv(BCSCK_XCHG_ADDR);

    setenv(BCSCK_XCHG_ADDR, " ", 1);
    unsetenv(BCSCK_XCHG_ADDR);

    if (g_bcsck_handle.xchg_addr == NULL) {
        do_xchg = do_xchg_server;
    } else {
        do_xchg = do_xchg_client;
    }

    if ((err = do_xchg()) != 0) {
        fprintf(stderr, "ERROR: During connection parameters exchanging. Aborted.\n");
        fflush(stderr);
        goto bcsck_read_rule_epilogue;
    }

bcsck_read_rule_epilogue:

    if (err != 0 && g_bcsck_handle.rule != NULL) {
        del_bnt_channel_rule_ctx(g_bcsck_handle.rule);
        g_bcsck_handle.rule = NULL;
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

    db_key = temp = session_key = rule_id = NULL;
    db_path = NULL;

    setenv(BCSCK_DBPATH, " ", 1);
    setenv(BCSCK_RULE, " ", 1);

    unsetenv(BCSCK_DBPATH);
    unsetenv(BCSCK_RULE);

    setenv(BCSCK_P2P, " ", 1);
    unsetenv(BCSCK_P2P);

    setenv(BCSCK_XCHG_PORT, " ", 1);
    unsetenv(BCSCK_P2P);

    setenv(BCSCK_XCHG_ADDR, " ", 1);
    unsetenv(BCSCK_XCHG_ADDR);

    return err;
}

static int do_xchg_server(void) {
    int err = -1;
    int lsockfd = -1, csockfd = -1;
    kryptos_u8_t *send_seed = NULL, *out_buf = NULL;
    size_t send_seed_size, out_buf_size;
    char buf[64];
    kryptos_u8_t *hash = NULL;
    ssize_t buf_size;
    struct sockaddr_in sin;
    socklen_t slen;
    unsigned char yeah_butt_head = 1;
    size_t seed_sizes[5] = { 4, 8, 16, 32, 64 }; // INFO(Rafael): Seeds from 32 up to 512 bits.

    // INFO(Rafael): Depending on the system, libkryptos randomness functions will call read.
    //               Due to it, let's avoid a deadlock by doing it before anything.

    send_seed_size = seed_sizes[kryptos_get_random_byte() % (sizeof(seed_sizes) / sizeof(seed_sizes[0]))];
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

    if ((lsockfd = g_bcsck_handle.libc_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        fprintf(stderr, "ERROR: Unable to create the listen socket.\n");
        err = errno;
        goto do_xchg_server_epilogue;
    }

    setsockopt(lsockfd, SOL_SOCKET, SO_REUSEADDR, &yeah_butt_head, sizeof(yeah_butt_head));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(g_bcsck_handle.xchg_port);
    sin.sin_addr.s_addr = INADDR_ANY;

    if ((bind(lsockfd, (struct sockaddr *)&sin, sizeof(sin))) == -1) {
        fprintf(stderr, "ERROR: Unable to bind the listen socket.\n");
        err = errno;
        goto do_xchg_server_epilogue;
    }

    listen(lsockfd, 1);

    if ((csockfd = accept(lsockfd, (struct sockaddr *)&sin, &slen)) == -1) {
        fprintf(stderr, "ERROR: Unable to accept the client during session parameters exchanging.\n");
        err = errno;
        goto do_xchg_server_epilogue;
    }

    bcsck_encrypt(send_seed, send_seed_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to encrypt the sending seed.\n");
                    err = EFAULT;
                    goto do_xchg_server_epilogue;
                  })

    if (g_bcsck_handle.libc_send(csockfd, out_buf, out_buf_size, 0) != send_seed_size) {
        fprintf(stderr, "ERROR: Unable to send the sending seed.\n");
        err = errno;
        goto do_xchg_server_epilogue;
    }

    kryptos_freeseg(out_buf, out_buf_size);
    out_buf = NULL;
    out_buf_size = 0;

    if ((buf_size = g_bcsck_handle.libc_recv(csockfd, buf, sizeof(buf), 0)) == -1) {
        fprintf(stderr, "ERROR: Unable to receive the sending seed.\n");
        err = errno;
        goto do_xchg_server_epilogue;
    }

    bcsck_decrypt(buf, buf_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to decrypt the receiving seed.\n");
                    err = EFAULT;
                    goto do_xchg_server_epilogue;
                  })

    hash = g_bcsck_handle.rule->pchain->repo_key_hash;

    // INFO(Rafael): It seems tricky but the 'sending seed' for us is actually the 'receiving seed'...

    g_bcsck_handle.keyset = &g_bcsck_handle.ks;

    if (init_bnt_keyset(&g_bcsck_handle.keyset, g_bcsck_handle.rule->pchain, BCSCK_SEQNO_WINDOW_SIZE,
                        get_hash_processor(hash), get_hash_input_size(hash), get_hash_size(hash),
                        NULL, out_buf, out_buf_size, send_seed, send_seed_size) == 0) {
        fprintf(stderr, "ERROR: Unable to initialize the keyset.\n");
        err = EFAULT;
        goto do_xchg_server_epilogue;
    }

    err = 0; // INFO(Rafael): ...and we done, now we got the two session key chains ('send' and 'recv') well configured.

do_xchg_server_epilogue:

    if (lsockfd != -1) {
        close(lsockfd);
    }

    if (csockfd != -1) {
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
    char buf[64];
    kryptos_u8_t *hash = NULL;
    ssize_t buf_size;
    struct sockaddr_in sin;
    socklen_t slen;
    size_t seed_sizes[5] = { 4, 8, 16, 32, 64 }; // INFO(Rafael): Seeds from 32 up to 512 bits.
    struct hostent *hp;

    // INFO(Rafael): Depending on the system, libkryptos randomness functions will call read.
    //               Due to it, let's avoid a deadlock by doing it before anything.

    send_seed_size = seed_sizes[kryptos_get_random_byte() % (sizeof(seed_sizes) / sizeof(seed_sizes[0]))];
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

    if ((sockfd = g_bcsck_handle.libc_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        fprintf(stderr, "ERROR: Unable to create a socket.\n");
        err = errno;
        goto do_xchg_client_epilogue;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(g_bcsck_handle.xchg_port);

    if ((hp = gethostbyname(g_bcsck_handle.xchg_addr)) == NULL) {
        fprintf(stderr, "ERROR: Unable to resolve the host name.\n");
        err = errno;
        goto do_xchg_client_epilogue;
    }

    sin.sin_addr.s_addr = ((struct in_addr *)hp->h_aliases[0])->s_addr;

    if (bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        fprintf(stderr, "ERROR: Unable to bind the socket.\n");
        err = errno;
        goto do_xchg_client_epilogue;
    }

    if (connect(sockfd, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
        fprintf(stderr, "ERROR: Unable to connect to the host.\n");
        err = errno;
        goto do_xchg_client_epilogue;
    }

    if ((buf_size = g_bcsck_handle.libc_recv(sockfd, buf, sizeof(buf), 0)) == -1) {
        fprintf(stderr, "ERROR: Unable to get the receiving seed.\n");
        err = errno;
        goto do_xchg_client_epilogue;
    }

    bcsck_decrypt(buf, buf_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to decrypt the receiving seed.\n");
                    err = EFAULT;
                    goto do_xchg_client_epilogue;
                  })

    hash = g_bcsck_handle.rule->pchain->repo_key_hash;
    g_bcsck_handle.keyset = &g_bcsck_handle.ks;

    if (init_bnt_keyset(&g_bcsck_handle.keyset, g_bcsck_handle.rule->pchain, BCSCK_SEQNO_WINDOW_SIZE,
                        get_hash_processor(hash), get_hash_input_size(hash), get_hash_size(hash),
                        NULL, send_seed, send_seed_size, out_buf, out_buf_size) == 0) {
        fprintf(stderr, "ERROR: Unable to initialize the keyset.\n");
        err = EFAULT;
        goto do_xchg_client_epilogue;
    }

    kryptos_freeseg(out_buf, out_buf_size);

    bcsck_encrypt(send_seed, send_seed_size, out_buf, out_buf_size,
                  {
                    fprintf(stderr, "ERROR: Unable to encrypt the sending seed.\n");
                    err = EFAULT;
                    goto do_xchg_client_epilogue;
                  })

    if (g_bcsck_handle.libc_send(sockfd, send_seed, send_seed_size, 0) != send_seed_size) {
        fprintf(stderr, "ERROR: Unable to send the sending seed.\n");
        err = EFAULT;
        goto do_xchg_client_epilogue;
    }

    err = 0;

do_xchg_client_epilogue:

    if (sockfd != -1) {
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

#undef BCSCK_DBPATH
#undef BCSCK_RULE
#undef BCSCK_P2P
#undef BCSCK_XCHG_PORT
#undef BCSCK_XCHG_ADDR

#undef BCSCK_SEQNO_WINDOW_SIZE
