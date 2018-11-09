/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <socket/socket.h>
#include <net/base/types.h>
#include <net/ctx/ctx.h>
#include <net/db/db.h>
#include <keychain/processor.h>
#include <kryptos.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>

#ifndef RTLD_NEXT
# define RTLD_NEXT ((void *)-1)
#endif

struct bcsck_handle_ctx {
    int (*libc_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
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
    int libc_loaded;
};

static struct bcsck_handle_ctx g_bcsck_handle = { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0 };

// TODO(Rafael): Make it thread safe.
#define __bcsck_prologue(return_stmt) {\
    if (g_bcsck_handle.rule == NULL) {\
        if (bcsck_read_rule() != 0) {\
            return_stmt;\
        }\
    }\
    if (!g_bcsck_handle.libc_loaded) {\
        g_bcsck_handle.libc_connect = dlsym(RTLD_NEXT, "connect");\
        g_bcsck_handle.libc_recv = dlsym(RTLD_NEXT, "recv");\
        g_bcsck_handle.libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");\
        g_bcsck_handle.libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");\
        g_bcsck_handle.libc_read = dlsym(RTLD_NEXT, "read");\
        g_bcsck_handle.libc_send = dlsym(RTLD_NEXT, "send");\
        g_bcsck_handle.libc_sendto = dlsym(RTLD_NEXT, "sendto");\
        g_bcsck_handle.libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");\
        g_bcsck_handle.libc_write = dlsym(RTLD_NEXT, "write");\
        g_bcsck_handle.libc_loaded = (g_bcsck_handle.libc_connect != NULL) &&\
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
}

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

#define BCSCK_DBPATH "BSCK_DBPATH"
#define BCSCK_DBKEY  "BSCK_DBKEY"
#define BCSCK_SKEY   "BSCK_SKEY"
#define BCSCK_RULE   "BSCK_RULE"

static void __attribute__((constructor)) bcsck_init(void);

static int bcsck_read_rule(void);

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
__bcsck_prologue(return -1)
    return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    kryptos_u8_t *obuf = NULL, *rbuf = NULL;
    size_t obuf_size = 0, rbuf_size = 0;
    ssize_t bytes_nr;
__bcsck_prologue(return - 1)

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

    return bytes_nr;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    kryptos_u8_t *obuf = NULL, *rbuf = NULL;
    size_t obuf_size = 0, rbuf_size = 0;
    ssize_t bytes_nr;

__bcsck_prologue(return -1)

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

    return bytes_nr;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
    kryptos_u8_t *rbuf = NULL, *obuf = NULL, *ob, *ob_end;
    size_t rbuf_size = 0, obuf_size = 0, ob_size, temp_size;
    ssize_t bytes_nr;
    size_t iov_c;
    struct msghdr rmsg;
    struct iovec iov;

__bcsck_prologue(return -1)

    if (msg == NULL) {
        errno = EINVAL;
        return -1;
    }

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

    return bytes_nr;
}

ssize_t read(int fd, void *buf, size_t count) {
    kryptos_u8_t *rbuf = NULL, *obuf = NULL;
    ssize_t rbuf_size = 0, obuf_size = 0;
    ssize_t bytes_nr;
    struct sockaddr addr;
    socklen_t addrl;

__bcsck_prologue(return -1)

    if (getsockname(fd, &addr, &addrl) == 0) {
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

    return bytes_nr;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    kryptos_u8_t *obuf;
    size_t obuf_size;
    ssize_t bytes_nr;

__bcsck_prologue(return -1)

    bcsck_encrypt(buf, len, obuf, obuf_size, return -1);

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

    return bytes_nr;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    kryptos_u8_t *obuf;
    size_t obuf_size;
    ssize_t bytes_nr;

__bcsck_prologue(return -1)

    bcsck_encrypt(buf, len, obuf, obuf_size, return -1);

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

    ibuf_size = 0;

    for (iov_c = 0; iov_c < msg->msg_iovlen; iov_c++) {
        ibuf_size += msg->msg_iov[iov_c].iov_len;
    }

    if ((ibuf = (kryptos_u8_t *) kryptos_newseg(ibuf_size)) == NULL) {
        return -1;
    }

    ib = ibuf;

    for (iov_c = 0; iov_c < msg->msg_iovlen; iov_c++) {
        iov_len = msg->msg_iov[iov_c].iov_len;
        memcpy(ib, msg->msg_iov[iov_c].iov_base, iov_len);
        ib += iov_len;
    }

    bcsck_encrypt(ibuf, ibuf_size, obuf, obuf_size, { kryptos_freeseg(ibuf, ibuf_size);
                                                      ibuf = NULL;
                                                      ibuf_size = 0;
                                                      return -1; });

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

    kryptos_freeseg(ibuf, ibuf_size);
    ibuf = NULL;
    ibuf_size = 0;

    kryptos_freeseg(obuf, obuf_size);
    obuf = NULL;
    obuf_size = 0;

    return bytes_nr;
}

ssize_t write(int fd, const void *buf, size_t count) {
    kryptos_u8_t *obuf;
    size_t obuf_size;
    ssize_t bytes_nr;
    struct sockaddr addr;
    socklen_t addrl;

__bcsck_prologue(return -1)

    if (getsockname(fd, &addr, &addrl) == 0) {
        bcsck_encrypt(buf, count, obuf, obuf_size, return -1);
    } else {
        obuf = (kryptos_u8_t *)buf;
        obuf_size = count;
    }

    if ((bytes_nr = g_bcsck_handle.libc_write(fd, obuf, obuf_size)) != -1) {
        bytes_nr = count;
    }

    if (obuf != buf) {
        kryptos_freeseg(obuf, obuf_size);
        obuf = NULL;
        obuf_size = 0;
    }

    return bytes_nr;
}

static void bcsck_init(void) {
__bcsck_prologue(return)
}

static int bcsck_read_rule(void) {
    kryptos_u8_t *db_key = NULL, *temp = NULL, *session_key = NULL, *rule_id = NULL;
    char *db_path = NULL;
    int err = 0;
    size_t session_key_size = 0, temp_size = 0, db_size = 0, db_path_size = 0, db_key_size = 0;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    if ((db_path = getenv(BCSCK_DBPATH)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    db_path_size = strlen(db_path);

    if ((temp = getenv(BCSCK_DBKEY)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    temp_size = strlen(temp);

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, temp, temp_size);

    if (kryptos_last_task_succeed(ktask)) {
        db_key = ktask->out;
        db_key_size = ktask->out_size;
    } else {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    memset(temp, 0, temp_size);
    temp = NULL;
    temp_size = 0;

    if ((rule_id = getenv(BCSCK_RULE)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    if ((temp = getenv(BCSCK_SKEY)) == NULL) {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    temp_size = strlen(temp);

    kryptos_task_set_decode_action(ktask);
    kryptos_run_encoder(base64, ktask, temp, temp_size);

    if (kryptos_last_task_succeed(ktask)) {
        session_key = ktask->out;
        session_key_size = ktask->out_size;
    } else {
        err = EFAULT;
        goto bcsck_read_rule_epilogue;
    }

    memset(temp, 0, temp_size);
    temp = NULL;
    temp_size = 0;

    kryptos_task_init_as_null(ktask);

    if ((err = blackcat_netdb_load(db_path)) == 0) {
        g_bcsck_handle.rule = blackcat_netdb_select(rule_id, db_key, db_key_size, &session_key, &session_key_size);
        err = blackcat_netdb_unload();
    }

    if (g_bcsck_handle.rule == NULL) {
        err = EFAULT;
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

    if (db_path != NULL) {
        memset(db_path, 0, db_path_size);
        db_path_size = 0;
    }

    db_key = temp = session_key = rule_id = NULL;
    db_path = NULL;

    setenv(BCSCK_DBPATH, " ", 1);
    setenv(BCSCK_DBKEY, " ", 1);
    setenv(BCSCK_SKEY, " ", 1);
    setenv(BCSCK_RULE, " ", 1);

    unsetenv(BCSCK_DBPATH);
    unsetenv(BCSCK_DBKEY);
    unsetenv(BCSCK_SKEY);
    unsetenv(BCSCK_RULE);

    return err;
}

#undef __bcsck_prologue
#undef bcsck_encrypt
#undef bcsck_decrypt

#undef BCSCK_DBPATH
#undef BCSCK_DBKEY
#undef BCSCK_SKEY
#undef BCSCK_RULE
