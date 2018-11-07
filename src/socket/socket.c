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
#define __bcsck_prologue {\
    if (g_bcsck_handle.rule == NULL) {\
        if (bcsck_read_rule() != 0) {\
            return -1;\
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
        return -1;\
    }\
}

#define BCSCK_DBPATH "BSCK_DBPATH"
#define BCSCK_DBKEY  "BSCK_DBKEY"
#define BCSCK_SKEY   "BSCK_SKEY"
#define BCSCK_RULE   "BSCK_RULE"

static int bcsck_read_rule(void);

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
__bcsck_prologue
    return -1;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
__bcsck_prologue
    return -1;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
__bcsck_prologue
    return -1;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
__bcsck_prologue
    return -1;
}

ssize_t read(int fd, void *buf, size_t count) {
__bcsck_prologue
    return -1;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
__bcsck_prologue
    return -1;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
__bcsck_prologue
    return -1;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
__bcsck_prologue
    return -1;
}

ssize_t write(int fd, const void *buf, size_t count) {
__bcsck_prologue
    return -1;
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

#undef __bsck_prologue

#undef BCSCK_DBPATH
#undef BCSCK_DBKEY
#undef BCSCK_SKEY
#undef BCSCK_RULE
