/*
 *                          Copyright (C) 2018 by Rafael Santiago
 *
 * Use of this source code is governed by GPL-v2 license that can
 * be found in the COPYING file.
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define HOOK_NR 4

typedef ssize_t (*send_func)(int fd, const char *buf, const size_t buf_size);

typedef ssize_t (*recv_func)(int fd, char *buf, const size_t buf_size);

typedef void *(*handle_func)(void *args);

static ssize_t write_sending(int fd, const char *buf, const size_t buf_size);

static ssize_t read_receiving(int fd, char *buf, const size_t buf_size);

static ssize_t send_sending(int fd, const char *buf, const size_t buf_size);

static ssize_t recv_receiving(int fd, char *buf, const size_t buf_size);

static ssize_t sendto_sending(int fd, const char *buf, const size_t buf_size);

static ssize_t recvfrom_receiving(int fd, char *buf, const size_t buf_size);

static ssize_t sendmsg_sending(int fd, const char *buf, const size_t buf_size);

static ssize_t recvmsg_receiving(int fd, char *buf, const size_t buf_size);

static void *server(void *args);

static void *client(void *args);

struct ntool_task_ctx {
    unsigned short port;
    char *data;
    size_t data_size;
    send_func send;
    recv_func recv;
    handle_func handle;
    pthread_t thread;
};

// INFO(Rafael): Para nao chamar de 'caiau', 'caiauzao' ou ainda 'caiauzaço'.
static struct ntool_task_ctx g_trinket[HOOK_NR << 1] = {
    { 1234, "read/write server\n",      18, write_sending,   read_receiving,     server, 0 },
    { 1235, "send/recv server\n",       17, send_sending,    recv_receiving,     server, 0 },
    { 1236, "sendto/recvfrom server\n", 23, sendto_sending,  recvfrom_receiving, server, 0 },
    { 1237, "sendmsg/recvmsg server\n", 23, sendmsg_sending, recvmsg_receiving,  server, 0 },
    { 1234, "read/write client\n",      18, write_sending,   read_receiving,     client, 0 },
    { 1235, "send/recv client\n",       17, send_sending,    recv_receiving,     client, 0 },
    { 1236, "sendto/recvfrom client\n", 23, sendto_sending,  recvfrom_receiving, client, 0 },
    { 1237, "sendmsg/recvmsg client\n", 23, sendmsg_sending, recvmsg_receiving,  client, 0 }
};

static size_t g_trinket_size = HOOK_NR << 1;

static void *client(void *args) {
    struct ntool_task_ctx *ntc = (struct ntool_task_ctx *) args;
    int fd;
    struct sockaddr_in s_in;
    char buf[0xFFFF];
    ssize_t buf_size;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd == -1) {
        perror("socket");
        exit(1);
    }

    s_in.sin_family = AF_INET;
    s_in.sin_port = htons(ntc->port);
    s_in.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(fd, (struct sockaddr *) &s_in, sizeof(s_in)) == -1) {
        perror("connect");
        exit(1);
    }

    if (ntc->send(fd, ntc->data, ntc->data_size) != ntc->data_size) {
        perror("ntc->send");
        exit(1);
    }

    buf_size = ntc->recv(fd, buf, sizeof(buf));

    if (buf_size == -1) {
        perror("ntc->recv");
        exit(1);
    }

    fwrite(buf, buf_size, 1, stderr);
    fflush(stderr);

    close(fd);

    return NULL;
}

static void *server(void *args) {
    struct ntool_task_ctx *ntc = (struct ntool_task_ctx *) args;
    int fd, c_fd;
    struct sockaddr_in s_in;
    struct sockaddr sa;
    socklen_t sa_len;
    char buf[0xFFFF];
    ssize_t buf_size;
    unsigned char yes = 1;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (fd == -1) {
        perror("socket");
        exit(1);
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    s_in.sin_family = AF_INET;
    s_in.sin_port = htons(ntc->port);
    s_in.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&s_in, sizeof(s_in)) != 0) {
        perror("bind");
        exit(1);
    }

    if (listen(fd, 1) != 0) {
        perror("listen");
        exit(1);
    }

    c_fd = accept(fd, &sa, &sa_len);

    if (c_fd == -1) {
        perror("accept");
        exit(1);
    }

    buf_size = ntc->recv(c_fd, buf, sizeof(buf));

    if (buf_size == -1) {
        perror("ntc->recv");
        exit(1);
    }

    fwrite(buf, buf_size, 1, stderr);
    fflush(stderr);

    if (ntc->send(c_fd, ntc->data, ntc->data_size) == -1) {
        perror("ntc->send");
        exit(1);
    }

    close(fd);

    return NULL;
}

static ssize_t write_sending(int fd, const char *buf, const size_t buf_size) {
    return write(fd, buf, buf_size);
}

static ssize_t read_receiving(int fd, char *buf, const size_t buf_size) {
    return read(fd, buf, buf_size);
}

static ssize_t send_sending(int fd, const char *buf, const size_t buf_size) {
    return send(fd, buf, buf_size, 0);
}

static ssize_t recv_receiving(int fd, char *buf, const size_t buf_size) {
    return recv(fd, buf, buf_size, 0);
}

static ssize_t sendto_sending(int fd, const char *buf, const size_t buf_size) {
    return sendto(fd, buf, buf_size, 0, NULL, 0);
}

static ssize_t recvfrom_receiving(int fd, char *buf, const size_t buf_size) {
    return recvfrom(fd, buf, buf_size, 0, NULL, 0);
}

static ssize_t sendmsg_sending(int fd, const char *buf, const size_t buf_size) {
    struct msghdr mhdr;
    struct iovec iov[1];
    mhdr.msg_name = NULL;
    mhdr.msg_namelen = 0;
    mhdr.msg_control = NULL;
    mhdr.msg_controllen = 0;
    mhdr.msg_flags = 0;
    iov[0].iov_base = (char *)buf;
    iov[0].iov_len = buf_size;
    mhdr.msg_iov = &iov[0];
    mhdr.msg_iovlen = 1;
    return sendmsg(fd, &mhdr, 0);
}

static ssize_t recvmsg_receiving(int fd, char *buf, const size_t buf_size) {
    struct msghdr mhdr;
    struct iovec iov[1];
    mhdr.msg_name = NULL;
    mhdr.msg_namelen = 0;
    mhdr.msg_control = NULL;
    mhdr.msg_controllen = 0;
    mhdr.msg_flags = 0;
    iov[0].iov_base = buf;
    iov[0].iov_len = buf_size;
    mhdr.msg_iov = &iov[0];
    mhdr.msg_iovlen = 1;
    return recvmsg(fd, &mhdr, 0);
}

int main(int argc, char **argv) {
    size_t t;

    for (t = 0; t < g_trinket_size; t++) {
        if (pthread_create(&g_trinket[t].thread, NULL, g_trinket[t].handle, &g_trinket[t]) != 0) {
            perror("pthread_create");
            exit(1);
        }
        usleep(1000);
    }

    for (t = 0; t < g_trinket_size; t++) {
        pthread_join(g_trinket[t].thread, NULL);
    }

    return 0;
}
