/**
 * server.c
 * A common server I/O structure.
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "amoeba.h"
#include "server.h"

static void
server_accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    UNUSED(revents);

    server_t *server = SERVER_FROM_LISTENIO(w);

    int fd = accept4(server->listen_fd, NULL, NULL, SOCK_NONBLOCK);
    if (fd == -1) {
        return;
    }
    int opt = 1;
    setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));

    stream_t *s = stream_new(loop);
    if (!s) {
        close(fd);
        return;
    }
    list_add_tail(&s->node, &server->stream_list);
    stream_attach(s, fd);
}

server_t *server_new(struct sockaddr_storage *addr)
{
    server_t *server;

    server = (server_t *)malloc(sizeof(server_t));
    if (!server) {
        return NULL;
    }
    server->addr = *addr;

    INIT_LIST_HEAD(&server->stream_list);

    return server;
}

void server_start(struct ev_loop *loop, server_t *s)
{
    int fd = socket(s->addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        exit(-1);
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    socklen_t addr_len;
    addr_len = s->addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6);
    if (bind(fd, (struct sockaddr *)&s->addr, addr_len) < 0) {
        char buffer[128];
        sockaddr_to_string(&s->addr, buffer, sizeof(buffer));
        log_error("unable to bind to %s", buffer);
        close(fd);
        exit(-1);
    }
    if (listen(fd, SOMAXCONN) == -1) {
        exit(-1);
    }
    s->listen_fd = fd;

    ev_io_init(&s->listen_io, server_accept_cb, s->listen_fd, EV_READ);
    ev_io_start(loop, &s->listen_io);    
}

