/*
 * server.h
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */
#ifndef __SERVER_H__
#define __SERVER_H__

#include <ev.h>
#define LIST_POISONING
#include "list.h"

typedef struct {
    struct sockaddr_storage  addr;
    int                 listen_fd;
    ev_io               listen_io;
    struct list_head    stream_list;
} server_t;

#define SERVER_FROM_LISTENIO(io) \
        ((server_t *)((char*)(io) - offsetof(server_t, listen_io)))

extern server_t *server_new (struct sockaddr_storage *addr);
extern void server_free (server_t *server);

extern void server_start (struct ev_loop *loop, server_t *s);

#endif
