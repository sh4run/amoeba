/*
 * amoeba.h
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */

#ifndef __AMOEBA_H__
#define __AMOEBA_H__

#include <ev.h>

//#define NDEBUG
#include <assert.h>

#include "mempool.h"
#include "json_config.h"
#include "utils.h"
#include "message_queue.h"
#include "stream.h"
#include "server.h"
#include "message.h"

typedef struct {
    struct ev_loop        *loop;
    task_id_t              name;
    message_queue_t       *msg_que;
    ev_io                  msgq_watcher;
    msg_handler_cb_func_t  msg_handler;
    void                  *extra_data;
} msg_ev_ctx_t;

typedef struct {
    proto_ctrl_t        *proto_cb;
    server_t            *server;
} proto_common_extra_t;

static inline void msg_ev_ctx_set_extradata(msg_ev_ctx_t *ctx, void *extra)
{
    ctx->extra_data = extra;
}

static inline void *msg_ev_ctx_get_extradata(msg_ev_ctx_t *ctx)
{
    return ctx->extra_data;
}

extern void
msgq_read_ev_common_cb (struct ev_loop *loop, ev_io *w, int revents);

extern int msg_ev_ctx_init (msg_ev_ctx_t *ctx, task_id_t name,
                            msg_handler_cb_func_t msg_handler);


typedef void* (*task_entry_t)(void*);

void register_task (jcfg_mode_t mode, task_id_t name, task_entry_t task_entry);
void register_stats_cb(void (*stats_cb)(void));

#define INIT_ROUTINE(f) __attribute__((constructor)) f

#endif
