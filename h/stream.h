/*
 * stream.h
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */

#ifndef __STREAM_H__
#define __STREAM_H__

#include <ev.h>

#include "netbuf.h"
#define LIST_POISONING
#include "list.h"

#define STREAM_BUF_LEN   (MAX_BUFFER_FACTOR * 1000)

typedef struct _stream_t stream_t;

typedef int (*proto_input_cb_t)(stream_t *s, netbuf_t **nb);
typedef void *(*proto_data_new_cb_t)(stream_t *s);
typedef int (*proto_data_free_cb_t)(stream_t *s, void *);
typedef void (*proto_bkp_cb_t)(stream_t *s, backpressure_state_t state);

typedef struct {
    int                      name;
    proto_data_new_cb_t      new_cb;
    proto_data_free_cb_t     free_cb;
    proto_input_cb_t         input_cb;
    proto_bkp_cb_t           bkp_cb;
} proto_ctrl_t;

#define STREAM_MAGIC    0xAA5577DD
#define STREAM_PENDING_DEL  0x3377AAEE

typedef struct _stream_t {
    struct list_head    node;
    uint32_t            magic;
    proto_ctrl_t        *proto_cb;
    int                 fd;
    struct ev_loop     *loop;
    ev_io               read_io;
    ev_io               write_io;
    ev_timer            idle_timer;
    uint32_t            io_num;
    netbuf_t           *input;
    queue_t             output_q;
    uint32_t            output_q_len;
    void               *proto_data;
    int                 obsolete;
    backpressure_state_t    bp_state;
} stream_t;

#define VALID_STREAM(s)   ((s)->magic == STREAM_MAGIC && ((s)->proto_data))
#define STREAM_FROM_READIO(io) \
        ((stream_t*)((char*)(io) - offsetof(stream_t, read_io)))
#define STREAM_FROM_WRITEIO(io) \
        ((stream_t*)((char*)(io) - offsetof(stream_t, write_io)))
#define STREAM_FROM_IDLETIMER(io) \
        ((stream_t*)((char*)(io) - offsetof(stream_t, idle_timer)))
#define STREAM_PROTO_DATA(s)  ((s)->magic == STREAM_MAGIC ? \
                               (s)->proto_data : NULL)

#define CTX_FROM_STREAM(s) (msg_ev_ctx_t*)ev_userdata((s)->loop)
#define TASK_FROM_STREAM(s) \
        (((proto_common_extra_t*) \
            msg_ev_ctx_get_extradata(CTX_FROM_STREAM(s)))->proto_cb->name)

void stream_send (stream_t *s, netbuf_t *nb);
int stream_free (stream_t *s);
stream_t *stream_new (struct ev_loop *loop);
void stream_attach (stream_t *s, int fd);
void stream_rcv_ctrl(stream_t *s, int stop);

#endif
