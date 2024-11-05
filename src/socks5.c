/**
 * socks5.c
 * An implmentation of socks ver5 downsteam side
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "amoeba.h"
#define LIST_POISONING
#include "list.h"
#include "stream.h"
#include "netbuf.h"
#include "mempool.h"
#include "server.h"

typedef enum {
    SOCKS5_INIT,
    SOCKS5_METHOD_CHOSEN,
    SOCKS5_REPLIED
} sock5_state_t;

#define SOCKS5_VER       5

#define METHOD_NOAUTH    0
#define GSSAPI           1
#define USERPASS         2
#define NOACCEPTABLE     0xff

#define SOCKS5_CMD_CONNECT  1
#define SOCKS5_CMD_BIND     2
#define SOCKS5_CMD_UDP      3

#define SOCKS5_ATYPE_IPv4   1
#define SOCKS5_ATYPE_DOMAIN 3
#define SOCKS5_ATYPE_IPv6   4

typedef struct {
    proto_common_extra_t    common;
} socks5_extra_t;

#define SS_MAGIC    0x9877bbee
typedef struct {
    sock5_state_t           state;
    int                     method;
    type_addr_t             type_addr;
    uint64_t                upstream_id;
    queue_t                 upstream_q;
    task_id_t               target;
    uint32_t                magic;
} socks5_stream_t;

typedef struct {
    uint8_t     ver;
    uint8_t     cmd;
    uint8_t     rsv;
    uint8_t     atype;
} socks5_request_head_t;

static uint32_t enqueue_num, dequeue_num;

static void socks5_start(msg_ev_ctx_t *ctx)
{
    socks5_extra_t *extra;
    extra = msg_ev_ctx_get_extradata(ctx);
    server_start(ctx->loop, extra->common.server);
}

static void socks5_init(msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
}

static inline int
socks5_send_data(socks5_stream_t *ss,
                 stream_t *s,
                 netbuf_t *nb)
{
    message_data_t *m;
    m = (message_data_t*)message_new_encap(task_socks5, MSG_DATA,
                                           sizeof(message_data_t));
    if (m) {
        m->downstream_id = (uint64_t)s;
        m->upstream_id = ss->upstream_id;
        m->nb = nb;
        message_send(&m->h, ss->target);
        return 0;
    }
    return -1;
}

static void socks5_connect_rsp(message_connect_rsp_t *rsp,
                               msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    if (MSG_SIZE(&rsp->h) != sizeof(message_connect_rsp_t)) {
        log_error("%s: wrong format msg", __func__);
        return;
    }
    stream_t *s = (stream_t*)rsp->downstream_id;
    if (!VALID_STREAM(s)) {
        return;
    }
    socks5_stream_t *ss = (socks5_stream_t *)STREAM_PROTO_DATA(s);
    if (ss->magic != SS_MAGIC) {
        return;
    }
    ss->upstream_id = rsp->upstream_id;
    if (!ss->upstream_id) {
        stream_free(s);
        return;
    }

    if (!is_empty(&ss->upstream_q)) {
        netbuf_t *nb;
        while ((nb = (netbuf_t*)dequeue(&ss->upstream_q))) {
            socks5_send_data(ss, s, nb);
            dequeue_num++;
        }
    }
}

static void socks5_disconnect(message_disconnect_t *m,
                              msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    if (MSG_SIZE(&m->h) != sizeof(message_disconnect_t)) {
        log_error("%s: wrong format msg", __func__);
        return;
    }
    stream_t *s = (stream_t*)m->downstream_id;
    if (!VALID_STREAM(s)) {
        return;
    }
    socks5_stream_t *ss = (socks5_stream_t *)STREAM_PROTO_DATA(s);
    if (ss->magic != SS_MAGIC) {
        return;
    }
    if (ss->upstream_id == m->upstream_id) {
        ss->upstream_id = 0;
        stream_free(s);
    }
}

static void socks5_data(message_data_t *m,
                        msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    netbuf_t *nb = m->nb;
    stream_t *s = (stream_t *)m->downstream_id;
    if (!VALID_STREAM(s)) {
        netbuf_free(nb);
        return;
    }
    socks5_stream_t *ss = (socks5_stream_t*)STREAM_PROTO_DATA(s);
    if ((ss->magic == SS_MAGIC) &&
        (ss->upstream_id == m->upstream_id)) {
        stream_send(s, nb);
    } else {
        netbuf_free(nb);
    }
}

static void
socks5_msg_handler(message_queue_t *que, message_header_t *header, void *arg)
{
    UNUSED(que);

    int notfree = 0;
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t *)arg;

    switch (MSG_TYPE(header)) {
        case MSG_DATA:
            socks5_data((message_data_t *)header, ctx);
            break;
        case MSG_CONNECT_RSP:
            socks5_connect_rsp((message_connect_rsp_t*)header, ctx);
            break;
        case MSG_DISCONNECT:
            socks5_disconnect((message_disconnect_t*)header, ctx);
            break;
        case MSG_HEARTBEAT_REQ :
            notfree = 1;
            send_heartbeat_rsp((message_heartbeat_t*)header, ctx->name);
            break;
        case MSG_SYS_INIT:
            socks5_init(ctx);
            notfree = 1;
            send_init_rsp(header, ctx->name);
            break;
        case MSG_SYS_START :
            socks5_start(ctx);
            break;
        default :
            log_error("%s: unsupported type %d\n",
                      __func__, MSG_TYPE(header));
            break;
    }
    if (!notfree) {
        message_free_encap(header);
    }
}

static int socks5_method(stream_t *s, netbuf_t **nb)
{
    netbuf_t *input = *nb;
    int len = input->len;

    if (len < 3) {
        return 0;
    }
    uint8_t ver = input->buf[input->offset];
    uint8_t nmethods = input->buf[input->offset+1];
    uint8_t *methods = (uint8_t*)&input->buf[input->offset+2];

    if (ver != SOCKS5_VER) {
        netbuf_free(*nb);
        *nb = NULL;
        stream_free(s);
        return 0;
    }
    if (len < 2 + nmethods) {
        return 0;
    }

    if (len > 2 + nmethods) {
        /* unlikely */
        netbuf_free(*nb);
        *nb = NULL;
        stream_free(s);
        return 0;
    }

    uint8_t i;
    uint8_t selected = 0xff;
    for (i = 0; i < nmethods; i++) {
        if (methods[i] == METHOD_NOAUTH) {
            /* only support no-auth */
            selected = methods[i];
            break;
        }
    }
    socks5_stream_t *ss = (socks5_stream_t *)STREAM_PROTO_DATA(s);
    *nb = NULL;
    input->buf[input->offset+1] = selected;
    input->len = 2;
    stream_send(s, input);
    ss->state = SOCKS5_METHOD_CHOSEN;
    ss->method = selected;
    return len;
}

static int socks5_request(stream_t *s, netbuf_t **nb)
{
    netbuf_t *input = *nb;
    uint32_t len = (uint32_t)input->len;

    if (len < sizeof(socks5_request_head_t) + 1) {
        return 0;
    }
    //dump_buffer((uint8_t*)NETBUF_START(input), input->len);
    socks5_request_head_t *h;
    h = (socks5_request_head_t*)NETBUF_START(input);
    if (h->ver != SOCKS5_VER || (h->rsv)) {
        goto error_close;
    }
    if (h->cmd == SOCKS5_CMD_BIND) {
        /* cmd not supported. */
        goto error_close;
    }
    socks5_stream_t *ss = (socks5_stream_t *)STREAM_PROTO_DATA(s);
    uint16_t port;
    uint32_t required_len = sizeof(socks5_request_head_t);
    switch (h->atype) {
        case SOCKS5_ATYPE_IPv4:
            required_len += 6;
            if (required_len != len) {
                goto error_close;
            }
            ss->type_addr.atype = ATYPE_IP;
            port = *(uint16_t*)(((uint8_t*)(h+1)) + sizeof(uint32_t));
            struct sockaddr_in *in4 = 
                (struct sockaddr_in *)&ss->type_addr.addr.sock_addr;
            in4->sin_family = AF_INET;
            in4->sin_port = (in_port_t)(port); // no need for htons here
            in4->sin_addr.s_addr = *(uint32_t*)(h+1);
            break;
        case SOCKS5_ATYPE_DOMAIN:
            uint8_t domain_len = *((uint8_t*)(h+1));
            if (!domain_len) {
                goto error_close;
            }
            required_len += domain_len + 3;
            if (required_len != len || domain_len > AMOEBA_MAX_DOMAIN) {
                goto error_close;
            }
            ss->type_addr.atype = ATYPE_DOMAIN;
            memcpy(ss->type_addr.addr.domain_addr.name,
                   (uint8_t*)(h+1) + 1, domain_len);
            ss->type_addr.addr.domain_addr.name[domain_len] = 0;
            ss->type_addr.addr.domain_addr.port =
                ntohs(*((uint16_t*)((uint8_t*)(h+1) + 1 + domain_len)));
            break;
        case SOCKS5_ATYPE_IPv6:
            required_len += 18;
            if (required_len != len) {
                goto error_close;
            }
            ss->type_addr.atype = ATYPE_IP;
            port = *(uint16_t*)(((uint8_t*)(h+1)) + sizeof(struct in6_addr));
            struct sockaddr_in6 *in6 =
                (struct sockaddr_in6 *)&ss->type_addr.addr.sock_addr;
            in6->sin6_family = AF_INET6;
            in6->sin6_port = (in_port_t)(port);
            memcpy(in6->sin6_addr.s6_addr, (uint8_t*)(h+1),
                   sizeof(struct in6_addr));
            break;
        default:
            goto error_close;
            break;
    }

    message_connect_t *m;
    m = (message_connect_t *)message_new_encap(task_socks5, MSG_CONNECT,
                                               sizeof(message_connect_t));
    if (!m) {
        goto error_close;
    }

    ss->target = task_transport;
    m->downstream_id = (uint64_t)s;
    m->type_addr = ss->type_addr;
    if (h->cmd == SOCKS5_CMD_CONNECT) {
        m->flags = 0;
    } else {
        m->flags = CONNECT_FLAG_UDP;
    }
    message_send(&m->h, ss->target);

    *nb = NULL;
    h->cmd = 0;
    stream_send(s, input);
    ss->state = SOCKS5_REPLIED;
    return 0;

error_close:
    netbuf_free(*nb);
    *nb = NULL;
    stream_free(s);
    return 0;
}

static int socks5_relay(stream_t *s, netbuf_t **nb)
{
    socks5_stream_t *ss = (socks5_stream_t *)STREAM_PROTO_DATA(s);

    if (ss->upstream_id) {
        if (socks5_send_data(ss, s, *nb) != -1) {
            *nb = NULL;
            return 0;
        }
    } else {
        enqueue(&ss->upstream_q, (queue_elem_t*)(*nb));
        *nb = NULL;
        enqueue_num++;
        return 0;
    }
    netbuf_free(*nb);
    *nb = NULL;
    return 0;
}

static int socks5_input(stream_t *s, netbuf_t **nb)
{
    socks5_stream_t *ss = (socks5_stream_t *)STREAM_PROTO_DATA(s);

    //dump_buffer((uint8_t*)NETBUF_START(*nb), (*nb)->len);
    switch (ss->state) {
        case SOCKS5_REPLIED:
            return socks5_relay(s, nb);
        case SOCKS5_INIT:
            return socks5_method(s, nb);
        case SOCKS5_METHOD_CHOSEN:
            return socks5_request(s, nb);
        default :
            break;
    }

    return 0;
}


static void *socks5_new(stream_t *s)
{
    UNUSED(s);

    socks5_stream_t *ss;
    int size = sizeof(socks5_stream_t);
    ss = (socks5_stream_t*)mempool_alloc(&size);
    if (ss) {
        ss->state = SOCKS5_INIT;
        ss->method = METHOD_NOAUTH;
        ss->type_addr.atype = 0;
        init_queue(&ss->upstream_q);
        ss->upstream_id = 0;
        ss->magic = SS_MAGIC;
    }
    return ss;
}

static int socks5_free(stream_t *s, void *m)
{
    message_disconnect_t *msg;
    socks5_stream_t *ss = (socks5_stream_t *)m;
    if (ss->upstream_id) {
        msg = (message_disconnect_t*)message_new_encap(task_socks5,
                            MSG_DISCONNECT, sizeof(message_disconnect_t));
        if (msg) {
            msg->downstream_id = (uint64_t)s;
            msg->upstream_id = ss->upstream_id;
            message_send(&msg->h, ss->target);
        }
        ss->upstream_id = 0;
    }

    netbuf_t *nb;
    while ((nb = (netbuf_t*)dequeue(&ss->upstream_q))) {
        netbuf_free(nb);
        dequeue_num++;
    }
    ss->magic = 0;
    mempool_free(m);
    return 0;
}

static proto_ctrl_t socks5_ctrl = {
    task_socks5,
    socks5_new,
    socks5_free,
    socks5_input
};

static void socks5_stats(void)
{
    printf("socks5: enqueue %d, dequeue %d \n",
            enqueue_num, dequeue_num);
}

static void *socks5_main(void *c)
{
    socks5_extra_t *extra;
    jcfg_system_t *cfg = (jcfg_system_t *)c;
    jcfg_local_t *local = &cfg->config.client_cfg.local;

    if (local->proto != proto_socks5) {
        log_error("unknown client protocol(%d)", local->proto);
        exit(-1);
    }
    
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)malloc(sizeof(msg_ev_ctx_t));
    assert(ctx);
    if (msg_ev_ctx_init(ctx, task_socks5, socks5_msg_handler) == -1) {
        exit(-1);
    }

    extra = (socks5_extra_t*)malloc(sizeof(socks5_extra_t));
    assert(extra);
    extra->common.proto_cb = &socks5_ctrl;
    extra->common.server = NULL;
    msg_ev_ctx_set_extradata(ctx, extra);

    struct sockaddr_storage *addr = &local->addr;
    server_t *server = server_new(addr);
    if (!server) {
        log_error("Unable to create server.");
        exit(-1);
    }
    extra->common.server = server;

    register_stats_cb(socks5_stats);

    ev_run(ctx->loop, 0);
    return NULL;
}

INIT_ROUTINE(static void module_init(void))
{
    register_task(client_mode, task_socks5, socks5_main);
}
