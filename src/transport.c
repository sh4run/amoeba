/**
 * transport.c
 * A transport layer above crypto protocol.
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 *
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "amoeba.h"
#include "message.h"
#include "mempool.h"

typedef struct {
    hash_head_t         head;
    jcfg_remote_t       *config;
    task_id_t           target;
    uint64_t            id;
} remote_t;

typedef struct {
    proto_common_extra_t    common;
    remote_t                *default_remote;
    jcfg_system_t           *sys_cfg;
    message_header_t        *init_rsp;
    struct list_head        stream_list;
    hashtable_t             *remote_table;
} transport_client_extra_t;

#define TS_MAGIC    0xa1b2c3d4

/* Flags*/
#define CRYPTO_CLOSED       0x00000001
#define TUNNEL_MODE         0x00000002
#define TRANS_SERVER        0x00000004
#define TRANS_PASSTHROUGH   0x00000008
#define TRANS_DROP          0x00000010

typedef struct {
    remote_t        *remote;
} client_stream_t;

typedef struct {
    netbuf_t        *leftover;
    queue_t         upstream_q;
} server_stream_t;

typedef struct {
    uint32_t        magic;
    uint32_t        flags;
    task_id_t       peer_task;
    task_id_t       crypto_task;
    uint64_t        downstream_id;
    uint64_t        upstream_id;
    stream_t        *stream;
    uint64_t        crypto_id;
    uint16_t        reply_enc;
    uint8_t         rx_extra;
    uint16_t        enc_sent;
    queue_t         enc_q;
    union  {
        client_stream_t  cs_info;
        server_stream_t  ss_info;
    } stream_info;
} transport_stream_t;

#define TRANSPORT_CONNECT   1
#define TRANSPORT_DATA      2
#define TRANSPORT_DISCONN   3
#define TRANSPORT_UDP       4

typedef struct __attribute__((__packed__)) {
    uint16_t    type;
    uint16_t    length;
    uint16_t    enc_bytes;
    uint16_t    reserve;
    uint64_t    downstream_id;
    type_addr_t type_addr;
} transport_connect_t;

typedef struct __attribute__((__packed__)) {
    uint16_t  type;
    uint16_t  length;
    uint64_t  downstream_id;
    uint64_t  upstream_id;
    uint8_t   buf[0];
} transport_data_t;

static uint32_t alloc_num, free_num, crypto_err, replay;
static uint32_t enqueue_num, dequeue_num;
static uint32_t passthrough;

static void *transport_stream_new(stream_t *s);
static int client_stream_free(stream_t *s, void *m);
static int client_stream_input(stream_t *s, netbuf_t **nb);
static void transport_bkpressure(stream_t *s, backpressure_state_t state);
/*
 * transport client stream control block
 */
static proto_ctrl_t client_stream_ctrl = {
    task_transport,
    transport_stream_new,
    client_stream_free,
    client_stream_input,
    transport_bkpressure
};

static void transport_stream_stats(void)
{
    printf("transport: alloc %d, free %d, crypto error %d replay %d\n",
            alloc_num, free_num, crypto_err, replay);
    printf("           enqueue %d, dequeue %d\n", enqueue_num, dequeue_num);
    printf("           passthrough %d\n", passthrough);
}

static void
transport_client_start(msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
}

static int remote_name_hash(void *key)
{
    return string_hash(key);
}

static int remote_name_compare(hash_head_t *node, void *key)
{
    char *name = (char*)key;
    remote_t *remote = (remote_t *)node;

    return strncmp(remote->config->remote_name, name, JCONF_MAX_STR);
}

static void
transport_client_associate_remote(char *remote_name, task_id_t target)
{
    message_asso_req_t *asso_req;
    asso_req = (message_asso_req_t*)message_new_encap(
                                        client_stream_ctrl.name,
                                        MSG_ASSO_REQ,
                                        sizeof(message_asso_req_t));
    if (asso_req) {
        strncpy(asso_req->remote_name, remote_name, JCONF_MAX_STR);
        message_send(&asso_req->h, target);
    }
}

static void
transport_close_crypto(uint64_t crypto_id, 
                       uint64_t transport_id, 
                       task_id_t task)
{
    message_crypto_notify_t *close;
    close = (message_crypto_notify_t*)message_new_encap(task_transport,
                                            MSG_CLOSE_REQ,
                                            sizeof(message_crypto_notify_t));
    if (close) {
        close->crypto_id = crypto_id;
        close->transport_id = transport_id;
        message_send(&close->h, task);
    }
}

static int transport_send_data(uint64_t ds_id,
                               uint64_t us_id,
                               netbuf_t *nb,
                               int src,
                               int target)
{
    message_data_t *m;
    m = (message_data_t*)message_new_encap(src,
                                           MSG_DATA,
                                           sizeof(message_data_t));
    if (m) {
        m->downstream_id = ds_id;
        m->upstream_id = us_id;
        m->nb = nb;
        message_send(&m->h, target);
        return 0;
    }
    return -1;
}

static inline stream_t*
crypto_validate_notify(message_crypto_notify_t *m)
{
    transport_stream_t *ts;
    stream_t *s = (stream_t*)m->transport_id;

    if (!VALID_STREAM(s)) {
        goto stream_deleted;
    }
    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);
    if (ts->magic != TS_MAGIC) {
        goto stream_deleted;
    }
    return s;

stream_deleted:
    transport_close_crypto(m->crypto_id,
                           m->transport_id,
                           MSG_SRC(&m->h));
    return NULL;
}

static void
crypto_error(message_crypto_notify_t *m)
{
    stream_t *s;
    transport_stream_t *ts;

    s = crypto_validate_notify(m);
    if (!s) {
        return;
    }
    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);
    if (!ts->crypto_id) {
        /* If this is the first packet, crypto-id is not set yet */
        ts->crypto_id = m->crypto_id;
    }
    ts->flags |= TRANS_DROP;
    crypto_err++;
    log_info("crypto error received.");
}

static void
crypto_update(message_crypto_notify_t *m)
{
    stream_t *s;
    transport_stream_t *ts;

    s = crypto_validate_notify(m);
    if (!s) {
        return;
    }
    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);
    if (!ts->crypto_id) {
        /* If this is the first packet, crypto-id is not set yet */
        ts->crypto_id = m->crypto_id;
    }

    if (m->rx_ex_bytes) {
       ts->rx_extra = m->rx_ex_bytes;
    }

    if (ts->reply_enc) {
        if (!(ts->flags & TRANS_PASSTHROUGH) &&
             (ts->enc_sent == ts->reply_enc + ts->rx_extra)) {
            ts->flags |= TRANS_PASSTHROUGH;
            passthrough++;
            if (!is_empty(&ts->enc_q)) {
                netbuf_t *b;
                while ((b = (netbuf_t*)dequeue(&ts->enc_q))) {
                    if (ts->flags & TRANS_SERVER) {
                        stream_send(s, b);
                    } else {
                        transport_send_data(ts->downstream_id,
                                            (uint64_t)s,
                                            b,
                                            TASK_FROM_STREAM(s),
                                            ts->peer_task);
                    }
                    dequeue_num++;
                }
            }
        }
    }
}

static void
crypto_replay(message_crypto_notify_t *m)
{
    stream_t *s;
    transport_stream_t *ts;
    s = crypto_validate_notify(m);
    if (!s) {
        return;
    }
    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);
    /* mark to drop following incoming */
    ts->flags |= TRANS_DROP;
    replay++;

    char peer_name[INET6_ADDRSTRLEN+10];
    stream_peer_name(s, peer_name, sizeof(peer_name));
    log_info("possible replay from %s.", peer_name);
}

static void transport_bkpressure(stream_t *s, backpressure_state_t state)
{
    transport_stream_t *ts;
    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);

    if (ts->flags & CRYPTO_CLOSED) {
        return;
    }
    if (ts->flags & TRANS_SERVER) {
        if (ts->upstream_id) {
            send_backpressure(task_transport, ts->peer_task,
                              (uint64_t)s, ts->upstream_id, state);
        }
    } else {
        if (ts->downstream_id) {
            send_backpressure(task_transport, ts->peer_task,
                              ts->downstream_id, (uint64_t)s, state);
        }
    }
}

static void transport_recv_backpressure(message_backpressure_t* m)
{
    transport_stream_t *ts;

    stream_t *s = (stream_t*)m->upstream_id;
    if (!VALID_STREAM(s)) {
        return;
    }
    ts = STREAM_PROTO_DATA(s);
    if(ts->magic != TS_MAGIC) {
        return;
    }
    if (ts->downstream_id == m->downstream_id) {
        stream_rcv_ctrl(s, (m->state == backpressure_on));
    }
}

static void *transport_stream_new(stream_t *s)
{
    int size = sizeof(transport_stream_t);
    transport_stream_t *ts = (transport_stream_t*)mempool_alloc(&size);
    if (ts) {
        memset(ts, 0, sizeof(transport_stream_t));
        ts->stream = s;
        ts->magic = TS_MAGIC;
        init_queue(&ts->enc_q);
    }
    alloc_num++;

    return ts;
}

static int transport_stream_free(stream_t *s, void *m)
{
    transport_stream_t *ts = (transport_stream_t*)m;

    if (ts->crypto_id) {
        ts->flags |= CRYPTO_CLOSED;
        transport_close_crypto(ts->crypto_id,
                               (uint64_t)s,
                               ts->crypto_task);
        ts->crypto_id = 0;
    }
    ts->magic = 0;
    mempool_free(m);
    free_num++;
    return 0;
}

static void
transport_client_init(message_header_t *h, msg_ev_ctx_t *ctx)
{
    /*
     * for each remote server, send ASSO message to crypto task and
     * get the remote-id in ASSO_RSP message.
     * INIT_RSP is sent after all asso responses are received.
     */
    transport_client_extra_t *extra;
    jcfg_remote_t *rcfg;
    jcfg_client_t *client_cfg;
    remote_t *r;

    extra = msg_ev_ctx_get_extradata(ctx);
    client_cfg = &extra->sys_cfg->config.client_cfg;
    extra->init_rsp = h;

    rcfg = (jcfg_remote_t*)queue_head(&client_cfg->remote_que);
    if (rcfg) {
        r = (remote_t*)hashtable_search(extra->remote_table,
                                        rcfg->remote_name);
        if (r) {
            transport_client_associate_remote(rcfg->remote_name, r->target);
            return;
        }
    }
    assert(0);
}

static void
transport_client_asso_rsp(message_asso_rsp_t *msg, msg_ev_ctx_t *ctx)
{
    transport_client_extra_t *extra;

    extra = msg_ev_ctx_get_extradata(ctx);
    extra->default_remote->id = msg->remote_id;

    send_init_rsp(extra->init_rsp, ctx->name);
    extra->init_rsp = NULL;
}

static remote_t *
transport_client_find_dest(transport_client_extra_t *extra,
                           type_addr_t *addr, int udp)
{
    UNUSED(addr);
    UNUSED(udp);
    return extra->default_remote;
}

//#define LOCAL_LOOP
static inline void
transport_send_to_crypto(message_transport_t type,
                         netbuf_t *nb,
                         uint64_t remote_id,
                         uint64_t crypto_id,
                         stream_t *s,
                         task_id_t target)
{
#ifdef LOCAL_LOOP
    message_crypto_rsp_t *req;

    req = (message_crypto_rsp_t*)message_new_encap(
                                        target,
                                        type+1,
                                        sizeof(message_crypto_rsp_t));
    if (req) {
        req->remote_id = remote_id;
        req->crypto_id = crypto_id;
        req->transport_id = (uint64_t)s;
        req->nb = nb;
        message_send(&req->h, TASK_FROM_STREAM(s));
    }
#else
    message_crypto_req_t *req;

    req = (message_crypto_req_t*)message_new_encap(
                                        task_transport,
                                        type,
                                        sizeof(message_crypto_req_t));
    if (req) {
        req->remote_id = remote_id;
        req->crypto_id = crypto_id;
        req->transport_id = (uint64_t)s;
        req->nb = nb;
        message_send(&req->h, target);
    }
#endif
}

static inline void
transport_echo_crypto(transport_stream_t *ts)
{
    message_crypto_notify_t *msg;

    msg = (message_crypto_notify_t *)message_new_encap(task_transport,
                                               MSG_CRYPTO_UPDATE,
                                               sizeof(message_crypto_notify_t));
    if (msg) {
        msg->crypto_id = (uint64_t)ts->crypto_id;
        msg->transport_id = (uint64_t)ts->stream;
        message_send(&msg->h, ts->crypto_task);
    }
}

static void
transport_client_send_to_crypto(message_transport_t type,
                                netbuf_t *nb,
                                stream_t *s)
{
    transport_stream_t *ts;

    ts = STREAM_PROTO_DATA(s);
    transport_send_to_crypto(type, nb,
                             ts->stream_info.cs_info.remote->id,
                             ts->crypto_id,
                             s,
                             ts->crypto_task);
}

static int
is_https(type_addr_t *dest)
{
    uint16_t port;
    if (dest->atype == ATYPE_IP) {
        if (dest->addr.sock_addr.ss_family == AF_INET) {
            struct sockaddr_in *in4 =
                    (struct sockaddr_in *)&dest->addr.sock_addr;
            port = in4->sin_port;
        } else {
            struct sockaddr_in6 *in6 =
                    (struct sockaddr_in6 *)&dest->addr.sock_addr;
            port = in6->sin6_port;
        }
    } else {
        port = dest->addr.domain_addr.port;
    }
    return (port == 443);
}

static void
transport_client_connect(message_connect_t *msg, msg_ev_ctx_t *ctx)
{
    message_connect_rsp_t  *reply;
    struct sockaddr_storage *addr;
    task_id_t peer_task = MSG_SRC(&msg->h);
    transport_client_extra_t *extra;
    transport_stream_t *ts;
    remote_t *dest;

    extra = msg_ev_ctx_get_extradata(ctx);

    if (MSG_SIZE(&msg->h) != sizeof(message_connect_t)) {
        log_error("%s: wrong format msg", __func__);
        return;
    }

    reply = (message_connect_rsp_t*)message_new_encap(client_stream_ctrl.name,
                                        MSG_CONNECT_RSP,
                                        sizeof(message_connect_rsp_t));
    if (!reply) {
        return;
    }
    reply->downstream_id = msg->downstream_id;
    reply->upstream_id = 0;

    dest = transport_client_find_dest(extra, &msg->type_addr,
                                      msg->flags & CONNECT_FLAG_UDP);
    stream_t *s = NULL;

    addr = &dest->config->addr;
    int fd = socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int rtn = connect(fd, (struct sockaddr*)addr,
                      addr->ss_family == AF_INET ? sizeof(struct sockaddr):
                                              sizeof(struct sockaddr_in6));
    if (rtn ==-1 && errno != EINPROGRESS) {
        /* not able to connect */
        close(fd);
        goto connect_end;
    }

    s = stream_new(ctx->loop);
    if (!s) {
        goto connect_end;
    }

    list_add_tail(&s->node, &extra->stream_list);
    ts = STREAM_PROTO_DATA(s);
    reply->upstream_id = (uint64_t)s;
    ts->downstream_id = msg->downstream_id;
    ts->peer_task = peer_task;
    ts->stream_info.cs_info.remote = dest;
    ts->crypto_task = dest->target;

    if (is_https(&msg->type_addr)) {
        ts->reply_enc = 3500 + (((uint64_t)s >> 4) & 0xff);
    } else {
        ts->reply_enc = 0;
    }

    stream_attach(s, fd);

    netbuf_t *nb;
    nb = netbuf_alloc(MSG_SIZE(&msg->h));
    if (nb) {
        transport_connect_t *connect;
        connect = (transport_connect_t*)NETBUF_START(nb);
        if (!msg->flags & CONNECT_FLAG_UDP) {
            connect->type = htons(TRANSPORT_CONNECT);
        } else {
            connect->type = htons(TRANSPORT_UDP);
        }
        connect->length        = htons(sizeof(transport_connect_t));
        connect->downstream_id = 0;
        connect->enc_bytes = htons(ts->reply_enc);
        connect->reserve = 0;
        connect->type_addr     = msg->type_addr;
        nb->len = sizeof(transport_connect_t);
        transport_client_send_to_crypto(MSG_ENCRYPT_REQ, nb, s);
    }

connect_end:
    message_send(&reply->h, peer_task);
}

static void
transport_client_data(message_data_t *msg, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    transport_data_t *data;
    transport_stream_t *ts;

    stream_t *s = (stream_t*)msg->upstream_id;
    if (!VALID_STREAM(s)) {
        goto client_data_exit;
    }
    ts = STREAM_PROTO_DATA(s);
    if(ts->magic != TS_MAGIC) {
        goto client_data_exit;
    }
    if (ts->downstream_id != msg->downstream_id) {
        goto client_data_exit;
    }

    netbuf_t *nb = msg->nb;
    if (nb->offset >= (int)(sizeof(transport_data_t))) {
        nb->offset -= sizeof(transport_data_t);
        nb->len += sizeof(transport_data_t);
        data = (transport_data_t *)NETBUF_START(nb);
        data->type = htons(TRANSPORT_DATA);
        data->length = htons(nb->len);
        data->downstream_id = 0;
        data->upstream_id = 0;
        transport_client_send_to_crypto(MSG_ENCRYPT_REQ, nb, s);
        return;
    } else {
        netbuf_t *b;
        b = netbuf_alloc(sizeof(transport_data_t) + nb->len);
        if (b) {
            data = (transport_data_t *)NETBUF_START(b);
            data->type = htons(TRANSPORT_DATA);
            data->length = htons(sizeof(transport_data_t) + msg->nb->len);
            data->downstream_id = 0;
            data->upstream_id = 0;
            b->len = sizeof(transport_data_t);
            nb = netbuf_join(b, nb);
            transport_client_send_to_crypto(MSG_ENCRYPT_REQ, nb, s);
            return;
        } else {
            log_error("out of memory");
            netbuf_free(msg->nb);
            stream_free(s);
            return;
        }
    }

client_data_exit:    
    netbuf_free(msg->nb);
}

static void
transport_client_disconnect(message_disconnect_t *msg, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);

    if (MSG_SIZE(&msg->h) != sizeof(message_disconnect_t)) {
        log_error("%s: wrong format msg", __func__);
        return;
    }
    stream_t *s = (stream_t*)msg->upstream_id;
    if (!VALID_STREAM(s)) {
        return;
    }
    transport_stream_t *ts;
    ts = STREAM_PROTO_DATA(s);
    if (ts->magic != TS_MAGIC) {
        return;
    }
    if (ts->downstream_id == msg->downstream_id) {
        ts->downstream_id = 0;
        if (ts->crypto_id) {
            ts->flags |= CRYPTO_CLOSED;
            transport_close_crypto(ts->crypto_id,
                                   (uint64_t)s,
                                   ts->crypto_task);
            /*
             * stream is freed after response is received.
             */
        } else {
            stream_free(s);
        }
    }
}

static void
transport_client_encrypt_rsp(message_crypto_rsp_t *rsp, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    stream_t *s;
    transport_stream_t *ts;

    s = (stream_t*)rsp->transport_id;
    if (!VALID_STREAM(s)) {
        goto encrypt_rsp_err_exit;
    }

    ts = STREAM_PROTO_DATA(s);
    if (!ts->crypto_id) {
        ts->crypto_id = rsp->crypto_id;
    } else {
        if (ts->crypto_id != rsp->crypto_id) {
            log_info("invalid stream.");
            goto encrypt_rsp_err_exit;
        }
    }

    stream_send(s, rsp->nb);
    return;

encrypt_rsp_err_exit:
    netbuf_free(rsp->nb);
}

static void
transport_client_decrypt_rsp(message_crypto_rsp_t *rsp, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    stream_t *s;
    transport_stream_t *ts;

    s = (stream_t*)rsp->transport_id;
    if (!VALID_STREAM(s)) {
        goto decrypt_rsp_error_exit;
    }

    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);
    if (ts->downstream_id && ts->magic == TS_MAGIC && ts->stream == s) {
        transport_send_data(ts->downstream_id,
                            (uint64_t)s,
                            rsp->nb,
                            TASK_FROM_STREAM(s),
                            ts->peer_task);
        return;
    }

decrypt_rsp_error_exit:
    netbuf_free(rsp->nb);
}

static void
transport_client_close_rsp(message_crypto_notify_t *rsp)
{
    stream_t *s;
    transport_stream_t *ts;

    s = (stream_t*)rsp->transport_id;
    if (VALID_STREAM(s)) {
        ts = STREAM_PROTO_DATA(s);
        ts->crypto_id = 0;
        stream_free(s);
    } else {
        //log_info("obsolete stream");
    }
}

static void
client_msg_handler(message_queue_t *que, message_header_t *header, void *arg)
{
    UNUSED(que);

    int notfree = 0;
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t *)arg;

    switch (MSG_TYPE(header)) {
        case MSG_DATA:
            transport_client_data((message_data_t*)header, ctx);
            break;
        case MSG_ENCRYPT_RSP:
            transport_client_encrypt_rsp((message_crypto_rsp_t*)header, ctx);
            break;
        case MSG_DECRYPT_RSP:
            transport_client_decrypt_rsp((message_crypto_rsp_t*)header, ctx);
            break;
        case MSG_CLOSE_RSP:
            transport_client_close_rsp((message_crypto_notify_t*)header);
            break;
        case MSG_CONNECT:
            transport_client_connect((message_connect_t*)header, ctx);
            break;
        case MSG_DISCONNECT:
            transport_client_disconnect((message_disconnect_t*)header, ctx);
            break;
        case MSG_CRYPTO_ERROR:
            crypto_error((message_crypto_notify_t*)header);
            break;
        case MSG_CRYPTO_UPDATE:
            crypto_update((message_crypto_notify_t*)header);
            break;
        case MSG_BACKPRESSURE:
            transport_recv_backpressure((message_backpressure_t*)header);
            break;
        case MSG_HEARTBEAT_REQ:
            notfree = 1;
            send_heartbeat_rsp((message_heartbeat_t*)header, ctx->name);
            break;
        case MSG_SYS_INIT:
            transport_client_init(header, ctx);
            notfree = 1;
            break;
        case MSG_SYS_START :
            transport_client_start(ctx);
            break;
        case MSG_ASSO_RSP:
            transport_client_asso_rsp((message_asso_rsp_t*)header, ctx);
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

static int client_stream_free(stream_t *s, void *m)
{
    message_disconnect_t *msg;
    transport_stream_t *ts = (transport_stream_t*)m;
    if (ts->downstream_id) {
        msg = (message_disconnect_t*)message_new_encap(TASK_FROM_STREAM(s),
                            MSG_DISCONNECT, sizeof(message_disconnect_t));
        if (msg) {
            msg->downstream_id = ts->downstream_id;
            msg->upstream_id = (uint64_t)s;
            message_send(&msg->h, ts->peer_task);
        }
        ts->downstream_id = 0;
    }

    return transport_stream_free(s, m);
}

static int client_stream_input(stream_t *s, netbuf_t **nb)
{
    transport_stream_t *ts;
    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);

    if (ts->flags & CRYPTO_CLOSED) {
        netbuf_free(*nb);
    } else {
        uint16_t l = ts->reply_enc + ts->rx_extra;
        if (ts->reply_enc) {
            if (ts->flags & TRANS_PASSTHROUGH) {
                /* reply head encryption completed */
                transport_send_data(ts->downstream_id,
                                    (uint64_t)s,
                                    *nb,
                                    TASK_FROM_STREAM(s),
                                    ts->peer_task);
                goto client_input_end;
            }
            if (ts->enc_sent == l) {
                /* all sent to crypto, but not all crypto rsp received */
                enqueue(&ts->enc_q, (queue_elem_t*)(*nb));
                enqueue_num++;
                goto client_input_end;
            }
            if ((*nb)->len + ts->enc_sent <= l) {
                ts->enc_sent += (*nb)->len;
            } else {
                int send_len = l - ts->enc_sent;
                netbuf_t *b = netbuf_alloc((*nb)->len - send_len);
                if (!b) {
                    log_error("out of memory.");
                    netbuf_free(*nb);
                    goto client_input_end;
                }
                memcpy(NETBUF_START(b),
                       NETBUF_START(*nb) + send_len,
                       (*nb)->len - send_len);
                b->len = (*nb)->len - send_len;
                (*nb)->len = send_len;
                enqueue(&ts->enc_q, (queue_elem_t*)b);
                enqueue_num++;
                ts->enc_sent += send_len;
            }
        }
        transport_client_send_to_crypto(MSG_DECRYPT_REQ, *nb, s);
        if (ts->reply_enc && ts->enc_sent == l) {
            transport_echo_crypto(ts);
        }
    }

client_input_end:
    *nb = NULL;
    return 0;
}

static void *transport_client(void *c)
{
    jcfg_system_t *cfg = (jcfg_system_t *)c;
    transport_client_extra_t *extra;

    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)malloc(sizeof(msg_ev_ctx_t));
    assert(ctx);
    if (msg_ev_ctx_init(ctx, client_stream_ctrl.name,
                                  client_msg_handler) == -1) {
        exit(-1);
    }
    
    extra = malloc(sizeof(transport_client_extra_t));
    assert(extra);
    extra->common.proto_cb = &client_stream_ctrl;
    extra->common.server = NULL;
    INIT_LIST_HEAD(&extra->stream_list);
    extra->sys_cfg = cfg;
    extra->default_remote = NULL;
    extra->init_rsp = NULL;
    extra->remote_table = hashtable_init(256,
                                         remote_name_hash,
                                         remote_name_compare);
    assert(extra->remote_table);

    /*
     * add all remote server into a hash table.
     */
    jcfg_remote_t *rcfg;
    jcfg_client_t *client_cfg;
    remote_t *r;
    int first = 1;
    client_cfg = &cfg->config.client_cfg;
    foreach_queue(rcfg, jcfg_remote_t*, &client_cfg->remote_que) {
        r = malloc(sizeof(remote_t));
        assert(r);
        r->config = rcfg;
        switch (rcfg->proto) {
            case proto_amoeba :
                r->target = task_amoeba;
                break;
            default:
                /* not supportred */
                assert(0);
                break;
        }
        r->id = 0;
        hashtable_add(extra->remote_table, r, rcfg->remote_name);
        if (first) {
            first = 0;
            extra->default_remote = r;
        }
    }

    msg_ev_ctx_set_extradata(ctx, extra);

    register_stats_cb(transport_stream_stats);

    ev_run(ctx->loop, 0);
    return NULL;
}

/**
 *  transport server portion
 */
typedef struct {
    proto_common_extra_t    common;
    jcfg_system_t           *sys_cfg;
    task_id_t               crypto_task;
} transport_server_extra_t;

static void *server_stream_new(stream_t *s);
static int server_stream_free(stream_t *s, void *m);
static int server_stream_input(stream_t *s, netbuf_t **nb);

/*
 * transport server stream control block
 */
static proto_ctrl_t server_stream_ctrl = {
    task_transport,
    server_stream_new,
    server_stream_free,
    server_stream_input,
    transport_bkpressure
};

static void *server_stream_new(stream_t *s)
{
    transport_stream_t *ts = transport_stream_new(s);
    if (ts) {
        msg_ev_ctx_t *ctx = CTX_FROM_STREAM(s);
        transport_server_extra_t *extra;
        extra = msg_ev_ctx_get_extradata(ctx);
        ts->crypto_task = extra->crypto_task;
        init_queue(&ts->stream_info.ss_info.upstream_q);
        ts->peer_task = task_upstream;
        ts->flags |= TRANS_SERVER;
    }
    return ts;
}

static int server_stream_free(stream_t *s, void *m)
{
    transport_stream_t *ts = (transport_stream_t *)m;
    message_disconnect_t *msg;

    if (ts->upstream_id) {
        msg = (message_disconnect_t*)message_new_encap(server_stream_ctrl.name,
                            MSG_DISCONNECT, sizeof(message_disconnect_t));
        if (msg) {
            msg->downstream_id = (uint64_t)s;
            msg->upstream_id = ts->upstream_id;
            message_send(&msg->h, ts->peer_task);
        }
        ts->upstream_id = 0;
    }

    netbuf_t *nb;
    while ((nb = (netbuf_t*)dequeue(&ts->stream_info.ss_info.upstream_q))) {
        netbuf_free(nb);
        dequeue_num++;
    }
    while ((nb = (netbuf_t*)dequeue(&ts->enc_q))) {
        netbuf_free(nb);
        dequeue_num++;
    }
    if (ts->stream_info.ss_info.leftover) {
        netbuf_free(ts->stream_info.ss_info.leftover);
    }

    return transport_stream_free(s, m);
}

static void server_relay_connect(stream_t *s,
                                 transport_connect_t *connect, 
                                 int udp)
{
    transport_stream_t *ts;
    message_connect_t *m;

    ts = (transport_stream_t*)STREAM_PROTO_DATA(s);
    m = (message_connect_t*)message_new_encap(server_stream_ctrl.name,
                                              MSG_CONNECT,
                                              sizeof(message_connect_t));
    if (!m) {
        stream_free(s);
        return;
    }
    ts->downstream_id = ntohll(connect->downstream_id);
    ts->reply_enc = ntohs(connect->enc_bytes);
    m->downstream_id = (uint64_t)s;
    m->type_addr = connect->type_addr;
    m->flags = udp ? CONNECT_FLAG_UDP : 0;

    message_send(&m->h, ts->peer_task);
}

static inline
int server_relay_data(stream_t *s, netbuf_t **nbp)
{
    transport_stream_t *ts;
    netbuf_t *b, *nb;
    uint16_t length;
    transport_data_t *data;

    nb = *nbp;
    ts = (transport_stream_t *)STREAM_PROTO_DATA(s);
    data = (transport_data_t*)NETBUF_START(nb);
    length = ntohs(data->length);

    if (length > nb->len) {
        /*
         * incomplete data segment
         * create a new head for next packet.
         */
        b = netbuf_alloc(sizeof(transport_data_t));
        if (!b) {
            log_error("out of memory");
            stream_free(s);
            return 0;
        }
        transport_data_t *h = (transport_data_t*)NETBUF_START(b);
        h->type = data->type;
        h->length = htons(length - nb->len + sizeof(transport_data_t));
        h->downstream_id = data->downstream_id;
        h->upstream_id = data->upstream_id;
        b->len = sizeof(transport_data_t);
        *nbp = b;
        nb->offset += sizeof(transport_data_t);
        nb->len -= sizeof(transport_data_t);

        length = 0;
        goto send_and_exit;
    }

    if (length > (uint16_t)nb->len - length) {
        /* the remaining bytes is less than the processed */
        uint16_t len = nb->len - length;
        b = netbuf_alloc(STREAM_BUF_LEN);
        if (!b) {
            log_error("out of memory");
            stream_free(s);
            return 0;
        }
        b->len = len;
        memcpy(NETBUF_START(b), NETBUF_START(nb) + length, len);
        *nbp = b;
        nb->len = length - sizeof(transport_data_t);
        nb->offset += sizeof(transport_data_t);

        length = 0;
        goto send_and_exit;
    }

    nb = netbuf_alloc(length - sizeof(transport_data_t));
    if (!nb) {
        stream_free(s);
        log_error("out of memory");
        return 0;
    }
    memcpy(NETBUF_START(nb), (char*)(data->buf),
           length - sizeof(transport_data_t));
    nb->len += length - sizeof(transport_data_t);

send_and_exit:
    if (ts->upstream_id) {
        transport_send_data((uint64_t)s, ts->upstream_id, nb,
                            TASK_FROM_STREAM(s), ts->peer_task);
    } else {
        enqueue(&ts->stream_info.ss_info.upstream_q, (queue_elem_t*)nb);
        enqueue_num++;
    }
    return length;
}

static int server_process_input(stream_t *s, netbuf_t **nbp)
{
    uint16_t type, length;

    if ((*nbp)->len < 4) {
        return 0;
    }

    type = ntohs(*(uint16_t*)NETBUF_START(*nbp));
    length = ntohs(*((uint16_t*)NETBUF_START(*nbp)+1));
    if ((*nbp)->len < length) {
        if (type != TRANSPORT_DATA) {
            return 0;
        } else {
            /* make sure the data head is complete */
            if ((*nbp)->len < 160) {
                return 0;
            }
        }
    }

    switch (type) {
        case TRANSPORT_DATA:
            length = server_relay_data(s, nbp);
            break;
        case TRANSPORT_CONNECT:
        case TRANSPORT_UDP:
            transport_connect_t *connect;
            connect = (transport_connect_t *)NETBUF_START(*nbp);
            server_relay_connect(s, connect, (type == TRANSPORT_UDP)); 
            break;
        default :
            break;
    }

    return length;
}

static inline void
transport_server_send_to_crypto(message_transport_t type,
                                netbuf_t *nb,
                                stream_t *s)
{
    transport_stream_t *ts;

    ts = STREAM_PROTO_DATA(s);
    transport_send_to_crypto(type, nb,
                             0,
                             ts->crypto_id,
                             s,
                             ts->crypto_task);
}

static int server_stream_input(stream_t *s, netbuf_t **nb)
{
    transport_stream_t *ts = (transport_stream_t *)STREAM_PROTO_DATA(s);
    if (ts->flags & CRYPTO_CLOSED) {
        /* this piece arrives late */
        netbuf_free(*nb);
        *nb = NULL;
        return 0;
    }
    if (ts->flags & TRANS_DROP) {
        netbuf_free(*nb);
        *nb = NULL;
        return 0;
    }

    transport_server_send_to_crypto(MSG_DECRYPT_REQ, *nb, s);
    *nb = NULL;
    return 0;
}

static void transport_server_start(msg_ev_ctx_t *ctx)
{
    transport_server_extra_t *extra;
    extra = msg_ev_ctx_get_extradata(ctx);
    server_start(ctx->loop, extra->common.server);
}

static void transport_server_init(msg_ev_ctx_t *ctx)
{
    jcfg_server_t *server_cfg;
    transport_server_extra_t *extra;

    extra = msg_ev_ctx_get_extradata(ctx);
    server_cfg = &extra->sys_cfg->config.server_cfg;

    if (server_cfg->proto != proto_amoeba) {
        log_error("unknown client protocol(%d)", server_cfg->proto);
        exit(-1);
    }
    extra->crypto_task = task_amoeba;

    struct sockaddr_storage *addr = &server_cfg->addr;
    char buffer[128];
    if (sockaddr_to_string(addr, buffer, sizeof(buffer)) == -1) {
        log_error("server ip error: %s", buffer);
        exit(-1);
    }
    server_t *server = server_new(addr);
    if (!server) {
        log_error("Unable to create server.");
        exit(-1);
    }
    extra->common.server = server;
}

static void server_decrypt_rsp(message_crypto_rsp_t *rsp, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    stream_t *s;

    s = (stream_t*)rsp->transport_id;
    if (!VALID_STREAM(s)) {
        goto server_decrypt_rsp_error_exit;
    }

    transport_stream_t *ts = (transport_stream_t *)STREAM_PROTO_DATA(s);
    if (!ts->crypto_id) {
        ts->crypto_id = rsp->crypto_id;
    } else {
        if (ts->crypto_id != rsp->crypto_id) {
            log_info("invalid stream.");
            goto server_decrypt_rsp_error_exit;
        }
    }
    /* there is some remaining data */
    /* combine all data into one netbuf */
    if (ts->stream_info.ss_info.leftover) {
        ts->stream_info.ss_info.leftover =
            netbuf_join(ts->stream_info.ss_info.leftover, rsp->nb);
        if (!ts->stream_info.ss_info.leftover) {
            log_error("out of memory(%s)", __func__);
            stream_free(s);
            return;
        }
    } else {
        ts->stream_info.ss_info.leftover = rsp->nb;
    }

    int len;
    while ((len =
              server_process_input(s, &ts->stream_info.ss_info.leftover))) {
        ts->stream_info.ss_info.leftover->offset += len;
        ts->stream_info.ss_info.leftover->len -= len;
        if (!ts->stream_info.ss_info.leftover->len) {
            netbuf_free(ts->stream_info.ss_info.leftover);
            ts->stream_info.ss_info.leftover = NULL;
            return;
        }
    }
    return;

server_decrypt_rsp_error_exit:
    netbuf_free(rsp->nb);
}

static void
server_encrypt_rsp(message_crypto_rsp_t *rsp, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    stream_t *s;
    transport_stream_t *ts;

    s = (stream_t*)rsp->transport_id;
    if (!VALID_STREAM(s)) {
        goto encrypt_rsp_err_exit;
    }

    ts = STREAM_PROTO_DATA(s);
    if (!ts->crypto_id) {
        ts->crypto_id = rsp->crypto_id;
    } else {
        if (ts->crypto_id != rsp->crypto_id) {
            log_info("invalid stream.");
            goto encrypt_rsp_err_exit;
        }
    }
    stream_send(s, rsp->nb);
    return;

encrypt_rsp_err_exit:
    netbuf_free(rsp->nb);
}

static void server_connect_rsp(message_connect_rsp_t *rsp,
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
    transport_stream_t *ts = (transport_stream_t *)STREAM_PROTO_DATA(s);
    if (ts->magic != TS_MAGIC) {
        return;
    }
    ts->upstream_id = rsp->upstream_id;
    if (!ts->upstream_id) {
        stream_free(s);
        return;
    }

    if (!is_empty(&ts->stream_info.ss_info.upstream_q)) {
        netbuf_t *nb;
        while ((nb = (netbuf_t*)dequeue(
                                &ts->stream_info.ss_info.upstream_q))) {
            transport_send_data((uint64_t)s, ts->upstream_id, nb,
                                TASK_FROM_STREAM(s), ts->peer_task);
            dequeue_num++;
        }
    }
}

static void server_recv_backpressure(message_backpressure_t* m)
{
    transport_stream_t *ts;

    stream_t *s = (stream_t*)m->downstream_id;
    if (!VALID_STREAM(s)) {
        return;
    }
    ts = STREAM_PROTO_DATA(s);
    if(ts->magic != TS_MAGIC) {
        return;
    }
    if (ts->upstream_id == m->upstream_id) {
        stream_rcv_ctrl(s, (m->state == backpressure_on));
    }
}

/* Data from upstream */
static void server_data(message_data_t *m, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    netbuf_t *nb = m->nb;
    stream_t *s = (stream_t *)m->downstream_id;
    if (!VALID_STREAM(s)) {
        netbuf_free(nb);
        return;
    }
    transport_stream_t *ts = (transport_stream_t*)STREAM_PROTO_DATA(s);
    if (ts->magic != TS_MAGIC) {
        netbuf_free(nb);
        return;
    }
    if (ts->upstream_id == m->upstream_id) {
        if (ts->reply_enc) {
            if (ts->flags & TRANS_PASSTHROUGH) {
                /* reply head encryption completed */
                stream_send(s, nb);
                return;
            }
            if (ts->enc_sent == ts->reply_enc) {
                /* all sent to crypto, but not all crypto rsp received */
                enqueue(&ts->enc_q, (queue_elem_t*)nb);
                enqueue_num++;
                return;
            }
            if (nb->len + ts->enc_sent <= ts->reply_enc) {
                ts->enc_sent += nb->len;
            } else {
                int send_len = ts->reply_enc - ts->enc_sent;
                netbuf_t *b = netbuf_alloc(nb->len - send_len);
                if (!b) {
                    netbuf_free(nb);
                    stream_free(s);
                    return;
                }
                memcpy(NETBUF_START(b),
                       NETBUF_START(nb) + send_len,
                       nb->len - send_len);
                b->len = nb->len - send_len;
                nb->len = send_len;
                enqueue(&ts->enc_q, (queue_elem_t*)b);
                enqueue_num++;
                ts->enc_sent += send_len;
            }
        }
        transport_server_send_to_crypto(MSG_ENCRYPT_REQ, nb, s);
        if (ts->reply_enc && ts->enc_sent == ts->reply_enc) {
            transport_echo_crypto(ts);
        }
    } else {
        netbuf_free(nb);
    }    
}

static void server_disconnect(message_disconnect_t *m, msg_ev_ctx_t *ctx)
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
    transport_stream_t *ts = (transport_stream_t *)STREAM_PROTO_DATA(s);
    if (ts->magic != TS_MAGIC) {
        return;
    }      
    if (ts->upstream_id == m->upstream_id) {
        ts->upstream_id = 0;
        if (ts->crypto_id) {
            ts->flags |= CRYPTO_CLOSED;
            transport_close_crypto(ts->crypto_id,
                                   (uint64_t)s,
                                   ts->crypto_task);
        } else {
            stream_free(s);
        }
    }
}

static void
server_close_rsp(message_crypto_notify_t *rsp)
{
    stream_t *s;
    transport_stream_t *ts;

    s = (stream_t*)rsp->transport_id;
    if (VALID_STREAM(s)) {
        ts = (transport_stream_t *)STREAM_PROTO_DATA(s);
        ts->crypto_id = 0;
        stream_free(s);
    } else {
        //log_info("obsolete stream");
    }
}

static void
server_msg_handler(message_queue_t *que, message_header_t *header, void *arg)
{
    UNUSED(que);

    int notfree = 0;
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t *)arg;

    switch (MSG_TYPE(header)) {
        case MSG_DATA:
            server_data((message_data_t *)header, ctx);
            break;
        case MSG_ENCRYPT_RSP:
            server_encrypt_rsp((message_crypto_rsp_t*)header, ctx);
            break;
        case MSG_DECRYPT_RSP:
            server_decrypt_rsp((message_crypto_rsp_t*)header, ctx);
            break;
        case MSG_CRYPTO_ERROR:
            crypto_error((message_crypto_notify_t*)header);
            break;
        case MSG_CLOSE_RSP:
            server_close_rsp((message_crypto_notify_t*)header);
            break;
        case MSG_CRYPTO_UPDATE:
            crypto_update((message_crypto_notify_t*)header);
            break;
        case MSG_CONNECT_RSP:
            server_connect_rsp((message_connect_rsp_t*)header, ctx);
            break;
        case MSG_DISCONNECT:
            server_disconnect((message_disconnect_t*)header,ctx);
            break;
        case MSG_BACKPRESSURE:
            server_recv_backpressure((message_backpressure_t*)header);
            break;
        case MSG_HEARTBEAT_REQ :
            notfree = 1;
            send_heartbeat_rsp((message_heartbeat_t*)header, ctx->name);
            break;
        case MSG_CRYPTO_REPLAY:
            crypto_replay((message_crypto_notify_t*)header);
            break;
        case MSG_SYS_INIT:
            transport_server_init(ctx);
            notfree = 1;
            send_init_rsp(header, ctx->name);
            break;
        case MSG_SYS_START :
            transport_server_start(ctx);
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

static void *transport_server(void *c)
{
    jcfg_system_t *cfg = (jcfg_system_t *)c;
    transport_server_extra_t *extra;

    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)malloc(sizeof(msg_ev_ctx_t));
    assert(ctx);
    if (msg_ev_ctx_init(ctx, server_stream_ctrl.name, 
                                server_msg_handler) == -1) {
        exit(-1);
    }

    extra = (transport_server_extra_t*)malloc(sizeof(transport_server_extra_t));
    assert(extra);
    extra->common.proto_cb = &server_stream_ctrl;
    extra->common.server = NULL;
    extra->sys_cfg = cfg;
    msg_ev_ctx_set_extradata(ctx, extra);

    register_stats_cb(transport_stream_stats);

    ev_run(ctx->loop, 0);
    return NULL;
}

INIT_ROUTINE(static void module_init(void))
{
    register_task(server_mode, task_transport, transport_server);
    register_task(client_mode, task_transport, transport_client);
}
