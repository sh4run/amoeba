/**
 * upstream.c
 * An implmentation of sock5 upstream side
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 *
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <errno.h>

#include "amoeba.h"
#include "mempool.h"

#define DNS_SIGNO   (SIGRTMIN+1)

typedef struct {
    proto_common_extra_t    common;
    struct list_head        stream_list;
    ev_io                   dns_io;
    int                     dns_fd;
} upstream_extra_t;

#define UP_MAGIC    0xfefe6565
typedef struct {
    struct gaicb    dns_req;
    uint64_t        downstream_id;
    task_id_t       downstream_task;
    stream_t        *stream;
    int             obsolete;
    uint32_t        magic;
} upstream_t;

#define UPSTREAM_FROM_IDLETIMER(io) \
        ((stream_t*)((char*)(io) - offsetof(stream_t, idle_timer)))

static upstream_extra_t *upstream_extra;

static uint32_t packet_drop;

static void
upstream_connect_domain(upstream_t *u)
{
    struct gaicb *req = &u->dns_req;
    struct addrinfo *result = req->ar_result;
    int fd, rtn;

    if (result) {
        fd = socket(result->ai_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        int opt = 1;
        setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        rtn = connect(fd, result->ai_addr, result->ai_addrlen);
        if (rtn ==-1 && errno != EINPROGRESS) {
            /* not able to connect */
            u->obsolete = 1;
            close(fd);
        } else {
            stream_attach(u->stream, fd);
        }
    } else {
        u->obsolete = 1;
    }
    /*
     * free the resources before deleting this entry.
     */
    if (result) {
        freeaddrinfo(result);
    }
    free((void*)(req->ar_name));
    req->ar_name = NULL;
    free((void*)(req->ar_service));
    req->ar_service = NULL;

    if (u->obsolete) {
        stream_free(u->stream);
    }
}

static void
dns_req_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    UNUSED(revents);
    UNUSED(loop);

    ssize_t s;
    struct signalfd_siginfo sinfo;
    struct gaicb *req;

    upstream_extra_t *extra;
    upstream_t *u;
    extra = (upstream_extra_t*)((char*)(w) -
                                offsetof(upstream_extra_t, dns_io));
    while((s = read(extra->dns_fd, &sinfo,
                    sizeof(struct signalfd_siginfo))) > 0) {
        if (s != sizeof(struct signalfd_siginfo)) {
            return;
        }
        req = (struct gaicb *)sinfo.ssi_ptr;
        u = (upstream_t *)req;
        if (u->magic != UP_MAGIC) {
            return;
        }
        upstream_connect_domain(u);
    }
}

static void
upstream_start(msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
}

static void
upstream_init(msg_ev_ctx_t *ctx)
{
    int sfd;
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, DNS_SIGNO);
    sfd = signalfd(-1, &mask, SFD_NONBLOCK);

    upstream_extra_t *extra = msg_ev_ctx_get_extradata(ctx);
    extra->dns_fd = sfd;
    ev_io_init(&extra->dns_io, dns_req_read_cb, sfd, EV_READ);
    ev_io_start(ctx->loop, &extra->dns_io);
}

static int
resolve_domain_async(upstream_t *u, domain_addr_t *domain)
{
    struct gaicb *req = &(u->dns_req);
    char port[10];
    struct sigevent sig;

    snprintf(port, sizeof(port), "%d", domain->port);
    req->ar_name = strdup(domain->name);
    req->ar_service = strdup(port);
    req->ar_request = NULL;
    req->ar_result = NULL;
    memset(&sig, 0, sizeof(struct sigevent));
    sig.sigev_notify = SIGEV_SIGNAL;
    sig.sigev_value.sival_ptr = req;
    sig.sigev_signo = DNS_SIGNO;

    getaddrinfo_a(GAI_NOWAIT, &req, 1, &sig);
    return 0;
}

static void
upstream_connect(message_connect_t *msg, msg_ev_ctx_t *ctx)
{
    message_connect_rsp_t  *reply;
    struct sockaddr_storage *addr;
    task_id_t downstream_task = MSG_SRC(&msg->h);
    upstream_t *u;

    if (MSG_SIZE(&msg->h) != sizeof(message_connect_t)) {
        log_error("%s: wrong format msg", __func__);
        return;
    }

    reply = (message_connect_rsp_t*)message_new_encap(task_upstream,
                                        MSG_CONNECT_RSP,
                                        sizeof(message_connect_rsp_t));
    if (!reply) {
        return;
    }
    reply->downstream_id = msg->downstream_id;
    reply->upstream_id = 0;

    int fd = -1;
    if (msg->type_addr.atype == ATYPE_IP) {
        int rtn;
        addr = &msg->type_addr.addr.sock_addr;
        fd = socket(addr->ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        int opt = 1;
        setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        rtn = connect(fd, (struct sockaddr*)addr,
                    addr->ss_family == AF_INET ? sizeof(struct sockaddr):
                                                 sizeof(struct sockaddr_in6));
        if (rtn ==-1 && errno != EINPROGRESS) {
            /* not able to connect */
            close(fd);
            goto connect_end;
        }
    } else if (msg->type_addr.atype != ATYPE_DOMAIN) {
        goto connect_end;
    }

    stream_t *s = stream_new(ctx->loop);
    if (!s) {
        goto connect_end;
    }
    upstream_extra_t *extra = msg_ev_ctx_get_extradata(ctx);
    list_add_tail(&s->node, &extra->stream_list);
    u = STREAM_PROTO_DATA(s);
    reply->upstream_id = (uint64_t)s;
    u->downstream_id = msg->downstream_id;
    u->downstream_task = downstream_task;

    if (msg->type_addr.atype == ATYPE_DOMAIN) {
        resolve_domain_async(u, &msg->type_addr.addr.domain_addr);
    } else if (fd != -1) {
        stream_attach(s, fd);
    }

connect_end:
    message_send(&reply->h, downstream_task);
}

static void
upstream_disconnect(message_disconnect_t *msg, msg_ev_ctx_t *ctx)
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
    upstream_t *u = (upstream_t *)STREAM_PROTO_DATA(s);
    if (u->magic != UP_MAGIC) {
        return;
    }
    if (u->downstream_id == msg->downstream_id) {
        u->downstream_id = 0;
        stream_free(s);
    }
}

static inline void
upstream_data(message_data_t *msg, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    if (MSG_SIZE(&msg->h) != sizeof(message_data_t)) {
        log_error("%s: wrong format msg", __func__);
        return;
    }
    int success = 0;
    netbuf_t *nb = msg->nb;
    stream_t *s = (stream_t *)msg->upstream_id;
    if (VALID_STREAM(s)) {
        upstream_t *u = (upstream_t*)STREAM_PROTO_DATA(s);
        if ((u->magic == UP_MAGIC) &&
            (u->downstream_id == msg->downstream_id)) {
            stream_send(s, nb);
            success = 1;
        }
    }
    if (!success) {
        packet_drop++;
        netbuf_free(nb);
    }
}

static void
upstream_recv_bp(message_backpressure_t* msg)
{
    stream_t *s = (stream_t *)msg->upstream_id;
    if (VALID_STREAM(s)) {
        upstream_t *u = (upstream_t*)STREAM_PROTO_DATA(s);
        if ((u->magic == UP_MAGIC) &&
            (u->downstream_id == msg->downstream_id)) {
            stream_rcv_ctrl(s, (msg->state == backpressure_on));
        }
    }
}

static void
msg_handler(message_queue_t *que, message_header_t *header, void *arg)
{
    UNUSED(que);

    int notfree = 0;
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t *)arg;

    switch (MSG_TYPE(header)) {
        case MSG_DATA:
            upstream_data((message_data_t*)header, ctx);
            break;
        case MSG_CONNECT:
            upstream_connect((message_connect_t*)header, ctx);
            break;
        case MSG_DISCONNECT:
            upstream_disconnect((message_disconnect_t*)header, ctx);
            break;
        case MSG_BACKPRESSURE:
            upstream_recv_bp((message_backpressure_t*)header);
            break;
        case MSG_HEARTBEAT_REQ :
            notfree = 1;
            send_heartbeat_rsp((message_heartbeat_t*)header, ctx->name);
            break;
        case MSG_SYS_INIT:
            upstream_init(ctx);
            notfree = 1;
            send_init_rsp(header, ctx->name);
            break;
        case MSG_SYS_START :
            upstream_start(ctx);
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

static inline
int upstream_send_data(upstream_t *u,
                       stream_t *s,
                       netbuf_t *nb)
{
    message_data_t *m;
    m = (message_data_t*)message_new_encap(task_upstream, MSG_DATA,
                                           sizeof(message_data_t));
    if (m) {
        m->downstream_id = u->downstream_id;
        m->upstream_id = (uint64_t)s;
        m->nb = nb;
        message_send(&m->h, u->downstream_task);
        return 0;
    }
    return -1;
}

static int upstream_input(stream_t *s, netbuf_t **nb)
{
    //dump_buffer((uint8_t*)NETBUF_START(*nb), (*nb)->len);
    upstream_t *u = (upstream_t*)STREAM_PROTO_DATA(s);
    if (u->downstream_id) {
        upstream_send_data(u, s, *nb);
    } else {
        packet_drop++;
        netbuf_free(*nb);
    }
    *nb = NULL;
    return 0;
}

static void *upstream_new(stream_t *s)
{
    int size = sizeof(upstream_t);
    upstream_t *u = (upstream_t*)mempool_alloc(&size);
    u->downstream_id = 0;
    u->dns_req.ar_name = NULL;
    u->dns_req.ar_service = NULL;
    u->stream = s;
    u->obsolete = 0;
    u->magic = UP_MAGIC;
    return u;
}

static int upstream_free(stream_t *s, void *m)
{
    message_disconnect_t *msg;
    upstream_t *u = (upstream_t*)m;
    if (u->dns_req.ar_name) {
        /*
         * a dns query is ongoing.
         * mark the entry to be deleted when dns query is finished.
         */
        u->obsolete = 1;
        return -1;
    }
    if (u->downstream_id) {
        msg = (message_disconnect_t*)message_new_encap(task_upstream,
                            MSG_DISCONNECT, sizeof(message_disconnect_t));
        if (msg) {
            msg->downstream_id = u->downstream_id;
            msg->upstream_id = (uint64_t)s;
            message_send(&msg->h, u->downstream_task);
        }
        u->downstream_id = 0;
    }
    u->magic = 0;
    mempool_free(m);
    return 0;
}

static void upstream_bkpressure(stream_t *s, backpressure_state_t state)
{
    upstream_t *u = (upstream_t*)STREAM_PROTO_DATA(s);
    send_backpressure(task_upstream, u->downstream_task,
                      u->downstream_id, (uint64_t)s, state);
}

static proto_ctrl_t upstream_ctrl = {
    task_upstream,
    upstream_new,
    upstream_free,
    upstream_input,
    upstream_bkpressure
};

static void upstream_stats(void)
{
    upstream_t *u;
    stream_t *s;
    struct list_head *node;

    if (!upstream_extra) {
        return;
    }

    printf("Upstream loss: %d\n", packet_drop);

    list_for_each(node, &upstream_extra->stream_list) {
        s = (stream_t*)node;
        u = (upstream_t*)STREAM_PROTO_DATA(s);
        printf("fd=%d downstream_id=%lx, obsolete=%d/%d, dns=%s ionum=%d\n",
                s->fd, u->downstream_id, u->obsolete, s->obsolete,
                u->dns_req.ar_name == NULL ? "NULL" : u->dns_req.ar_name,
                s->io_num);
    }
}

static void *upstream_main(void *cfg)
{
    UNUSED(cfg);
    upstream_extra_t *extra;
    msg_ev_ctx_t *ctx;

    ctx = (msg_ev_ctx_t*)malloc(sizeof(msg_ev_ctx_t));
    assert(ctx);
    if (msg_ev_ctx_init(ctx, task_upstream, msg_handler) == -1) {
        exit(-1);
    }
    extra = (upstream_extra_t*)malloc(sizeof(upstream_extra_t));
    assert(extra);
    upstream_extra = extra;
    extra->common.proto_cb = &upstream_ctrl;
    extra->common.server = NULL;
    INIT_LIST_HEAD(&extra->stream_list);
    msg_ev_ctx_set_extradata(ctx, extra);

    register_stats_cb(upstream_stats);
    ev_run(ctx->loop, 0);
    return NULL;
}

INIT_ROUTINE(static void module_init(void))
{
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, DNS_SIGNO);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    register_task(server_mode, task_upstream, upstream_main);
}

