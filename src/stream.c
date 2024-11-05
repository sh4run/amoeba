/**
 * stream.c
 * An encapsulation of tcp streams based on libev.
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 *
 */
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>
#include <signal.h>

#include "amoeba.h"
#include "utils.h"
#include "mempool.h"

#define  DATA_OFFSET    256
static int stream_timeout_interval;

static int total_streams;
static int idle_cleaned;
static uint32_t enqueue_num, dequeue_num;
//static uint32_t obsolete_free, send_num;

static void stream_stats(void)
{
    printf("Total streams %d, idle cleaned %d\n",
            total_streams, idle_cleaned);
    printf("enqueue %d, dequeue %d\n", enqueue_num, dequeue_num);
}

#define SKIP_SHIFT_THRESHOLD   (STREAM_BUF_LEN >> 1)
static void
stream_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    UNUSED(revents);
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)ev_userdata(loop);
    proto_common_extra_t *proto;

    proto = (proto_common_extra_t*)msg_ev_ctx_get_extradata(ctx);
    stream_t *s = STREAM_FROM_READIO(w);

    s->io_num++;
    ssize_t len;
    if (!s->input) {
        netbuf_t *netbuf;
        netbuf = netbuf_alloc(STREAM_BUF_LEN);
        if (!netbuf) {
            /* low memory. close and exit*/
            stream_free(s);
            return;
        }
        netbuf->offset = DATA_OFFSET;
        s->input = netbuf;
    }
    len = recv(s->fd, s->input->buf + s->input->offset + s->input->len,
               s->input->buf_len - s->input->len - s->input->offset, 0);
    if (len != -1) {
        if (len == 0) {
            /* remote close */
            stream_free(s);
        } else {
            int processed_bytes;
            s->input->len += len;
            while((processed_bytes =
                        proto->proto_cb->input_cb(s, &s->input))) {
                if (!s->input) {
                    /* netbuf is taken by cb. nothing to do */
                    return;
                }
                s->input->offset += processed_bytes;
                s->input->len -= processed_bytes;
                if (!s->input->len) {
                    s->input->offset = DATA_OFFSET;
                    return;
                }
            }
            if (!s->input) {
                /* netbuf is taken by cb. nothing to do */
                return;
            }
            if (s->input->buf_len - s->input->len - s->input->offset <
                                                   SKIP_SHIFT_THRESHOLD) {
                memcpy(s->input->buf, s->input->buf + s->input->offset,
                       s->input->len);
            }
        }
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            log_info("socket read error(%d)", errno);
            ev_io_stop(s->loop, &s->write_io);
            ev_io_stop(s->loop, &s->read_io);
            stream_free(s);
        }
    }
}

static void
stream_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    UNUSED(revents);

    stream_t *s = STREAM_FROM_WRITEIO(w);
    netbuf_t *nb;
    ssize_t size;
    int sent_bytes = 0;

    s->io_num++;
    if (is_empty(&s->output_q)) {
        ev_io_stop(loop, &s->write_io);
        if (s->obsolete) {
            s->obsolete = 0;
            stream_free(s);
        }
    } else {
        while ((nb = (netbuf_t*)queue_head(&s->output_q)) 
                && (sent_bytes < (STREAM_BUF_LEN>>1))) {
            size = send(s->fd, nb->buf + nb->offset, nb->len, 0);
            if (size != -1) {
                if (size < (ssize_t)nb->len) {
                    /* partially sent. */
                    nb->offset += (int)size;
                    nb->len -= (int)size;
                    break;
                } else {
                    /* all sent. */
                    dequeue(&s->output_q);
                    netbuf_free(nb);
                    __sync_add_and_fetch(&dequeue_num, 1);
                }
                sent_bytes += (int)size;
            } else {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    log_info("socket write error(%d)\n", errno);
                    /* socket error */
                    ev_io_stop(s->loop, &s->write_io);
                    stream_free(s);
                }
                break;
            }
        }
    }
}

void stream_send(stream_t *s, netbuf_t *nb)
{
    //__sync_add_and_fetch(&send_num, 1);
    if (s->obsolete) {
        /* no more transmit if it is pending for removal */
        //__sync_add_and_fetch(&obsolete_free, 1);
        netbuf_free(nb);
        return;
    }

    if (is_empty(&s->output_q)) {
        enqueue(&s->output_q, &nb->elem);
        __sync_add_and_fetch(&enqueue_num, 1);
        if (s->fd != -1) {
            /* socket already attached */
            stream_write_cb(s->loop, &s->write_io, 0);
            if (!is_empty(&s->output_q)) {
                ev_io_start(s->loop, &s->write_io);
            }
        }
        return;
    }
    netbuf_t *tail = (netbuf_t*)queue_tail(&s->output_q);
    if (tail->buf_len - tail->offset - tail->len > nb->len) {
        /* 
         * if there is enough room, copy the new data to
         * the tail netbuf. This is to save one system call(send)
         * A system call is more expensive than a memcpy at
         * at user space.
         */
        memcpy(tail->buf + tail->offset + tail->len, 
               nb->buf + nb->offset, nb->len);
        tail->len += nb->len;
        netbuf_free(nb);
    } else {
        enqueue(&s->output_q, &nb->elem);
        __sync_add_and_fetch(&enqueue_num, 1);
    }
}

static void
stream_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    UNUSED(loop);
    UNUSED(revents);

    stream_t *s;
    s = (stream_t*)STREAM_FROM_IDLETIMER(w);
    if (!s->io_num) {
        if (stream_free(s) == 0) {
            __sync_add_and_fetch(&idle_cleaned, 1);
        }
    } else {
        s->io_num = 0;
    }
}

static void
stream_del_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    UNUSED(loop);
    UNUSED(revents);

    stream_t *s;
    s = (stream_t*)STREAM_FROM_IDLETIMER(w);
    if (s->magic == STREAM_PENDING_DEL) {
        /* delete timeout*/
        s->magic = 0;
        mempool_free(s);
        __sync_sub_and_fetch(&total_streams, 1);
    }
}

static void
stream_delete(stream_t *s)
{
    /* wait a short time before acutal delete */
    s->magic = STREAM_PENDING_DEL;
    ev_timer_init(&s->idle_timer, stream_del_timeout_cb, 1, 0);
    ev_timer_start(s->loop, &s->idle_timer);    
}

int stream_free(stream_t *s)
{
    if (s->fd != -1) {
        /* make sure fd is attached */
        if (ev_is_active(&s->write_io)) {
            /*
             * something ongoing. Mark it to be deleted after
             * the write is done.
             * If it has already been marked, deleted anyway.
             */
            if (!s->obsolete) {
                s->obsolete = 1;
                return -1;
            }
        }

        ev_io_stop(s->loop, &s->write_io);
        ev_io_stop(s->loop, &s->read_io);
        ev_timer_stop(s->loop, &s->idle_timer);
    }

    if (s->proto_data) {
        msg_ev_ctx_t *ctx;
        proto_common_extra_t *proto;
        ctx = (msg_ev_ctx_t*)ev_userdata(s->loop);
        proto = (proto_common_extra_t*)msg_ev_ctx_get_extradata(ctx);
        if (proto->proto_cb->free_cb(s, s->proto_data) != 0) {
            /* something is ongoing */
            return -1;
        }
    }

    s->proto_data = NULL;

    if (s->fd != -1) {
        close(s->fd);
    }
    if (s->input) {
        netbuf_free(s->input);
        s->input = NULL;
    }

    netbuf_t *nb;
    while ((nb = (netbuf_t*)dequeue(&s->output_q))) {
        netbuf_free(nb);
        __sync_add_and_fetch(&dequeue_num, 1);
    }
    if (s->node.prev || s->node.next) {
        list_del_init(&s->node);
    }
    s->fd = -1;
    stream_delete(s);
    return 0;
}

stream_t *stream_new(struct ev_loop *loop)
{
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)ev_userdata(loop);
    proto_common_extra_t *proto;

    proto = (proto_common_extra_t*)msg_ev_ctx_get_extradata(ctx);

    int size = sizeof(stream_t);
    stream_t *s = (stream_t*)mempool_alloc(&size);
    if (!s) {
        return NULL;
    }
    s->magic = STREAM_MAGIC;
    s->input = NULL;
    s->fd = -1;
    s->loop = loop;
    s->obsolete = 0;
    s->node.prev = s->node.next = NULL;
    s->io_num = 0;
    init_queue(&s->output_q);

    s->proto_data = proto->proto_cb->new_cb(s);
    if (!s->proto_data) {
        mempool_free(s);
        return NULL;
    }

    __sync_add_and_fetch(&total_streams, 1);
    return s;
}

void stream_attach(stream_t *s, int fd)
{
    s->fd = fd;
    ev_io_init(&s->write_io, stream_write_cb, fd, EV_WRITE);
    ev_io_init(&s->read_io, stream_read_cb, fd, EV_READ);
    ev_io_start(s->loop, &s->read_io);
    if (!is_empty(&s->output_q)) {
        ev_io_start(s->loop, &s->write_io);
    }

    ev_timer_init(&s->idle_timer, stream_timeout_cb,
                  stream_timeout_interval, stream_timeout_interval);
    ev_timer_start(s->loop, &s->idle_timer);
}

INIT_ROUTINE(static void stream_init_env(void))
{
    register_stats_cb(stream_stats);

    if (!stream_timeout_interval) {
        stream_timeout_interval = (time(NULL) % 7) + 4;
    }
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
}