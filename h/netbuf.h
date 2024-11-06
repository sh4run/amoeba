/*
 * netbuf.h
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */
#ifndef __NETBUF_H__
#define __NETBUF_H__

#include "mempool.h"
#include "queue.h"

typedef struct {
    queue_elem_t  elem;
    int           offset;
    int           len;
    int           buf_len;
    char          buf[0];
} netbuf_t;

#define NETBUF_START(nb)   (&((nb)->buf[(nb)->offset]))
#define NETBUF_FREEROOM(nb)  ((nb)->buf_len - (nb)->offset - (nb)->len)

#define dump_nb(nb)   dump_buffer((uint8_t*)NETBUF_START((nb)), (nb)->len);

static inline
netbuf_t *netbuf_alloc(int len)
{
    netbuf_t *nb;
    int l = len;
    l += sizeof(netbuf_t);
    nb = (netbuf_t *)mempool_alloc(&l);
    if (nb) {
        nb->offset = nb->len = 0;
        nb->elem.next = NULL;
        nb->buf_len = l - sizeof(netbuf_t);
    }
    return nb;
}

static inline 
void netbuf_free(netbuf_t *netbuf)
{
    assert((uint32_t)netbuf->offset != 0xdeaddead);
    netbuf->offset = netbuf->len = 0xdeaddead;
    netbuf->elem.next = (void*)(-1);
    mempool_free((void*)netbuf);
}

static inline 
netbuf_t *netbuf_join(netbuf_t *one, netbuf_t *two)
{
    netbuf_t *b;
    if (NETBUF_FREEROOM(one) > two->len) {
        memcpy(NETBUF_START(one) + one->len, NETBUF_START(two), two->len);
        one->len += two->len;
        netbuf_free(two);
        return one;
    }
    if (one->len < two->offset) {
        memcpy(NETBUF_START(two) - one->len, NETBUF_START(one), one->len);
        two->offset -= one->len;
        two->len += one->len;
        netbuf_free(one);
        return two;
    }
    b = netbuf_alloc(one->len + two->len);
    if (b) {
        memcpy(NETBUF_START(b), NETBUF_START(one), one->len);
        b->len = one->len;
        memcpy(NETBUF_START(b) + b->len, NETBUF_START(two), two->len);
        b->len += two->len;
        netbuf_free(one);
        netbuf_free(two);
        return b;
    }
    return NULL;
}

#endif
