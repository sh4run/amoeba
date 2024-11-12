/**
 * mempool.c
 * A simple memory pool structure and management
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "amoeba.h"
#include "mempool.h"
#include "mem_pool.h"

#define BUF128_NUM   256
#define BUF320_NUM   256
#define BUF640_NUM   16
#define BUF6K_NUM    512
#define BUFMAX_NUM   8

#define BUF128_SIZE  128
#define BUF320_SIZE  320
#define BUF640_SIZE  640
#define BUF6K_SIZE  (MAX_BUFFER_FACTOR*1024)
#define BUFMAX_SIZE  (MAX_BUFFER_FACTOR*2048)

typedef struct {
    FixedMemPool  *pool;
    uint32_t      used_num;
    uint32_t      used_max;
    uint32_t      max;
} netbuf_pool_t;

typedef struct {
    netbuf_pool_t *netpool;
    uint32_t       pad;
    uint32_t       magic;
} netbuf_header_t;

#define NETBUF_MAGIC  0xdeaddeed

static netbuf_pool_t netbuf_pool_128;
static netbuf_pool_t netbuf_pool_320;
static netbuf_pool_t netbuf_pool_640;
static netbuf_pool_t netbuf_pool_6K;
static netbuf_pool_t netbuf_pool_max;

static uint32_t outbound_used;
static uint32_t alloc_fail;

void mempool_output_stats(void)
{
    printf("netbuf pool stats:  used      max\n");
    printf("        pool-128 : %5d   %6d\n",  netbuf_pool_128.used_num,
                                        netbuf_pool_128.used_max);
    printf("        pool-320 : %5d   %6d\n",  netbuf_pool_320.used_num,
                                        netbuf_pool_320.used_max);
    printf("        pool-640 : %5d   %6d\n",  netbuf_pool_640.used_num,
                                        netbuf_pool_640.used_max);
    printf("        pool-6K  : %5d   %6d\n",  netbuf_pool_6K.used_num,
                                        netbuf_pool_6K.used_max);
    printf("        pool-MAX : %5d   %6d\n",  netbuf_pool_max.used_num,
                                        netbuf_pool_max.used_max);
    printf("        outbound : %5d\n",   outbound_used);
    printf("        failure  : %5d\n",   alloc_fail);
}

int mempool_init(uint32_t memory_cap)
{
    memset(&netbuf_pool_128, 0, sizeof(netbuf_pool_t));
    memset(&netbuf_pool_320, 0, sizeof(netbuf_pool_t));
    memset(&netbuf_pool_640, 0, sizeof(netbuf_pool_t));
    memset(&netbuf_pool_6K, 0, sizeof(netbuf_pool_t));
    memset(&netbuf_pool_max, 0, sizeof(netbuf_pool_t));

    if (pool_fixed_init(&netbuf_pool_128.pool, BUF128_SIZE, BUF128_NUM)
                                            != MEM_POOL_ERR_OK) {
        goto init_err;
    }
    if (pool_fixed_init(&netbuf_pool_320.pool, BUF320_SIZE, BUF320_NUM)
                                            != MEM_POOL_ERR_OK) {
        goto init_err;
    }
    if (pool_fixed_init(&netbuf_pool_640.pool, BUF640_SIZE, BUF640_NUM)
                                            != MEM_POOL_ERR_OK) {
        goto init_err;
    }
    if (pool_fixed_init(&netbuf_pool_6K.pool, BUF6K_SIZE, BUF6K_NUM)
                                            != MEM_POOL_ERR_OK) {
        goto init_err;
    }
    if (pool_fixed_init(&netbuf_pool_max.pool, BUFMAX_SIZE, BUFMAX_NUM)
                                            != MEM_POOL_ERR_OK) {
        goto init_err;
    }
    netbuf_pool_128.max = BUF128_NUM * memory_cap - 1;
    netbuf_pool_320.max = BUF320_NUM * memory_cap - 1;
    netbuf_pool_640.max = BUF640_NUM * memory_cap - 1;
    netbuf_pool_6K.max = BUF6K_NUM * memory_cap - 1;
    netbuf_pool_max.max = BUFMAX_NUM * memory_cap - 1;
    return 0;

init_err: 
    return -1;
}

void *mempool_alloc(int *size)
{
    netbuf_pool_t *p;
    netbuf_header_t *m;
    int buflen;

    int n = *size + sizeof(netbuf_header_t);
    if (n < BUF6K_SIZE) {
        if (n < BUF640_SIZE) {
            if (n < BUF128_SIZE) {
                p = &netbuf_pool_128;
                buflen = BUF128_SIZE;
            } else {
                if (n < BUF320_SIZE) {
                    p = &netbuf_pool_320;
                    buflen = BUF320_SIZE;
                } else {
                    p = &netbuf_pool_640;
                    buflen = BUF640_SIZE;
                }
            }
        } else {
            p = &netbuf_pool_6K;
            buflen = BUF6K_SIZE;
        }
    } else if (n < BUFMAX_SIZE) {
        p = &netbuf_pool_max;
        buflen = BUFMAX_SIZE;
    } else {
        __sync_add_and_fetch(&outbound_used, 1);
        m = (netbuf_header_t*)malloc(n);
        if (m) {
            m->netpool = NULL;
            m->pad = 0;
            m->magic = NETBUF_MAGIC;
            return (void*)(m+1);
        } else {
            __sync_add_and_fetch(&alloc_fail, 1);
            return NULL;
        }
    }

    uint64_t current, max;
    current = p->used_num;
    if (current > p->max) {
        __sync_add_and_fetch(&alloc_fail, 1);
        return NULL;
    }
    if (pool_fixed_alloc(p->pool, (void**)(&m)) == MEM_POOL_ERR_OK) {
        current = __sync_add_and_fetch(&p->used_num, 1);
        max = p->used_max;
        __sync_synchronize();
        if (max < current) {
            __sync_val_compare_and_swap(&p->used_max, max, current);
        }
        __sync_synchronize();
        m->netpool = p;
        m->pad = 0;
        m->magic = NETBUF_MAGIC;
        *size = buflen - sizeof(netbuf_header_t);
        return (void*)(m+1);
    } 
    __sync_add_and_fetch(&alloc_fail, 1);
    return NULL;
}

void mempool_free(void *mem)
{
    netbuf_header_t *m;
    m = (netbuf_header_t *)mem;
    m = m - 1;
    assert(m->magic == NETBUF_MAGIC);
    
    m->magic = 0;
    if (m->netpool) {
        __sync_sub_and_fetch(&m->netpool->used_num, 1);
        pool_fixed_free(m->netpool->pool, (void*)m);
    } else {
        __sync_sub_and_fetch(&outbound_used, 1);
        free(m);
    }
}
