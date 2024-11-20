/*
 * message.h
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */

#ifndef __MESSAGE_H__
#define __MESSAGE_H__

//#define MESSAGE_DEBUG

typedef enum {
    task_null = -1,
    task_main,
    task_transport,
    task_socks5,
    task_upstream,
    task_amoeba,
    task_id_end
} task_id_t;

#define MESSAGE_MAX     256

#define MESSAGE_TYPE_BASE(task) ((task) << 8)

typedef enum {
    MSG_HEARTBEAT_REQ = MESSAGE_TYPE_BASE(task_main),
    MSG_HEARTBEAT_RSP,
    MSG_SYS_INIT,
    MSG_SYS_INIT_COMPLETE,
    MSG_SYS_START,
    MSG_BACKPRESSURE
} message_type_main_t;

typedef enum {
    MSG_CONNECT = MESSAGE_TYPE_BASE(task_upstream),
    MSG_CONNECT_RSP,
    MSG_DATA,
    MSG_DISCONNECT
} message_type_upstream_t;

typedef enum {
    MSG_ASSO_REQ = MESSAGE_TYPE_BASE(task_transport),
    MSG_ASSO_RSP,
    MSG_ENCRYPT_REQ,
    MSG_ENCRYPT_RSP,
    MSG_DECRYPT_REQ,
    MSG_DECRYPT_RSP,
    MSG_CLOSE_REQ,
    MSG_CLOSE_RSP,
    MSG_CRYPTO_ERROR,
    MSG_CRYPTO_UPDATE,
    MSG_CRYPTO_REPLAY
} message_transport_t;

typedef struct {
    message_header_t    h;
    uint64_t            crypto_id;
    uint64_t            transport_id;
    uint8_t             rx_ex_bytes;
} message_crypto_notify_t;

typedef enum {
    backpressure_on = 1,
    backpressure_off
} backpressure_state_t;

typedef struct {
    message_header_t        h;
    uint64_t                downstream_id;
    uint64_t                upstream_id;
    backpressure_state_t    state;
} message_backpressure_t;

typedef struct {
    message_header_t    h;
    char                remote_name[JCONF_MAX_STR];
} message_asso_req_t;

typedef struct {
    message_header_t    h;
    char                remote_name[JCONF_MAX_STR];
    uint64_t            remote_id;
} message_asso_rsp_t;

typedef struct {
    message_header_t    h;
    uint64_t            remote_id;
    uint64_t            crypto_id;
    uint64_t            transport_id;
    netbuf_t            *nb;
} message_crypto_req_t;

typedef struct {
    message_header_t    h;
    uint64_t            remote_id;
    uint64_t            crypto_id;
    uint64_t            transport_id;
    netbuf_t            *nb;
} message_crypto_rsp_t;

#define AMOEBA_MAX_DOMAIN   127

#define ATYPE_IP        1
#define ATYPE_DOMAIN    2

typedef struct {
    uint16_t port;
    char     name[AMOEBA_MAX_DOMAIN];
} domain_addr_t;

typedef struct {
    int8_t  atype;
    union {
        domain_addr_t           domain_addr;
        struct sockaddr_storage sock_addr;
    } addr;
} type_addr_t;

#define CONNECT_FLAG_UDP            0x00000001

typedef struct {
    message_header_t    h;
    uint64_t            downstream_id;
    uint32_t            flags;
    type_addr_t         type_addr;
} message_connect_t;

typedef struct {
    message_header_t  h;
    uint64_t downstream_id;
    uint64_t upstream_id;
} message_connect_rsp_t;

typedef struct {
    message_header_t  h;
    uint64_t  downstream_id;
    uint64_t  upstream_id;
    netbuf_t *nb;
} message_data_t;

typedef struct {
    message_header_t  h;
    uint64_t  downstream_id;
    uint64_t  upstream_id;
} message_disconnect_t;

typedef struct {
    message_header_t  h;
    uint64_t          seq;
} message_heartbeat_t;


#ifdef MESSAGE_DEBUG
extern uint64_t message_new_num;
extern uint64_t message_free_num;
extern uint64_t message_diff_max;

static inline
message_header_t *message_new_encap(int src_id, int message_type, int length)
{
    uint64_t alloc, diff;
    alloc = __sync_add_and_fetch(&message_new_num, 1);
    diff = alloc - message_free_num;
    uint64_t old_max = message_diff_max;
    __sync_synchronize();
    if (old_max < diff) {
        __sync_val_compare_and_swap(&message_diff_max, old_max, diff);
    }
    __sync_synchronize();
    return message_new(src_id, message_type, length);
}

static inline
void message_free_encap(message_header_t *message)
{
    __sync_add_and_fetch(&message_free_num, 1);
    message_free(message);
}

#else

#define message_new_encap    message_new
#define message_free_encap   message_free

#endif

static inline void
send_heartbeat_rsp(message_heartbeat_t *m, task_id_t name)
{
    task_id_t target = MSG_SRC(&m->h);
    MSG_TYPE(&m->h) = MSG_HEARTBEAT_RSP;
    MSG_SRC(&m->h) = name;
    message_send(&m->h, target);
}

static inline void
send_init_rsp(message_header_t *h, task_id_t name)
{
    task_id_t target = MSG_SRC(h);
    MSG_TYPE(h) = MSG_SYS_INIT_COMPLETE;
    MSG_SRC(h) = name;
    message_send(h, target);
}

static inline void
send_backpressure(task_id_t src,
                  task_id_t dst,
                  uint64_t  downstream_id,
                  uint64_t  upstream_id,
                  backpressure_state_t state)
{
    message_backpressure_t *m;
    m = (message_backpressure_t*)message_new_encap(src, MSG_BACKPRESSURE,
                                        sizeof(message_backpressure_t));
    if (m) {
        m->downstream_id = downstream_id;
        m->upstream_id = upstream_id;
        m->state = state;
        message_send(&m->h, dst);
    }
}

#endif
