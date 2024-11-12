/**
 * amoeba_main.c
 * System start and management.
 * 
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of message_queue nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <pthread.h>
#include <signal.h>

#include "amoeba.h"

typedef struct {
    pthread_t    tid;
    task_id_t    name;
    task_entry_t entry;
} task_t;

typedef struct {
    uint32_t   heartbeat_rcvd;
    uint32_t   heartbeat_sent;
} task_heartbeat_stats_t;

typedef struct {
    ev_signal               sigint_watcher;
    task_t                 *active_task_list;
    ev_timer                heartbeat_timer;
    uint64_t                heartbeat_seq;
    task_heartbeat_stats_t  tasks[task_id_end];
    int                     break_num;
    int                     init_index;
} ev_ctx0_extra_t;


#ifdef MESSAGE_DEBUG
uint64_t message_new_num;
uint64_t message_free_num;
uint64_t message_diff_max;
#endif

static task_t server_tasks[task_id_end];
static task_t client_tasks[task_id_end];

void register_task(jcfg_mode_t mode, task_id_t name, task_entry_t task_entry)
{
    static int server_task_num, client_task_num;
    int *task_num;
    task_t *t;
    if (mode == server_mode) {
        t = server_tasks;
        task_num = &server_task_num;
    } else {
        t = client_tasks;
        task_num = &client_task_num;
    }

    int i = (int)__sync_fetch_and_add(task_num, 1); 
    t[i].entry = task_entry;
    t[i].name = name;
}

static void msg_handler_heartbeat_rsp(message_heartbeat_t *msg,
                                      msg_ev_ctx_t *ctx0)
{
    ev_ctx0_extra_t *extra = (ev_ctx0_extra_t*)msg_ev_ctx_get_extradata(ctx0);
    if (msg->seq == extra->heartbeat_seq) {
        extra->tasks[MSG_SRC(&msg->h)].heartbeat_rcvd++;
    } else {
        log_info("late heartbeat received (%d)", MSG_SRC(&msg->h));
    }
}

static void msg_handler_sys_start(msg_ev_ctx_t *ctx0)
{
    int i;
    message_header_t *msg;
    ev_ctx0_extra_t *extra;

    extra = (ev_ctx0_extra_t*)msg_ev_ctx_get_extradata(ctx0);
    for (i = 0; extra->active_task_list[i].entry != NULL; i++) {
        msg = message_new_encap(task_main, MSG_SYS_START,
                          sizeof(message_header_t));
        if (msg) {
            message_send(msg, extra->active_task_list[i].name);
        }
    }
    log_info("system ready.");
    printf("Press CTRL-C to display system stats.\n");
    printf("Press two consecutive CTRL-C to exit.\n");
}

static void msg_handler_sys_init(msg_ev_ctx_t *ctx0)
{
    message_header_t *msg;
    ev_ctx0_extra_t *extra;

    extra = (ev_ctx0_extra_t*)msg_ev_ctx_get_extradata(ctx0);
    msg = message_new_encap(task_main, MSG_SYS_INIT,
                          sizeof(message_header_t));
    if (msg) {
        message_send(msg, extra->active_task_list[extra->init_index].name);
    }
}

static void msg_handler_init_complete(msg_ev_ctx_t *ctx0)
{
    message_header_t *msg;
    ev_ctx0_extra_t *extra;

    extra = (ev_ctx0_extra_t*)msg_ev_ctx_get_extradata(ctx0);
    if (!extra->active_task_list[++extra->init_index].entry) {
        /* 
         * all threads complete its init. 
         * send a SYS_START to myself.
         */
        msg = message_new_encap(task_main, MSG_SYS_START,
                          sizeof(message_header_t));
        if (msg) {
            message_send(msg, task_main);
        }
        return;
    }
    msg = message_new_encap(task_main, MSG_SYS_INIT,
                          sizeof(message_header_t));
    if (msg) {
        message_send(msg, extra->active_task_list[extra->init_index].name);
    }
}

static void
ctx0_msg_handler(message_queue_t *que, message_header_t *header, void *arg)
{
    UNUSED(que);

    msg_ev_ctx_t *ctx0 = (msg_ev_ctx_t *)arg;

    switch (MSG_TYPE(header)) {
        case MSG_HEARTBEAT_RSP :
            msg_handler_heartbeat_rsp((message_heartbeat_t*)header, ctx0);
            break;
        case MSG_SYS_INIT :
            msg_handler_sys_init(ctx0);
            break;
        case MSG_SYS_INIT_COMPLETE:
            msg_handler_init_complete(ctx0);
            break;
        case MSG_SYS_START :
            msg_handler_sys_start(ctx0);
            break;
        default :
            log_info("%s: unsupported msg(%d)", __func__, MSG_TYPE(header));
            break;
    }
    message_free_encap(header);
}

void
msgq_read_ev_common_cb(struct ev_loop *loop, ev_io *w, int revents)
{
    UNUSED(revents);
    UNUSED(w);

    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)ev_userdata(loop);

    assert(ctx && ctx->msg_handler);

    message_recv(ctx->msg_que, ctx->msg_handler, ctx);
}

static volatile int threads_ready;

int msg_ev_ctx_init(msg_ev_ctx_t *ctx, task_id_t name,
                    msg_handler_cb_func_t msg_handler)
{
    memset(ctx, 0, sizeof(msg_ev_ctx_t));
    ctx->name = name;
    ctx->msg_handler = msg_handler;
    ctx->msg_que = message_queue_new(name, 256, NULL, NULL);
    if (!ctx->msg_que) {
        log_error("%d: Fail to create message queue", name);
        return -1;
    }

    ctx->loop = ev_loop_new(EVFLAG_AUTO);
    ev_set_userdata(ctx->loop, (void*)ctx);

    /*
     * Create a io-watcher to monitor the eventfd of the
     * message queue.
     */
    ev_io_init(&ctx->msgq_watcher, msgq_read_ev_common_cb,
               message_queue_get_fd(ctx->msg_que), EV_READ);
    ev_io_start(ctx->loop, &ctx->msgq_watcher);
    __sync_add_and_fetch(&threads_ready, 1);
    return 0;
}

static void
heartbeat_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
    UNUSED(revents);
    message_heartbeat_t *msg;
    msg_ev_ctx_t *ctx0;
    ev_ctx0_extra_t *extra;
    int i;

    ctx0 = (msg_ev_ctx_t*)ev_userdata(loop);
    extra = (ev_ctx0_extra_t*)msg_ev_ctx_get_extradata(ctx0);
    
    /* check whether all responses are received. */
    int error_found = 0;
    for (i = 0; extra->active_task_list[i].entry != NULL; i++) {
        if (extra->tasks[extra->active_task_list[i].name].heartbeat_sent !=
            extra->tasks[extra->active_task_list[i].name].heartbeat_rcvd) {
            log_error("missing heart beat from (%d)",
                      extra->active_task_list[i].name);
            error_found++;
        }
    }
    assert(error_found == 0);

    /* send out a new round heartbeat */
    extra->heartbeat_seq++;
    for (i = 0; extra->active_task_list[i].entry != NULL; i++) {
        msg = (message_heartbeat_t *)message_new_encap(task_main, MSG_HEARTBEAT_REQ,
                                                 sizeof(message_heartbeat_t));
        if (msg) {
            msg->seq = extra->heartbeat_seq;
            message_send(&msg->h, extra->active_task_list[i].name);
            extra->tasks[extra->active_task_list[i].name].heartbeat_sent++;
        }
    }

    extra->break_num = 0;
    ev_timer_again(loop, w);
}

static void (*stats_cb_array[16])(void);
static int stats_cb_num;

void register_stats_cb(void (*stats_cb)(void))
{
    int i = (int)__sync_fetch_and_add(&stats_cb_num, 1);
    stats_cb_array[i] = stats_cb;
}

static void
sigint_cb (struct ev_loop *loop, ev_signal *w, int revents)
{
    UNUSED(revents);
    UNUSED(w);

    ev_ctx0_extra_t *extra;
    msg_ev_ctx_t *ctx0;

    ctx0 = (msg_ev_ctx_t*)ev_userdata(loop);
    extra = (ev_ctx0_extra_t*)msg_ev_ctx_get_extradata(ctx0);

    printf("\n");

    int i;
    for (i = 0; i < stats_cb_num; i++) {
        stats_cb_array[i]();
    }

#ifdef MESSAGE_DEBUG
    printf("Message stats: %ld, %ld, %ld\n", message_new_num,
                                             message_free_num,
                                             message_diff_max);
#endif

    mempool_output_stats();

    /*
     * exit after 3 consecutive crtl-c
     */
    if (++extra->break_num >= 2)
        ev_break (loop, EVBREAK_ALL);
}

static void print_usage(void)
{
    printf("\n");
    printf("Usage: \n");
    printf("amoeba -c <config-file>\n");
    printf("   config-file: JSON config file with path.\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    jcfg_system_t *sys_cfg = NULL;
    msg_ev_ctx_t  *ctx0;
    ev_ctx0_extra_t *extra;

    ctx0 = (msg_ev_ctx_t *)malloc(sizeof(msg_ev_ctx_t));
    assert(ctx0);
    memset(ctx0, 0, sizeof(msg_ev_ctx_t));

    extra = (ev_ctx0_extra_t *)malloc(sizeof(ev_ctx0_extra_t));
    assert(extra);
    memset(extra, 0, sizeof(ev_ctx0_extra_t));
    msg_ev_ctx_set_extradata(ctx0, (void*)extra);

    if (argc != 3) {
        goto error_exit;
    }
    if (strncmp(argv[1], "-c", 2)) {
       goto error_exit;
    }

    /* parse config */
    sys_cfg = jcfg_parse_config(argv[2]);
    if (!sys_cfg) {
        goto error_exit;
    }

    if (mempool_init(sys_cfg->memory_cap) == -1) {
        printf("Not enough memory.\n");
        return -1;
    }

    message_queue_init(task_id_end, MESSAGE_MAX);

    ctx0->name = task_main;
    ctx0->msg_handler = ctx0_msg_handler;
    ctx0->msg_que = message_queue_new(ctx0->name, 256, NULL, NULL);
    if (!ctx0->msg_que) {
        log_error("%d: Fail to create message queue", ctx0->name);
        return -1;
    }

    ctx0->loop = ev_default_loop(0);
    ev_set_userdata(ctx0->loop, (void*)ctx0);

    ev_io_init(&ctx0->msgq_watcher, msgq_read_ev_common_cb,
               message_queue_get_fd(ctx0->msg_que), EV_READ);
    ev_io_start(ctx0->loop, &ctx0->msgq_watcher);

    /* start a heartbeat monitor timer */
    ev_init(&extra->heartbeat_timer, heartbeat_timeout_cb);
    extra->heartbeat_timer.repeat = 5;
    ev_timer_again(ctx0->loop, &extra->heartbeat_timer);

    switch (sys_cfg->mode) {
        case server_mode:
            extra->active_task_list = server_tasks;
            break;
        case client_mode:
            extra->active_task_list = client_tasks;
            break;
        default:
            goto error_exit;
            break;
    }

    int i = 0;
    while (extra->active_task_list[i].entry != NULL) {
        pthread_create(&extra->active_task_list[i].tid, NULL,
                       extra->active_task_list[i].entry, (void*)sys_cfg);
        i++;
    }

    /* waiting for all threads to be ready */
    time_t now = time(NULL);
    while (threads_ready != i) {
        sched_yield();
        if (time(NULL) - now > 1) {
            break;
        }
    }
    if (threads_ready != i) {
        log_error("Not all threads started.");
        exit(-1);
    }

    ev_signal_init(&extra->sigint_watcher, sigint_cb, SIGINT);
    ev_signal_start(ctx0->loop, &extra->sigint_watcher);

    /* send a INIT msg to myself */
    message_header_t *m;
    m = message_new_encap(task_main, MSG_SYS_INIT, sizeof(message_header_t));
    assert(m);
    message_send(m, task_main);

    ev_run(ctx0->loop, 0);

    return 0;

error_exit:
    if (sys_cfg) {
        jcfg_free_config(sys_cfg);
    }
    print_usage();
    return -1;
}


