/**
 * amoeba.c
 *
 * Amoeba transport protocol.
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 *
 */
#include "amoeba.h"
#include "message.h"

#include <mbedtls/pk.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>

#include <sys/random.h>
#include <sys/time.h>

#include "amoeba_protocol.h"

#define RANDOM_DATA_SIZE 80000

static uint8_t _rand_data[RANDOM_DATA_SIZE];
static int _rand_data_idx = -1;

static void init_random_data(void)
{
    int ret;
    ret = getrandom(_rand_data, RANDOM_DATA_SIZE, 0);
    if (ret != RANDOM_DATA_SIZE) {
        exit(-1);
    }

    _rand_data_idx = 0;
}

static void update_random_data(void)
{
    static int update_idx = 0;

    int ret = getrandom(_rand_data + update_idx, 256, 0);
    update_idx += ret;
    if (update_idx == RANDOM_DATA_SIZE) {
        update_idx = 0;
    } else if (update_idx > RANDOM_DATA_SIZE - 256) {
        update_idx = RANDOM_DATA_SIZE - 256;
    }
}

static uint8_t *get_random_data(int len)
{
    uint8_t *data;

    if (_rand_data_idx + len >= RANDOM_DATA_SIZE) {
        _rand_data_idx = RANDOM_DATA_SIZE - _rand_data_idx + 1;
    }
    data = &_rand_data[_rand_data_idx];
    _rand_data_idx += len;
    return data;
}

typedef struct {
    mbedtls_pk_context          key;
    mbedtls_ctr_drbg_context    ctr_drbg;
    mbedtls_entropy_context     entropy;
    int                         scramble_len;
    size_t                      encrypted_size;
} amoeba_pki_info_t;

typedef struct {
    queue_elem_t        elem;
    jcfg_remote_t       *config;
    char                *user_password;
    amoeba_pki_info_t   pki_info;
} serverinfo_t;

#define CS_MAGIC            0x7d7d5c5c

typedef struct {
    struct list_head    node;
    serverinfo_t        *server;
    uint64_t            transport_id;
    uint32_t            magic;
    mbedtls_cipher_context_t  cipher;
    mbedtls_cipher_context_t  decipher;
    uint8_t             iv[AMOEBA_IV_SIZE];
    rand_params_t       rands;
    netbuf_t            *leftover;
    int                 tail_bytes;
    uint32_t            traffic_idx;
    client_info_t       *client;
} crypto_stream_t;

typedef struct {
    queue_t                      server_q;
    struct list_head             crypto_stream_list;
    const mbedtls_cipher_info_t *amoeba_cipher_info;
    uint64_t                     device_id;
} amoeba_client_extra_t;

static uint32_t alloc_num, free_num;

static void amoeba_init_pki_info(amoeba_pki_info_t *pki,
                                 jcfg_amoeba_t *amoeba, 
                                 int public)
{
    int rtn;
    mbedtls_pk_init(&pki->key);
    mbedtls_ctr_drbg_init(&pki->ctr_drbg);
    mbedtls_entropy_init(&pki->entropy);

    pki->scramble_len = amoeba->scramble_len;
    if (public) {
        rtn = mbedtls_pk_parse_public_keyfile(&pki->key, amoeba->key);
    } else {
        rtn = mbedtls_pk_parse_keyfile(&pki->key, amoeba->key, "" );
    }
    if (rtn) {
        log_error("unable to read %s", amoeba->key);
        exit(-1);
    }

    char pers[32];
    int r = *(int*)get_random_data(sizeof(int));
    snprintf(pers, sizeof(pers), "%s%d", AMOEBA_CLIENT_PERS, r);
    mbedtls_ctr_drbg_seed(&pki->ctr_drbg,
                          mbedtls_entropy_func,
                          &pki->entropy,
                          (const unsigned char *)pers,
                          strlen(pers));

    size_t key_bitlen = mbedtls_pk_get_bitlen(&pki->key);
    pki->encrypted_size = (key_bitlen + 7) / 8;
}

static void crypto_stats(void)
{
    printf("crypto: alloc %d, free %d\n", alloc_num, free_num);
}

static void
crypto_init_cipher_info(const mbedtls_cipher_info_t **cipher_info)
{
    *cipher_info = mbedtls_cipher_info_from_type(AMOEBA_CIPHER_TYPE);
    assert(*cipher_info);
}

static void
crypto_key_from_password(uint8_t *key, char *password)
{
    int len = strlen(password);
    int i;
    for (i = 0; i < AMOEBA_KEY_SIZE; i++) {
        key[i] = i < len ? (uint8_t)password[i] : (uint8_t)password[len -i];
    }
}

static int
crypto_init_ciphers(mbedtls_cipher_context_t *encrypt,
                    mbedtls_cipher_context_t *decrypt,
                    const mbedtls_cipher_info_t *cipher_info,
                    char *password,
                    uint8_t *iv)
{
    uint8_t key[AMOEBA_KEY_SIZE];
    int rtn = -1;

    crypto_key_from_password(key, password);
    if (mbedtls_cipher_setup(encrypt, cipher_info)) {
        goto init_cipher_error;
    }
    if (mbedtls_cipher_setkey(encrypt, key,
                              AMOEBA_KEY_SIZE * 8, MBEDTLS_ENCRYPT)) {
        goto init_cipher_error;
    }
    if (mbedtls_cipher_set_iv(encrypt, iv, AMOEBA_IV_SIZE) != 0) {
        goto init_cipher_error;
    }
    if (mbedtls_cipher_reset(encrypt)) {
        goto init_cipher_error;
    }
    if (mbedtls_cipher_setup(decrypt, cipher_info)) {
        goto init_cipher_error;
    }
    if (mbedtls_cipher_setkey(decrypt, key,
                              AMOEBA_KEY_SIZE * 8, MBEDTLS_DECRYPT)) {
        goto init_cipher_error;
    }
    if (mbedtls_cipher_set_iv(decrypt, iv, AMOEBA_IV_SIZE) != 0) {
        goto init_cipher_error;
    }
    if (mbedtls_cipher_reset(decrypt)) {
        goto init_cipher_error;
    }
    rtn = 0;

init_cipher_error:
    return rtn;
}

/* encrypt/decrypt data */
static inline int
crypto_process_data(mbedtls_cipher_context_t *ctx,
                    uint8_t *input, int len,
                    uint8_t *out)
{
    int ret;
    size_t olen;

    ret = mbedtls_cipher_update(ctx, input, len, out, &olen);

    if (ret) {
        return -1;
    }
    return (int)olen;
}

static netbuf_t *
crypto_process_nb(mbedtls_cipher_context_t *ctx, netbuf_t *input)
{
    netbuf_t *nb;
    int ret;

    nb = netbuf_alloc(STREAM_BUF_LEN);
    if (!nb) {
        return NULL;
    }
    nb->offset = NETBUF_FREEROOM(nb) - input->len;
    ret = crypto_process_data(ctx, (uint8_t*)NETBUF_START(input),
                              input->len,
                              (uint8_t*)NETBUF_START(nb));

    if (ret == -1) {
        netbuf_free(nb);
        return NULL;
    }
    nb->len = ret;
    return nb;
}

static void
init_remote_rands(rand_params_t *rands)
{
    int ret = getrandom(rands, sizeof(rand_params_t), 0);
    if (ret != sizeof(rand_params_t)) {
        exit(1);
    }

    rands->pad_type += rands->pad_type == rands->data_type ? 1 : 0;
    rands->reply_scramble += rands->reply_scramble < 16 ? 16 : 0;

    if ((rands->traffic_pattern + 1) <= 1) {
        rands->traffic_pattern = 0x5ac2b7914d30e533;
    }
}

static void
crypto_notify(crypto_stream_t *cs, int type)
{
    message_crypto_notify_t *msg;

    msg = (message_crypto_notify_t *)message_new_encap(task_amoeba,
                                               type,
                                               sizeof(message_crypto_notify_t));
    if (msg) {
        msg->crypto_id = (uint64_t)cs;
        msg->transport_id = cs->transport_id;
        msg->rx_ex_bytes = cs->rands.reply_scramble;
        message_send(&msg->h, task_transport);
    }
}

static void
crypto_update(message_crypto_notify_t *m)
{
    crypto_stream_t *cs;
    cs = (crypto_stream_t *)m->crypto_id;
    assert(cs->magic == CS_MAGIC);
    crypto_notify(cs, MSG_CRYPTO_UPDATE);
}

static crypto_stream_t *
crypto_stream_new(char *password, const mbedtls_cipher_info_t *cipher_info)
{
    crypto_stream_t *cs;
    int size = sizeof(crypto_stream_t);

    cs = (crypto_stream_t*)mempool_alloc(&size);
    if (!cs) {
        log_error("out of memory!");
        return NULL;
    }
    alloc_num++;

    cs->server = NULL;
    cs->transport_id = 0;
    cs->magic = CS_MAGIC;
    cs->leftover = NULL;
    cs->traffic_idx = 0;
    cs->tail_bytes = 0;
    cs->client = NULL;

    if (!password) {
        /* server */
        memset(&cs->rands, 0, sizeof(rand_params_t));
        memset(&cs->cipher, 0, sizeof(mbedtls_cipher_context_t));
        memset(&cs->decipher, 0, sizeof(mbedtls_cipher_context_t));
        return cs;
    }

    /* client */
    init_remote_rands(&cs->rands);
    memcpy(cs->iv, get_random_data(AMOEBA_IV_SIZE), AMOEBA_IV_SIZE);
    int rtn = crypto_init_ciphers(&cs->cipher, &cs->decipher, cipher_info,
                                  password, cs->iv);
    if (!rtn) {
        return cs;
    }

    log_error("cipher init error");
    mempool_free(cs);
    free_num++;
    return NULL;
}

static void
crypto_stream_free(crypto_stream_t *cs)
{
    list_del_init(&cs->node);
    if (mbedtls_cipher_get_type(&cs->cipher) != MBEDTLS_CIPHER_NONE) {
        mbedtls_cipher_free(&cs->cipher);
        mbedtls_cipher_free(&cs->decipher);
    }
    if (cs->leftover) {
        netbuf_free(cs->leftover);
    }
    cs->magic = 0;
    mempool_free(cs);
    free_num++;
}

static void
send_crypto_close_rsp(uint64_t transport_id)
{
    message_crypto_notify_t *rsp;
    rsp = (message_crypto_notify_t*)message_new_encap(task_amoeba,
                                          MSG_CLOSE_RSP,
                                          sizeof(message_crypto_notify_t));
    if (rsp) {
        rsp->transport_id = transport_id;
        message_send(&rsp->h, task_transport);
    }
}

/*
 * Associate a remote server between crypto and transport.
 */
static void
amoeba_asso_req(message_asso_req_t *asso_req, msg_ev_ctx_t *ctx)
{
    amoeba_client_extra_t *extra;
    serverinfo_t *server;
    uint64_t  remote_id = 0;

    extra = msg_ev_ctx_get_extradata(ctx);
    foreach_queue(server, serverinfo_t *, &extra->server_q) {
        if (!strncmp(server->config->remote_name,
                     asso_req->remote_name, JCONF_MAX_STR)) {
            remote_id = (uint64_t)server;
            break;
        }
    }
    if (remote_id) {
        message_asso_rsp_t *rsp;
        rsp = (message_asso_rsp_t*)message_new_encap(task_amoeba,
                                              MSG_ASSO_RSP,
                                              sizeof(message_asso_rsp_t));
        if (rsp) {
            rsp->remote_id = remote_id;
            strncpy(rsp->remote_name, asso_req->remote_name, JCONF_MAX_STR);
            message_send(&rsp->h, MSG_SRC(&asso_req->h));
        }
    } else {
        log_error("unknow server %s", asso_req->remote_name);
    }
}

static void amoeba_client_data_return(message_transport_t type,
                                      netbuf_t *nb,
                                      crypto_stream_t *cs)
{
    message_crypto_rsp_t *rsp;
    rsp = (message_crypto_rsp_t*)message_new_encap(task_amoeba,
                                               type,
                                               sizeof(message_crypto_rsp_t));
    if (rsp) {
        rsp->remote_id = (uint64_t)cs->server;
        rsp->crypto_id = (uint64_t)cs;
        rsp->transport_id = cs->transport_id;
        rsp->nb = nb;
        message_send(&rsp->h, task_transport);
    } else {
        netbuf_free(nb);
    }
}

static void
amoeba_client_decrypt_req(message_crypto_req_t *req, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    crypto_stream_t *cs;
    netbuf_t *n;

    cs = (crypto_stream_t *)req->crypto_id;
    assert(cs->magic == CS_MAGIC);

    if (cs->rands.reply_scramble) {
        if (req->nb->len > cs->rands.reply_scramble) {
            req->nb->offset += cs->rands.reply_scramble;
            req->nb->len -= cs->rands.reply_scramble;
            cs->rands.reply_scramble = 0;
        } else {
            cs->rands.reply_scramble -= req->nb->len;
            netbuf_free(req->nb);
            return;
       }
    }
    n = crypto_process_nb(&cs->decipher, req->nb);
    netbuf_free(req->nb);
    if (n == NULL) {
        /* crypto error */
        crypto_notify(cs, MSG_CRYPTO_ERROR);
        return;
    }

    amoeba_client_data_return(MSG_DECRYPT_RSP, n, cs);
}

static void amoeba_sha256(uint8_t* input, int len, uint8_t *output)
{
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *md_info;
    int ret;

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return;
    }

    // Initialize the context
    mbedtls_md_init(&ctx);
    ret = mbedtls_md_setup(&ctx, md_info, 0); // 0 means no HMAC
    if (ret != 0) {
        goto sha256_exit;
    }

    ret = mbedtls_md_starts(&ctx);
    if (ret != 0) {
        goto sha256_exit;
    }

    ret = mbedtls_md_update(&ctx, input, len);
    if (ret != 0) {
        goto sha256_exit;
    }

    // Finish the hashing process and retrieve the hash
    mbedtls_md_finish(&ctx, output);

sha256_exit:
    // Free the message digest context
    mbedtls_md_free(&ctx);
}

static netbuf_t *amoeba_crypto_head_new(crypto_stream_t *cs, uint64_t devid)
{
    netbuf_t *nb;
    uint8_t buffer[128];
    amoeba_head_t *head = (amoeba_head_t*)buffer;
    char *user;
    uint8_t *scramble;
    int head_len;
    size_t olen;
    uint8_t hash[AMOEBA_HEAD_HASH_LEN];
    amoeba_pki_info_t *pki = &cs->server->pki_info;
    uint8_t tail_len;

    user = cs->server->config->user_name;
    head_len = sizeof(amoeba_head_t) + strlen(user);

    /* head scramble */
    scramble = get_random_data(pki->scramble_len+1);
    tail_len = scramble[pki->scramble_len];
    tail_len = (tail_len & 0x3f) + 1;

    nb = netbuf_alloc(STREAM_BUF_LEN);
    if (!nb) {
        return NULL;
    }
    memcpy(NETBUF_START(nb), scramble, pki->scramble_len);

    head->major_version = MAJOR_VER;
    head->minor_version = MINOR_VER;
    head->data_type = cs->rands.data_type;
    head->pad_type = cs->rands.pad_type;
    head->reply_scramble = cs->rands.reply_scramble;
    head->tail_len = tail_len;
    head->flags = 0;
    head->reserve = 0;
    head->device_id = devid;

    struct timeval secs;
    gettimeofday(&secs, NULL);
    head->epoch = secs.tv_sec;
    head->epoch <<= 20;
    head->epoch += secs.tv_usec;
    head->epoch = htonll(head->epoch);

    head->username_len = strlen(user);
    memcpy(head->username, user, head->username_len);
    memcpy(head->iv, cs->iv, AMOEBA_IV_SIZE);

    int l = strlen(cs->server->user_password);
    memcpy(head->hash, cs->server->user_password, l);
    memset(&head->hash[l], 0, AMOEBA_HEAD_HASH_LEN - l);

    amoeba_sha256((uint8_t*)head, head_len, hash);
    memcpy(head->hash, hash, AMOEBA_HEAD_HASH_LEN);

    mbedtls_pk_encrypt(&pki->key, buffer, head_len,
                       (uint8_t*)(NETBUF_START(nb) + pki->scramble_len), 
                       &olen, pki->encrypted_size,
                       mbedtls_ctr_drbg_random, &pki->ctr_drbg);

    nb->len = (int)olen + pki->scramble_len;

    /* tail scramble */
    scramble = get_random_data(tail_len);
    memcpy(NETBUF_START(nb) + nb->len, scramble, tail_len);
    nb->len += tail_len;

    return nb;
}

static void
amoeba_client_encrypt_req(message_crypto_req_t *req, msg_ev_ctx_t *ctx)
{
    crypto_stream_t *cs;
    serverinfo_t *server;
    amoeba_client_extra_t *extra;
    netbuf_t *n = NULL;

    extra = msg_ev_ctx_get_extradata(ctx);
    server = (serverinfo_t *)req->remote_id;
    cs = (crypto_stream_t *)req->crypto_id;
    if (!cs) {
        /*
         * Check the stream list to see if a req has been received
         * This might happen if consecutive data packets come in
         * before the first response is received.
         */
        int found = 0;
        list_for_each_entry(cs, &extra->crypto_stream_list, node) {
            if (cs->transport_id == req->transport_id) {
                found = 1;
                break;
            }
        }
        if (!found) {
            cs = crypto_stream_new(server->user_password,
                                   extra->amoeba_cipher_info);
            if (!cs) {
                log_error("out of memory!");
                goto cencrypt_error;
            }
            cs->server = server;
            cs->transport_id = req->transport_id;
            list_add(&cs->node, &extra->crypto_stream_list);
            crypto_notify(cs, MSG_CRYPTO_UPDATE);
            n = amoeba_crypto_head_new(cs, extra->device_id);
            if (!n) {
                goto cencrypt_error;
            }
        }
    }

    assert(cs->magic == CS_MAGIC);
    uint8_t *data = (uint8_t*)NETBUF_START(req->nb);
    int data_left = req->nb->len, ret;
    uint64_t bit;
    uint8_t tlv_len = 0;
    uint8_t *p, *output, *rand_len;
    uint32_t rand_len_i = 0;

    if (!n) {
        n = netbuf_alloc(STREAM_BUF_LEN);
        if (!n) {
            goto cencrypt_error;
        }
    }
    output = (uint8_t*)NETBUF_START(n);

    if (cs->tail_bytes) {
        /* add a half pad at the beginning */
        p = get_random_data(cs->tail_bytes);
        memcpy(&output[n->len], p, cs->tail_bytes);
        n->len += cs->tail_bytes;
        cs->tail_bytes = 0;
    } else {
        /* there is no half pad for the first packet */
    }

    rand_len = get_random_data(16);

    while (data_left) {
        tlv_len = rand_len[rand_len_i++ & 0xf];
        bit = 1;
        bit <<= (cs->traffic_idx++ & 0x3f);
        if (bit & cs->rands.traffic_pattern) {
            /* data */
            tlv_len += tlv_len < 64 ? 64 : 0;
            if (tlv_len > data_left) {
                tlv_len = data_left;
            }
            output[n->len++] = cs->rands.data_type;
            output[n->len++] = tlv_len;
            ret = crypto_process_data(&cs->cipher, data,
                                      tlv_len, (uint8_t*)&output[n->len]);
            if (ret == -1) {
                goto cencrypt_error;
            }

            data += tlv_len;
            data_left -= tlv_len;
            n->len += tlv_len;
        } else {
            /* scramble */
            tlv_len += tlv_len < 16 ? 16 : 0;
            output[n->len++] = cs->rands.pad_type;
            output[n->len++] = tlv_len;
            p = get_random_data(tlv_len);
            memcpy(&output[n->len], p, tlv_len);
            n->len += tlv_len;
        }
        if (NETBUF_FREEROOM(n) <= 0x200) {
            /* leave enough room to add a half pad */
            /*
             * TODO:
             *   there is no half pad protection in the middle.
             *   Does it matter?
             */
            amoeba_client_data_return(MSG_ENCRYPT_RSP, n, cs);
            n = netbuf_alloc(STREAM_BUF_LEN);
            if (!n) {
                goto cencrypt_error;
            }
            output = (uint8_t*)NETBUF_START(n);
        }
    }

    netbuf_free(req->nb);

    /*
     * add a half pad at the end.
     * the another half is added the head of the next
     * packet for protection.
     */
    tlv_len = rand_len[rand_len_i] & 0x7f;
    tlv_len += tlv_len < 16 ? 16 : 0;
    output[n->len++] = cs->rands.pad_type;
    output[n->len++] = tlv_len + tlv_len;
    p = get_random_data(tlv_len);
    memcpy(&output[n->len], p, tlv_len);
    n->len += tlv_len;
    cs->tail_bytes = tlv_len;

    amoeba_client_data_return(MSG_ENCRYPT_RSP, n, cs);

    return;

cencrypt_error:
    netbuf_free(req->nb);
    crypto_notify(cs, MSG_CRYPTO_ERROR);
    if (n) {
        netbuf_free(n);
    }
}

static void
amoeba_client_close_req(message_crypto_notify_t *req, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    crypto_stream_t *cs;
    uint64_t transport_id;

    cs = (crypto_stream_t *)req->crypto_id;
    if (cs->magic == CS_MAGIC) {
        transport_id = cs->transport_id;
        crypto_stream_free(cs);
        send_crypto_close_rsp(transport_id);
    }
}

static void
amoeba_client_msg_handler(message_queue_t *que,
                          message_header_t *header,
                          void *arg)
{
    UNUSED(que);
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t *)arg;
    int notfree = 0;

    switch (MSG_TYPE(header)) {
        case MSG_ENCRYPT_REQ:
            amoeba_client_encrypt_req((message_crypto_req_t *)header, ctx);
            break;
        case MSG_DECRYPT_REQ:
            amoeba_client_decrypt_req((message_crypto_req_t *)header, ctx);
            break;
        case MSG_CLOSE_REQ:
            amoeba_client_close_req((message_crypto_notify_t*)header, ctx);
            break;
        case MSG_CRYPTO_UPDATE:
            crypto_update((message_crypto_notify_t*)header);
            break;
        case MSG_HEARTBEAT_REQ:
            notfree = 1;
            send_heartbeat_rsp((message_heartbeat_t*)header, ctx->name);
            update_random_data();
            break;
        case MSG_ASSO_REQ:
            amoeba_asso_req((message_asso_req_t*)header, ctx);
            break;
        case MSG_SYS_INIT:
            notfree = 1;
            send_init_rsp(header, ctx->name);
            break;
        case MSG_SYS_START:
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

static void *amoeba_client(void *c)
{
    UNUSED(c);

    jcfg_system_t *cfg = (jcfg_system_t *)c;
    jcfg_client_t *client_cfg = &cfg->config.client_cfg;
    amoeba_client_extra_t *extra;
    jcfg_remote_t *remote_cfg;
    jcfg_amoeba_t *amoeba;
    serverinfo_t *server;

    init_random_data();

    extra = (amoeba_client_extra_t*)malloc(sizeof(amoeba_client_extra_t));
    assert(extra);
    init_queue(&extra->server_q);
    INIT_LIST_HEAD(&extra->crypto_stream_list);

    extra->device_id = client_cfg->device_id;

    jcfg_user_t *user;
    foreach_queue(remote_cfg, jcfg_remote_t *, &client_cfg->remote_que) {
        if (remote_cfg->proto == proto_amoeba) {
            user = (jcfg_user_t*)hashtable_search(cfg->user_cfg,
                                                  remote_cfg->user_name);
            if (!user) {
                log_error("unable to find user %s", remote_cfg->user_name);
                exit(-1);
            }
            server = malloc(sizeof(serverinfo_t));
            assert(server);
            server->config = remote_cfg;
            server->user_password = user->password;

            amoeba = &remote_cfg->amoeba;
            amoeba_init_pki_info(&server->pki_info, amoeba, 1);
            enqueue(&extra->server_q, &server->elem);
        }
    }

    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)malloc(sizeof(msg_ev_ctx_t));
    assert(ctx);
    if (msg_ev_ctx_init(ctx, task_amoeba,
                        amoeba_client_msg_handler) == -1) {
        exit(-1);
    }

    msg_ev_ctx_set_extradata(ctx, extra);
    crypto_init_cipher_info(&extra->amoeba_cipher_info);
    register_stats_cb(crypto_stats);
    ev_run(ctx->loop, 0);
    return NULL;
}

typedef struct {
    jcfg_system_t               *syscfg;
    const mbedtls_cipher_info_t *amoeba_cipher_info;
    amoeba_pki_info_t            pki_info;
    struct list_head             crypto_stream_list;
} amoeba_server_extra_t;

static void amoeba_server_data_return(message_transport_t type,
                                      netbuf_t *nb,
                                      crypto_stream_t *cs)
{
    message_crypto_rsp_t *rsp;
    rsp = (message_crypto_rsp_t*)message_new_encap(task_amoeba,
                                               type,
                                               sizeof(message_crypto_rsp_t));
    if (rsp) {
        rsp->remote_id = (uint64_t)cs->server;
        rsp->crypto_id = (uint64_t)cs;
        rsp->transport_id = cs->transport_id;
        rsp->nb = nb;
        message_send(&rsp->h, task_transport);
    } else {
        netbuf_free(nb);
    }
}

static void
amoeba_server_encrypt_req(message_crypto_req_t *req, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    crypto_stream_t *cs;
    netbuf_t *n;
    uint8_t *p;

    cs = (crypto_stream_t *)req->crypto_id;
    assert(cs->magic == CS_MAGIC);

    n = crypto_process_nb(&cs->cipher, req->nb);
    netbuf_free(req->nb);
    if (n == NULL) {
        /* crypto error */
        goto sencrypt_error;
    }
    if (cs->rands.reply_scramble) {
        p = get_random_data(cs->rands.reply_scramble);
        if (n->offset > cs->rands.reply_scramble) {
            n->offset -= cs->rands.reply_scramble;
            memcpy(NETBUF_START(n), p, cs->rands.reply_scramble);
            n->len += cs->rands.reply_scramble;
        } else {
            netbuf_t *ex;
            ex = netbuf_alloc(cs->rands.reply_scramble);
            if (ex) {
                memcpy(NETBUF_START(ex), p, cs->rands.reply_scramble);
                ex->len = cs->rands.reply_scramble;
                amoeba_server_data_return(MSG_ENCRYPT_RSP, ex, cs);
            } else {
                goto sencrypt_error;
            }
        }
        cs->rands.reply_scramble = 0;
    }

    amoeba_server_data_return(MSG_ENCRYPT_RSP, n, cs);
    return;

sencrypt_error:
    crypto_notify(cs, MSG_CRYPTO_ERROR);
    if (n) {
        netbuf_free(n);
    }
}

static int 
amoeba_decrypt_head(crypto_stream_t *cs,
                    netbuf_t *nb,
                    amoeba_server_extra_t *extra)
{
    size_t s;
    uint8_t *p;
    uint8_t buffer[128];
    size_t olen;
    client_info_t *client;

    s = extra->pki_info.encrypted_size + extra->pki_info.scramble_len;
    if (nb->len < (int)s) {
        return 0;
    }
    p = (uint8_t*)(NETBUF_START(nb) + extra->pki_info.scramble_len);
    int rtn = mbedtls_pk_decrypt(&extra->pki_info.key, p,
                                 extra->pki_info.encrypted_size,
                                 buffer, &olen, sizeof(buffer),
                                 mbedtls_ctr_drbg_random,
                                 &extra->pki_info.ctr_drbg);
    if (rtn) {
        /* decryption error */
        return -1;
    }

    amoeba_head_t *h;
    char username[32];
    h = (amoeba_head_t*)buffer;
    if (h->username_len > sizeof(username)) {
        log_error("wrong username length %d", h->username_len);
        return -1;
    }
    memcpy(username, h->username, h->username_len);
    username[h->username_len] = 0;

    jcfg_user_t *user;
    user = (jcfg_user_t*)hashtable_search(extra->syscfg->user_cfg,
                                          username);
    if (!user) {
        log_error("unable to find user %s", username);
        return -1;
    }

    /* validate hash */
    uint8_t hash_origin[AMOEBA_HEAD_HASH_LEN];
    uint8_t hash[AMOEBA_HEAD_HASH_LEN];
    memcpy(hash_origin, h->hash, AMOEBA_HEAD_HASH_LEN);
    int l = strlen(user->password);
    memcpy(h->hash, user->password, l);
    memset(&h->hash[l], 0, AMOEBA_HEAD_HASH_LEN - l);

    amoeba_sha256((uint8_t*)h,
                  sizeof(amoeba_head_t) + h->username_len, hash);
    if (memcmp(hash, hash_origin, AMOEBA_HEAD_HASH_LEN)) {
        /* hash doesn't match */
        log_error("wrong password for user %s", username);
        return -1;
    }

    h->device_id = ntohll(h->device_id);
    h->epoch     = ntohll(h->epoch); 

    /* check device queue for any existing client */
    int new_client = 1;
    foreach_queue(client, client_info_t *, &user->device_q) {
        if (client->device_id == h->device_id) {
            new_client = 0;
            break;
        }
    }
    if (new_client) {
        client = (client_info_t*)malloc(sizeof(client_info_t));
        if (!client) {
            log_error("Out of memory!");
            return -1;
        }
        client->device_id = h->device_id;
        client->last_epoch = EPOCH_MARGIN;
        client->last_server_epoch = 0;
        enqueue(&user->device_q, &client->elem);
    }

    /*
     * Different connections might be classified into different
     * flows or queues by routers in the path.
     * Earlier connection may arrive later due to the different
     * latency of differnt queues.
     */
    if ((client->last_epoch - EPOCH_MARGIN) >= h->epoch) {
        /* these are earlier than a reasonable margin */
        log_info("Obsolete timestamp from %s: last=%lx rcv=%lx diff=%ld",
                  username,
                  client->last_epoch, h->epoch,
                  client->last_epoch - h->epoch);
        return -1;
    }

    /* calculate local epoch */
    struct timeval secs;
    uint64_t epoch;
    gettimeofday(&secs, NULL);
    epoch = secs.tv_sec;
    epoch <<= 20;
    epoch += secs.tv_usec;

    /*
     * last_server_epoch keeps the server timestamp when last
     * connection is received. If server receives no connection in
     * IDLE_MARGIN, any new connection must have a new(greater)
     * EPOCH.
     */
    if (client->last_server_epoch + IDLE_MARGIN < epoch) {
        if (h->epoch <= client->last_epoch) {
            log_info("Obsolete timestamp after idle: %lx",
                     h->epoch);
            return -1;
        }
    }

    cs->client = client;
    client->last_server_epoch = epoch;
    client->last_epoch = h->epoch;
    cs->rands.data_type = h->data_type;
    cs->rands.pad_type = h->pad_type;
    cs->rands.reply_scramble = h->reply_scramble;
    cs->tail_bytes = h->tail_len;

    rtn = crypto_init_ciphers(&cs->cipher, &cs->decipher,
                              extra->amoeba_cipher_info,
                              user->password, h->iv);
    if (rtn) {
        return -1;
    }

    if (0) {
        log_info("New connection, device=%lx, epoch=%lx",
                h->device_id, h->epoch);
    }

    if (nb->len > (int)s + cs->tail_bytes) {
        s += cs->tail_bytes;
        cs->tail_bytes = 0;
    }
    return (int)s;
}

static int
amoeba_decrypt_data(crypto_stream_t *cs,
                    netbuf_t *nb,
                    amoeba_server_extra_t *extra)
{
    UNUSED(extra);
    int processed = 0;
    netbuf_t *output;

    if (cs->tail_bytes) {
        /* skip the tail pad after head */
        if (nb->len > cs->tail_bytes) {
            processed += cs->tail_bytes;
            cs->tail_bytes = 0;
            return processed;
        } else {
            return 0;
        }
    }

    uint8_t *tlv_head = (uint8_t*)NETBUF_START(nb);
    uint16_t tlv_len;
    int left = nb->len;
    int ret;

    output = netbuf_alloc(STREAM_BUF_LEN);
    if (!output) {
        return -1;
    }

    while (left > 2) {
        tlv_len = tlv_head[1];
        if (!tlv_len) {
            /* wrong format */
            log_error("wrong tlv length.");
            goto sdecrypt_error;
        }
        if (left < tlv_len + 2) {
            break;
        }
        if (tlv_head[0] == cs->rands.data_type) {
            ret = crypto_process_data(&cs->decipher, &tlv_head[2], tlv_len,
                              (uint8_t*)(NETBUF_START(output) + output->len));
            if (ret == -1) {
                goto sdecrypt_error;
            }
            output->len += tlv_len;
            tlv_len += 2;
            tlv_head += tlv_len;
            left -= tlv_len;
            processed += tlv_len;
        } else if (tlv_head[0] == cs->rands.pad_type) {
            tlv_len += 2;
            tlv_head += tlv_len;
            left -= tlv_len;
            processed += tlv_len;
        } else {
            log_error("wrong TLV type(%x)", tlv_head[0]);
            goto sdecrypt_error;
        }
    }

    amoeba_server_data_return(MSG_DECRYPT_RSP, output, cs);
    return processed;

sdecrypt_error:
    if (output) {
        netbuf_free(output);
    }
    return -1;
}

static int server_decrypt_input(crypto_stream_t *cs,
                                netbuf_t *nb,
                                amoeba_server_extra_t *extra)
{
    int ret;
    if (cs->rands.data_type || cs->rands.pad_type) {
        /* head decrypted. */
        ret = amoeba_decrypt_data(cs, nb, extra);
    } else {
        /* head not decryped yet */
        ret = amoeba_decrypt_head(cs, nb, extra);
    }
    return ret;
}

static void
amoeba_server_decrypt_req(message_crypto_req_t *req, msg_ev_ctx_t *ctx)
{
    crypto_stream_t *cs;
    amoeba_server_extra_t *extra;

    extra = msg_ev_ctx_get_extradata(ctx);
    cs = (crypto_stream_t *)req->crypto_id;
    if (!cs) {
        /*
         * Check the stream list to see if a req has been received
         * This might happen if consecutive data packets come in
         * before the first response is received.
         */
        int found = 0;
        list_for_each_entry(cs, &extra->crypto_stream_list, node) {
            if (cs->transport_id == req->transport_id) {
                found = 1;
                break;
            }
        }
        if (!found) {
            cs = crypto_stream_new(NULL, NULL);
            if (!cs) {
                log_error("out of memory!");
                netbuf_free(req->nb);
                return;
            }
            cs->server = NULL;
            cs->transport_id = req->transport_id;
            list_add(&cs->node, &extra->crypto_stream_list);
            crypto_notify(cs, MSG_CRYPTO_UPDATE);
        }
    }
    assert(cs->magic == CS_MAGIC);
    if (cs->leftover) {
        cs->leftover = netbuf_join(cs->leftover, req->nb);
        assert(cs->leftover);
    } else {
        cs->leftover = req->nb;
    }

    int len;
    while ((len = server_decrypt_input(cs, cs->leftover, extra))) {
        if (len == -1 || len > cs->leftover->len) {
            /* error in decryption */
            crypto_notify(cs, MSG_CRYPTO_ERROR);
            break;
        }
        cs->leftover->offset += len;
        cs->leftover->len -= len;
        if (!cs->leftover->len) {
            netbuf_free(cs->leftover);
            cs->leftover = NULL;
            break;
        }
    }
}

static void
amoeba_server_close_req(message_crypto_notify_t *req, msg_ev_ctx_t *ctx)
{
    UNUSED(ctx);
    crypto_stream_t *cs;
    uint64_t transport_id;

    cs = (crypto_stream_t *)req->crypto_id;
    if (cs->magic == CS_MAGIC) {
        transport_id = cs->transport_id;
        crypto_stream_free(cs);
        send_crypto_close_rsp(transport_id);
    }
}

static void
amoeba_server_msg_handler(message_queue_t *que,
                          message_header_t *header,
                          void *arg)
{
    UNUSED(que);
    msg_ev_ctx_t *ctx = (msg_ev_ctx_t *)arg;
    int notfree = 0;

    switch (MSG_TYPE(header)) {
        case MSG_ENCRYPT_REQ:
            amoeba_server_encrypt_req((message_crypto_req_t *)header, ctx);
            break;
        case MSG_DECRYPT_REQ:
            amoeba_server_decrypt_req((message_crypto_req_t *)header, ctx);
            break;
        case MSG_CLOSE_REQ:
            amoeba_server_close_req((message_crypto_notify_t*)header, ctx);
            break;
        case MSG_SYS_START :
            break;
        case MSG_CRYPTO_UPDATE:
            crypto_update((message_crypto_notify_t*)header);
            break;
        case MSG_HEARTBEAT_REQ :
            notfree = 1;
            send_heartbeat_rsp((message_heartbeat_t*)header, ctx->name);
            update_random_data();
            break;
        case MSG_SYS_INIT:
            notfree = 1;
            send_init_rsp(header, ctx->name);
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

static void *amoeba_server(void *c)
{
    jcfg_system_t *cfg = (jcfg_system_t *)c;
    jcfg_server_t *server_cfg = &cfg->config.server_cfg;
    jcfg_amoeba_t *amoeba;
    amoeba_server_extra_t *extra;

    register_stats_cb(crypto_stats);

    init_random_data();
    if (server_cfg->proto != proto_amoeba) {
        log_error("unknown protocol(%d)", server_cfg->proto);
        exit(-1);
    }
    amoeba = &server_cfg->amoeba;

    extra = (amoeba_server_extra_t*)malloc(sizeof(amoeba_server_extra_t));
    assert(extra);
    extra->syscfg = cfg;
    amoeba_init_pki_info(&extra->pki_info, amoeba, 0);
    INIT_LIST_HEAD(&extra->crypto_stream_list);

    msg_ev_ctx_t *ctx = (msg_ev_ctx_t*)malloc(sizeof(msg_ev_ctx_t));
    assert(ctx);
    if (msg_ev_ctx_init(ctx, task_amoeba,
                        amoeba_server_msg_handler) == -1) {
        exit(-1);
    }

    msg_ev_ctx_set_extradata(ctx, extra);
    crypto_init_cipher_info(&extra->amoeba_cipher_info);

    ev_run(ctx->loop, 0);
    return NULL;
}

INIT_ROUTINE(static void module_init(void))
{
    register_task(server_mode, task_amoeba, amoeba_server);
    register_task(client_mode, task_amoeba, amoeba_client);
}
