/*
 * amoeba_protocol.h
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */ 

#ifndef __AMOEBA_PROTO_H__
#define __AMOEBA_PROTO_H__

#define MAJOR_VER    0
#define MINOR_VER    1

#define AMOEBA_IV_SIZE        16
#define AMOEBA_KEY_SIZE       16
#define AMOEBA_CIPHER_TYPE  MBEDTLS_CIPHER_AES_128_CTR
#define AMOEBA_HEAD_HASH_LEN  32

#define EPOCH_MARGIN            30000
#define IDLE_MARGIN             50000

typedef struct __attribute__((__packed__)) {
    uint8_t   major_version;
    uint8_t   minor_version;
    uint8_t   data_type;
    uint8_t   pad_type;
    uint8_t   reply_scramble;
    uint8_t   tail_len;
    uint16_t  flags;
    uint32_t  reserve;
    uint8_t   iv[AMOEBA_IV_SIZE];
    uint64_t  device_id;
    uint64_t  epoch;
    uint8_t   hash[AMOEBA_HEAD_HASH_LEN];
    uint8_t   username_len;
    uint8_t   username[0];
} amoeba_head_t;

#define AMOEBA_CLIENT_PERS  "am_client_"
#define AMOEBA_SERVER_PERS  "am_server_"

typedef struct {
    uint64_t traffic_pattern;
    uint8_t  data_type;
    uint8_t  pad_type;
    uint8_t  reply_scramble;  /* length of pad from remote to client */
    uint8_t  reserve;
} rand_params_t;

typedef struct {
    queue_elem_t    elem;
    uint64_t        device_id;
    uint64_t        last_epoch;
    uint64_t        last_server_epoch;
} client_info_t;

#endif
