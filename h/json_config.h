/*                                                                                           
 * json_config.h 
 *
 * Copyright (C) 2024, sh4run
 * All rights reserved.
 */

#ifndef _JSON_CONFIG_H_
#define _JSON_CONFIG_H_

#include <arpa/inet.h>
#include "hashtable.h"

#define JCONF_MAX_PATH    128
#define JCONF_MAX_STR     32

typedef enum {
    cfg_type_int,
    cfg_type_string,
    cfg_type_none
} cfg_var_t;

typedef enum {
    server_mode,
    client_mode,
    mode_max
} jcfg_mode_t;

typedef enum {
    proto_amoeba,
    proto_socks5,
    proto_max
} jcfg_proto_t;

typedef struct {
    char   key[JCONF_MAX_PATH];
    int    scramble_len;
} jcfg_amoeba_t;

typedef struct {
    struct sockaddr_storage addr;
    jcfg_proto_t proto;
    jcfg_amoeba_t amoeba;
} jcfg_server_t;

typedef struct {
    queue_elem_t elem;
    char   remote_name[JCONF_MAX_STR];
    struct sockaddr_storage addr;
    jcfg_proto_t proto;
    char   user_name[JCONF_MAX_STR];
    jcfg_amoeba_t  amoeba;
} jcfg_remote_t;

typedef struct {
    struct sockaddr_storage addr;
    jcfg_proto_t proto;
} jcfg_local_t;

typedef struct {
    queue_t          remote_que;
    jcfg_local_t     local;
    uint64_t         device_id;
} jcfg_client_t;

typedef struct {
    hash_head_t head;
    char username[JCONF_MAX_STR];
    char password[JCONF_MAX_STR];
    queue_t    device_q;
} jcfg_user_t;


typedef struct {
    jcfg_mode_t   mode;
    uint32_t      memory_cap;
    union {
        jcfg_client_t client_cfg;
        jcfg_server_t server_cfg;
    } config;
    int user_num;
    hashtable_t  *user_cfg;
} jcfg_system_t;

extern jcfg_system_t *jcfg_parse_config (char *name);
extern void jcfg_free_config (jcfg_system_t *config);

extern int find_user_password (hashtable_t *user_cfg,
                       char *username,
                       char *password_buff,
                       int buff_len);
#endif
