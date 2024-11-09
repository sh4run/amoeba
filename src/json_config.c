/*                                                                                           
 * json_config.c
 * amoeba configuration parser. 
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
 *
 */
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "cJSON.h"
#include "json_config.h"
#include "utils.h"

typedef struct {
    char *string;
    int  casesntvty;
    int  value;
} string_value_t;

static string_value_t mode_schema[] = { {"server", 0, server_mode}, 
                                        {"client", 0, client_mode},
                                        {"", 0, -1}
                                      };

static string_value_t proto_schema[] = { {"amoeba", 0, proto_amoeba},
                                         {"socks5", 0, proto_socks5},
                                         {"", 0, -1}
                                      };

static int 
string_to_value(string_value_t *schema, char *string)
{
    int i = 0;
    int rtn = -1;
    if (string) {
        while(schema[i].string && schema[i].string[0]) {
            if (schema[i].casesntvty) {
                if (!strncmp(schema[i].string, string, JCONF_MAX_STR)) {
                    rtn = schema[i].value;
                    break;
                }
            } else {
                if (!strncasecmp(schema[i].string, string, JCONF_MAX_STR)) {
                    rtn = schema[i].value;
                    break;
                }            
            }
            i++;
        }
    }
    return rtn;
}

static char *
value_to_string(string_value_t *schema, int val)
{
    int i = 0;
    char *string = NULL;
    while(schema[i].string && schema[i].string[0]) {
        if (schema[i].value == val) {
            string = schema[i].string;
            break;
        }
        i++;
    }
    return string;
}

static int 
parse_ip_addr(cJSON *module, 
              char  *keyword, 
              struct sockaddr_storage *sock_addr)
{
    cJSON *ip, *port, *addr_obj;
    int rtn = -1;

    addr_obj = cJSON_GetObjectItemCaseSensitive(module, keyword);
    if (!addr_obj) {
        return rtn;
    }

    ip = cJSON_GetObjectItemCaseSensitive(addr_obj, "ip");
    port = cJSON_GetObjectItemCaseSensitive(addr_obj, "port");
    if (ip && port) {
        int port_val = -1;
        if (cJSON_IsNumber(port)) {
            port_val = (int)cJSON_GetNumberValue(port);    
        }
        char *ipaddr = NULL;
        if (cJSON_IsString(ip))  {
            ipaddr = cJSON_GetStringValue(ip);
        }
        if (ipaddr && (port_val != -1)) {
            if (form_sockaddr(ipaddr, port_val, sock_addr) != -1) {
                rtn = 0;
            }
        }
    }

    return rtn;
}

static int 
parse_protocol(cJSON *module, 
               char  *keyword, 
               jcfg_proto_t *p)
{
    cJSON *proto;
    int rtn = -1;

    proto = cJSON_GetObjectItemCaseSensitive(module, keyword);
    if (!proto) {
        return rtn;
    }
    char *proto_string = cJSON_GetStringValue(proto);
    int proto_val;
    if (proto_string) {
        proto_val = string_to_value(proto_schema, proto_string);
        if (proto_val != -1) {
            *p = proto_val;
            rtn = 0;
        }
    }
    return rtn;
}

static int 
parse_amoeba_cfg(cJSON *module, 
                 char  *keyword,
                 char  *public_key,
                 char  *private_key,
                 int   *scramble_len)
{
    cJSON *proto_cfg;
    int rtn = -1;

    proto_cfg = cJSON_GetObjectItemCaseSensitive(module, keyword);
    if (!proto_cfg) {
        return -1;
    }

    cJSON *key = NULL, *scramble;
    char *dest = NULL;
    if (public_key) {
        key = cJSON_GetObjectItemCaseSensitive(proto_cfg, "public-key");
        dest = public_key;
    } else if (private_key) {
        key = cJSON_GetObjectItemCaseSensitive(proto_cfg, "private-key");
        dest = private_key;
    }
    if (key && dest) {
        char *path;
        if (cJSON_IsString(key))  {
            path = cJSON_GetStringValue(key);
            strncpy(dest, path, JCONF_MAX_PATH);
            rtn = 0;
        }        
    } 

    if (rtn == -1) {
        return rtn;
    }

    rtn = -1;
    scramble = cJSON_GetObjectItemCaseSensitive(proto_cfg, "scramble-length");
    if (scramble) {
        if (cJSON_IsNumber(scramble)) {
            *scramble_len = (int)cJSON_GetNumberValue(scramble);
            rtn = 0;
        }    
    }
    return rtn;
}
                 
static int parse_server_config(cJSON *module, jcfg_system_t *cfg)
{
    int omit_err = 0;

    if (parse_ip_addr(module, "address", 
                      &cfg->config.server_cfg.addr) == -1) {
        omit_err = 1;
        log_error("JSON cfg: server ip error");
        goto  server_error_exit;
    }

    if (parse_protocol(module, "protocol", 
                       &cfg->config.server_cfg.proto) == -1) {
        log_error("JSON cfg: server protocol error");
        omit_err = 1;
        goto server_error_exit;
    }

    char *proto = value_to_string(proto_schema, cfg->config.server_cfg.proto);
    if (!proto) {
        goto server_error_exit;
    }
    if (parse_amoeba_cfg(module, proto, NULL,
                         cfg->config.server_cfg.amoeba.key,
                         &cfg->config.server_cfg.amoeba.scramble_len) == -1) {
        goto server_error_exit;
    }

    return 0;

server_error_exit:
    if (!omit_err) {
        log_error("JSON config: server config error");
    }
    return -1;
}

static int parse_client_config(cJSON *module, jcfg_system_t *cfg)
{
    int omit_err = 0;
    cJSON *local, *remote;

    local = cJSON_GetObjectItemCaseSensitive(module, "local");
    if (!local) {
        goto client_error_exit;
    }
    if (parse_ip_addr(local, "address", 
                      &cfg->config.client_cfg.local.addr) == -1) {
        log_error("JSON cfg: local ip error");
        omit_err = 1;
        goto client_error_exit;
    }
    if (parse_protocol(local, "protocol", 
                       &cfg->config.client_cfg.local.proto) == -1) {
        log_error("JSON cfg: local protocol error");
        omit_err = 1;
        goto client_error_exit;
    }

    remote = cJSON_GetObjectItemCaseSensitive(module, "remote");
    if (!remote) {
        goto client_error_exit;
    }

    init_queue(&cfg->config.client_cfg.remote_que);

    cJSON *r_obj, *name, *user;
    jcfg_remote_t r, *copy;
    memset(&r, 0, sizeof(jcfg_remote_t));
    char *proto;
    cJSON_ArrayForEach(r_obj, remote) {
        name = cJSON_GetObjectItemCaseSensitive(r_obj, "name");
        user = cJSON_GetObjectItemCaseSensitive(r_obj, "user");
        if (!name || !cJSON_IsString(name)) {
            goto client_error_exit;
        }
        if (!user || !cJSON_IsString(user)) {
            goto client_error_exit;
        }

        strncpy(r.remote_name, cJSON_GetStringValue(name), JCONF_MAX_STR);
        strncpy(r.user_name, cJSON_GetStringValue(user), JCONF_MAX_STR);
        /* check if user is configured */
        if (!hashtable_search(cfg->user_cfg, r.user_name)) {
            log_error("user(%s) not configured.\n",
                     cJSON_GetStringValue(name));
            continue;
        }

        if (parse_ip_addr(r_obj, "address", &r.addr) == -1) {
            log_error("JSON cfg: remote(%s) ip error", r.remote_name);
            continue;
        }

        if (parse_protocol(r_obj, "protocol", 
                           &r.proto) == -1) {
            log_error("JSON cfg: remote(%s) protocol error", r.remote_name);
            continue;
        }

        proto = value_to_string(proto_schema, r.proto);
        if (!proto) {
            goto client_error_exit;
        }
        if (parse_amoeba_cfg(r_obj, proto,
                             r.amoeba.key, NULL,
                             &r.amoeba.scramble_len) == -1) {
            log_error("JSON cfg: remote(%s) protocol cfg error", 
                      r.remote_name);
            continue;
        }

        copy = (jcfg_remote_t*)malloc(sizeof(jcfg_remote_t));
        if (!copy) {
            goto client_error_exit;
        }
        *copy = r;
        enqueue(&cfg->config.client_cfg.remote_que, &copy->elem);
        log_info("add remote %s", copy->remote_name);
    }

    return 0;

client_error_exit:
    if (!omit_err) {
        log_error("JSON config: client config error");
    }    
    return -1;
}

static int username_hash(void *key)
{
    return string_hash(key);
}

static int username_compare(hash_head_t *node, void *key)
{
    char *name = (char*)key;
    jcfg_user_t *user = (jcfg_user_t *)node;
    
    return strncmp(user->username, name, JCONF_MAX_STR);
}

int find_user_password(hashtable_t *user_cfg,
                       char *username,
                       char *password_buff,
                       int buff_len)
{
    jcfg_user_t *user;
    user = (jcfg_user_t *)hashtable_search(user_cfg, username);
    if (user) {
        if (strlen(user->password) < (size_t)buff_len) {
            snprintf(password_buff, buff_len, "%s", user->password);
            return 0;
        }
    }
    return -1;
}

static jcfg_system_t *parse_config(const char *input) 
{
    cJSON *mode = NULL;
    int mode_found = -1;
    jcfg_system_t *cfg = NULL;
    cJSON *cfg_json = NULL;
    char *mode_string = NULL;
    cJSON *module;

    cfg = (jcfg_system_t *)malloc(sizeof(jcfg_system_t));
    if (!cfg) {
        goto parse_error;
    }
    memset(cfg, 0, sizeof(jcfg_system_t));

    cfg->user_cfg = hashtable_init(256, username_hash, username_compare);
    if (!cfg->user_cfg) {
        goto parse_error;
    }

    cfg_json = cJSON_Parse(input);
    if (cfg_json == NULL) {
        char const *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) {
            log_error("JSON config: parse error before\n   %s\n", error_ptr);
        }
        goto parse_error;
    }

    /* parse user section first as user info is needed in client cfg */
    module = cJSON_GetObjectItemCaseSensitive(cfg_json, "user");
    if (!module) {
        log_error("JSON config : user config not found.");
        goto parse_error;
    }

    cJSON *user, *name, *password;
    jcfg_user_t *u;
    cJSON_ArrayForEach(user, module) {
        name = cJSON_GetObjectItemCaseSensitive(user, "user-name");
        password = cJSON_GetObjectItemCaseSensitive(user, "password");
        if (name && cJSON_IsString(name) && 
            password && cJSON_IsString(password)) {
            /* check for duplicated user name */
            if (hashtable_search(cfg->user_cfg, 
                                 cJSON_GetStringValue(name))) {
                log_info("Duplicated user(%s), skipped.", 
                        cJSON_GetStringValue(name));
                continue;
            }            
            u = (jcfg_user_t*)malloc(sizeof(jcfg_user_t));
            if (!u) {
                goto parse_error;
            }
            init_queue(&u->device_q);
            strncpy(u->username, cJSON_GetStringValue(name), 
                    JCONF_MAX_STR);
            strncpy(u->password, cJSON_GetStringValue(password), 
                    JCONF_MAX_STR);
            hashtable_add(cfg->user_cfg, u, u->username);
            cfg->user_num++;
        }
    }

    mode = cJSON_GetObjectItemCaseSensitive(cfg_json, "mode");
    if (mode && cJSON_IsString(mode)) {
        mode_string = cJSON_GetStringValue(mode);
        if (mode_string) {
            mode_found = string_to_value(mode_schema, mode_string);
            if (mode_found != -1) {
                cfg->mode = mode_found;
            }
        }
    } 
    if (mode_found == -1) {
        log_error("JSON config: mode not found or not valid");
        goto parse_error;
    }

    cJSON *cap = cJSON_GetObjectItemCaseSensitive(cfg_json, "memory-cap");
    if (cap && cJSON_IsNumber(cap)) {
        cfg->memory_cap = (uint32_t)cJSON_GetNumberValue(cap);
    } else {
        /* assign default value */
        if (cfg->mode == server_mode) {
            cfg->memory_cap = 8;
        } else {
            cfg->memory_cap = 4;
        }
    }

    module = cJSON_GetObjectItemCaseSensitive(cfg_json, mode_string);
    if (!module) {
        log_error("JSON config : %s config not found.", mode_string);
        goto parse_error;
    }

    int rtn = -1;
    switch (cfg->mode) {
        case server_mode:
            rtn = parse_server_config(module, cfg);
            break;
        case client_mode:
            rtn = parse_client_config(module, cfg);
            break;
        default:
            break;
    }

    if (rtn != -1) {
        goto parse_end;
    }

parse_error:
    if (cfg) {
        if (cfg->user_cfg) {
            hashtable_free(cfg->user_cfg);
        }
        free(cfg);
        cfg = NULL;
    }

parse_end:
    if (cfg_json) {
        cJSON_Delete(cfg_json);
    }
    return cfg;
}

jcfg_system_t *jcfg_parse_config(char *name)
{
    FILE *fd = NULL;
    char *config_data = NULL;
    int size;
    jcfg_system_t *rtn = NULL;

    if (!name) {
        goto read_config_exit;
    }

    if ((fd = fopen(name, "rb")) == NULL) {
        log_error("Fail to open config file: %s", name);
        goto read_config_exit;
    }

    fseek(fd, 0, SEEK_END); 
    size = ftell(fd); 
    fseek(fd, 0, SEEK_SET); 

    config_data = malloc(size+1);
    if (config_data == NULL) {
        log_error("Not enough memory to read config");
        goto read_config_exit;
    }

    int n;
    if ((n = fread(config_data, 1, size, fd)) != size) {
        log_error("Error reading config: %s, read/expected: %d/%d", 
                  name, n, size);
        goto read_config_exit;
    }
  
    config_data[size] = 0;
    rtn = parse_config(config_data);

    if (rtn != NULL) {
        if (rtn->mode == client_mode) {
            struct stat fs;
            if (stat(name, &fs)) {
                /* error */
                free(rtn);
                rtn = NULL;
            } else {
                uint32_t *p = (uint32_t*)&rtn->config.client_cfg.device_id;
                p[0] = (uint32_t)fs.st_ctime;
                p[1] = (uint32_t)fs.st_ctim.tv_nsec;
            }
        }
    }

read_config_exit:
    if (config_data) {
        free(config_data);
    }
    if (fd) {
        fclose(fd);
    }

    return rtn;
}

void jcfg_free_config(jcfg_system_t *config)
{
    if (config && config->user_cfg) {
        free(config->user_cfg);
    }
}
