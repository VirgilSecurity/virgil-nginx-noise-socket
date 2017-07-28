/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_NSOC_H_INCLUDED_
#define _NGX_NSOC_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct ngx_nsoc_session_s ngx_nsoc_session_t;

#include "ngx_noise_protocol.h"
#include "ngx_nsoc_handler.h"
#include "ngx_nsoc_noiseserver_module.h"
#include "ngx_nsoc_variables.h"
#include "ngx_nsoc_script.h"
#include "ngx_nsoc_upstream.h"
#include "ngx_nsoc_upstream_round_robin.h"

#define NGX_NSOC_OK                        200
#define NGX_NSOC_BAD_REQUEST               400
#define NGX_NSOC_FORBIDDEN                 403
#define NGX_NSOC_INTERNAL_SERVER_ERROR     500
#define NGX_NSOC_BAD_GATEWAY               502
#define NGX_NSOC_SERVICE_UNAVAILABLE       503

#define NGX_NSOC_BUFFERED       0x01

typedef struct {
        void **main_conf;
        void **srv_conf;
} ngx_nsoc_conf_ctx_t;

typedef struct {
        ngx_sockaddr_t sockaddr;
        socklen_t socklen;

        /* server ctx */
        ngx_nsoc_conf_ctx_t *ctx;

        unsigned bind :1;
        unsigned wildcard :1;

        /*noise*/
        unsigned noise_on :1;
        /*end noise*/
#if (NGX_HAVE_INET6)
        unsigned ipv6only :1;
#endif
        unsigned reuseport :1;
        unsigned so_keepalive :2;
        unsigned proxy_protocol :1;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
        int tcp_keepidle;
        int tcp_keepintvl;
        int tcp_keepcnt;
#endif
        int backlog;
        int type;
} ngx_nsoc_listen_t;

typedef struct {
        ngx_nsoc_conf_ctx_t *ctx;
        ngx_str_t addr_text;
        /*noise*/
        unsigned noise_on :1;
        /*end noise*/
        //unsigned proxy_protocol :1;
} ngx_nsoc_addr_conf_t;

typedef struct {
        in_addr_t addr;
        ngx_nsoc_addr_conf_t conf;
} ngx_nsoc_in_addr_t;

#if (NGX_HAVE_INET6)

typedef struct {
        struct in6_addr addr6;
        ngx_nsoc_addr_conf_t conf;
} ngx_nsoc_in6_addr_t;

#endif

typedef struct {
        /* ngx_nsoc_in_addr_t or ngx_nsoc_in6_addr_t */
        void *addrs;
        ngx_uint_t naddrs;
} ngx_nsoc_port_t;

typedef struct {
        int family;
        int type;
        in_port_t port;
        ngx_array_t addrs; /* array of ngx_nsoc_conf_addr_t */
} ngx_nsoc_conf_port_t;

typedef struct {
        ngx_nsoc_listen_t opt;
} ngx_nsoc_conf_addr_t;

typedef enum {
    NGX_NSOC_POST_ACCEPT_PHASE = 0,
    NGX_NSOC_PREACCESS_PHASE,
    NGX_NSOC_ACCESS_PHASE,
    NGX_NSOC_PROTECT_PHASE,
    NGX_NSOC_PREREAD_PHASE,
    NGX_NSOC_CONTENT_PHASE,
    NGX_NSOC_LOG_PHASE
} ngx_nsoc_phases;

typedef struct ngx_nsoc_phase_handler_s ngx_nsoc_phase_handler_t;

typedef ngx_int_t (*ngx_nsoc_phase_handler_pt)(ngx_nsoc_session_t *s,
        ngx_nsoc_phase_handler_t *ph);
typedef ngx_int_t (*ngx_nsoc_handler_pt)(ngx_nsoc_session_t *s);
typedef void (*ngx_nsoc_content_handler_pt)(ngx_nsoc_session_t *s);

struct ngx_nsoc_phase_handler_s {
        ngx_nsoc_phase_handler_pt checker;
        ngx_nsoc_handler_pt handler;
        ngx_uint_t next;
};

typedef struct {
        ngx_nsoc_phase_handler_t *handlers;
} ngx_nsoc_phase_engine_t;

typedef struct {
        ngx_array_t handlers;
} ngx_nsoc_phase_t;

typedef struct {
        ngx_array_t servers; /* ngx_nsoc_core_srv_conf_t */
        ngx_array_t listen; /* ngx_nsoc_listen_t */

        ngx_pool_t *pool;

        ngx_nsoc_phase_engine_t phase_engine;

        ngx_hash_t variables_hash;

        ngx_array_t variables; /* ngx_nsoc_variable_t */
        ngx_array_t prefix_variables; /* ngx_nsoc_variable_t */
        ngx_uint_t ncaptures;

        ngx_uint_t variables_hash_max_size;
        ngx_uint_t variables_hash_bucket_size;

        ngx_hash_keys_arrays_t *variables_keys;

        ngx_nsoc_phase_t phases[NGX_NSOC_LOG_PHASE + 1];
} ngx_nsoc_core_main_conf_t;

typedef struct {
        ngx_nsoc_content_handler_pt handler;

        ngx_nsoc_conf_ctx_t *ctx;

        u_char *file_name;
        ngx_uint_t line;

        ngx_flag_t tcp_nodelay;
        size_t nsoc_preread_buffer_size;
        ngx_msec_t preread_timeout;

        ngx_log_t *error_log;

        ngx_msec_t resolver_timeout;
        ngx_resolver_t *resolver;

        //ngx_msec_t proxy_protocol_timeout;

        ngx_uint_t listen; /* unsigned  listen:1; */
} ngx_nsoc_core_srv_conf_t;

struct ngx_nsoc_session_s {
        uint32_t signature; /* "NSOC" */

        ngx_connection_t *connection;

        off_t received;
        time_t start_sec;
        ngx_msec_t start_msec;

        ngx_log_handler_pt log_handler;

        void **ctx;
        void **main_conf;
        void **srv_conf;

        /*noise*/
        ngx_noise_connection_t *client_noise_connection;
        ngx_noise_connection_t *server_noise_connection;
        /*end noise*/

        ngx_nsoc_upstream_t *upstream;
        ngx_array_t *upstream_states;
        /* of ngx_nsoc_upstream_state_t */
        ngx_nsoc_variable_value_t *variables;

#if (NGX_PCRE)
        ngx_uint_t ncaptures;
        int *captures;
        u_char *captures_data;
#endif

        ngx_int_t phase_handler;
        ngx_uint_t status;

        /*noise*/
        unsigned noise_on :1;
        /*end noise*/
        unsigned stat_processing :1;

        unsigned health_check :1;
};

typedef struct {
        ngx_int_t (*preconfiguration)(ngx_conf_t *cf);
        ngx_int_t (*postconfiguration)(ngx_conf_t *cf);

        void *(*create_main_conf)(ngx_conf_t *cf);
        char *(*init_main_conf)(ngx_conf_t *cf, void *conf);

        void *(*create_srv_conf)(ngx_conf_t *cf);
        char *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_nsoc_module_t;

#define NGX_NSOC_MODULE       0x434F534E     /* "NSOC" */

#define NGX_NSOC_MAIN_CONF    0x02000000
#define NGX_NSOC_SRV_CONF     0x04000000
#define NGX_NSOC_UPS_CONF     0x08000000

#define NGX_NSOC_MAIN_CONF_OFFSET  offsetof(ngx_nsoc_conf_ctx_t, main_conf)
#define NGX_NSOC_SRV_CONF_OFFSET   offsetof(ngx_nsoc_conf_ctx_t, srv_conf)

#define ngx_nsoc_get_module_ctx(s, module)   (s)->ctx[module.ctx_index]
#define ngx_nsoc_set_ctx(s, c, module)       s->ctx[module.ctx_index] = c;
#define ngx_nsoc_delete_ctx(s, module)       s->ctx[module.ctx_index] = NULL;

#define ngx_nsoc_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_nsoc_get_module_srv_conf(s, module)                              \
    (s)->srv_conf[module.ctx_index]

#define ngx_nsoc_conf_get_module_main_conf(cf, module)                       \
    ((ngx_nsoc_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_nsoc_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_nsoc_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]

#define ngx_nsoc_cycle_get_module_main_conf(cycle, module)                   \
    (cycle->conf_ctx[ngx_nsoc_module.index] ?                                \
        ((ngx_nsoc_conf_ctx_t *) cycle->conf_ctx[ngx_nsoc_module.index])   \
            ->main_conf[module.ctx_index]:                                     \
        NULL)

#define NGX_NSOC_WRITE_BUFFERED  0x10

void ngx_nsoc_core_run_phases(ngx_nsoc_session_t *s);
ngx_int_t ngx_nsoc_core_generic_phase(ngx_nsoc_session_t *s,
        ngx_nsoc_phase_handler_t *ph);
ngx_int_t ngx_nsoc_core_preread_phase(ngx_nsoc_session_t *s,
        ngx_nsoc_phase_handler_t *ph);
ngx_int_t ngx_nsoc_core_content_phase(ngx_nsoc_session_t *s,
        ngx_nsoc_phase_handler_t *ph);

extern ngx_module_t ngx_nsoc_module;
extern ngx_uint_t ngx_nsoc_max_module;
extern ngx_module_t ngx_nsoc_core_module;

typedef ngx_int_t (*ngx_nsoc_filter_pt)(ngx_nsoc_session_t *s,
        ngx_chain_t *chain, ngx_uint_t from_upstream);

extern ngx_nsoc_filter_pt ngx_nsoc_top_filter;

#endif /* _NGX_NSOC_H_INCLUDED_ */
