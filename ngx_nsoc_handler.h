/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#ifndef _NGX_NSOC_HANDLER_H_INCLUDED_
#define _NGX_NSOC_HANDLER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_nsoc.h"

#define NGX_NSOC_BUFFER   1
#define NGX_NSOC_CLIENT   2

#define NGX_NSOC_BUFSIZE  65536

typedef enum {
    NGX_NSOC_HANDSHAKE_NONE_PHASE = 0,
    NGX_NSOC_HANDSHAKE_CLIENTHELLO_PHASE,
    NGX_NSOC_HANDSHAKE_SERVERHELLO_PHASE,
} ngx_noise_handshake_phases_e;

typedef enum {
    NGX_NSOC_UNSET_ROLE = -1,
    NGX_NSOC_CLIENT_ROLE,
    NGX_NSOC_SERVER_ROLE
} ngx_noise_role_e;

typedef struct noise_ctx_st {
        char XOR_symb;
} NOISE_CTX;

typedef struct ngx_noise_s {
        NOISE_CTX *ctx;
        ngx_log_t *log;
        size_t buffer_size;
} ngx_noise_t;

typedef struct ngx_noise_connection_s {

        ngx_connection_t *connection;
        NOISE_CTX *noise_ctx;

        ngx_noise_handshake_phases_e handshake_phase;
        ngx_noise_role_e noise_role;

        ngx_int_t last;
        ngx_buf_t *buf;
        size_t buffer_size;

        ngx_connection_handler_pt handler;

        ngx_event_handler_pt saved_read_handler;
        ngx_event_handler_pt saved_write_handler;

        unsigned again :1;
        unsigned handshaked :1;
        unsigned renegotiation :1;
        unsigned buffer :1;
        unsigned no_wait_shutdown :1;
        unsigned no_send_shutdown :1;
        unsigned handshake_buffer_set :1;
} ngx_noise_connection_t;

void ngx_nsoc_init_connection(ngx_connection_t *c);
void ngx_nsoc_session_handler(ngx_event_t *rev);
void ngx_nsoc_finalize_session(ngx_nsoc_session_t *s, ngx_uint_t rc);
char * ngx_nsoc_conf_set_char_slot(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

void ngx_nsoc_cleanup_ctx(void *data);
ngx_int_t ngx_nsoc_create(ngx_noise_t *noise, void *data);
ngx_int_t ngx_nsoc_create_connection(ngx_noise_t *noise, ngx_connection_t *c,
        ngx_uint_t flags);
ngx_int_t ngx_nsoc_handshake(ngx_connection_t *c);
ngx_int_t ngx_nsoc_shutdown(ngx_connection_t *c);

ssize_t ngx_nsoc_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit);
ssize_t ngx_nsoc_recv(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t * ngx_nsoc_send_chain(ngx_connection_t *c, ngx_chain_t *in,
        off_t limit);
ssize_t ngx_nsoc_write(ngx_connection_t *c, u_char *data, size_t size);
#endif

