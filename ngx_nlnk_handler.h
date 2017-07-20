/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#ifndef _NGX_NLNK_HANDLER_H_INCLUDED_
#define _NGX_NLNK_HANDLER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_nlnk.h"

#define NGX_NLNK_BUFFER   1
#define NGX_NLNK_CLIENT   2

#define NGX_NLNK_1MSG 0
#define NGX_NLNK_2MSG 1
#define NGX_NLNK_3MSG 2
#define NGX_NLNK_2MSG_ERR 3
#define NGX_NLNK_1MSG_NEG_DATA_SIZE 6
#define NGX_NLNK_2MSG_NEG_DATA_SIZE 3
#define NGX_NLNK_3MSG_NEG_DATA_SIZE 2
#define NGX_NLNK_2MSG_NEG_ERR_SIZE 3
#define NGX_NLNK_LEN_FIELD_SIZE 2

#define NGX_NLNK_VERSION_ID swapw(1)

#define NGX_NLNK_BUFSIZE  NOISE_PROTOCOL_PAYLOAD_SIZE + NOISE_PROTOCOL_MAC_DATA_SIZE + 2*NGX_NLNK_LEN_FIELD_SIZE

typedef enum {
    NGX_NLNK_HANDSHAKE_NONE_PHASE = 0,
    NGX_NLNK_HANDSHAKE_PROCESS_PHASE,
    NGX_NLNK_HANDSHAKE_END_PHASE,
} ngx_noise_handshake_phases_e;

typedef struct ngx_noise_s {
        NOISE_CTX *ctx;
        ngx_log_t *log;
        noise_prologue_data_t prologue;
        size_t buffer_size;
        ngx_msec_t handshake_timeout;
} ngx_noise_t;

typedef struct ngx_noise_connection_s {

        ngx_connection_t *connection;
        noise_protocol_conn_t noise_connection;
        NOISE_CTX *noise_ctx;
        noise_prologue_data_t *prologue;

        ngx_noise_handshake_phases_e handshake_phase;
        ngx_noise_role_e noise_role;
        ngx_int_t msg_num;

        ngx_int_t last;
        ngx_buf_t *buf;
        size_t buffer_size;

        ngx_msec_t handshake_timeout;

        ngx_buf_t *send_buf;
        ngx_buf_t *recv_buf;
        ssize_t to_send;
        ssize_t neg_data_recv_size;
        ssize_t noise_msg_recv_size;

        ngx_connection_handler_pt handler;

        unsigned handshaked :1;
        unsigned noise_msg_size_reading :1;
        unsigned neg_data_size_reading :1;
        unsigned buffer :1;

} ngx_noise_connection_t;

void ngx_nlnk_init_connection(ngx_connection_t *c);
void ngx_nlnk_session_handler(ngx_event_t *rev);
void ngx_nlnk_finalize_session(ngx_nlnk_session_t *s, ngx_uint_t rc);

void ngx_nlnk_cleanup_ctx(void *data);
ngx_int_t ngx_nlnk_create(ngx_noise_t *noise, size_t buffer_size, void *data);
ngx_int_t ngx_nlnk_create_connection(ngx_noise_t *noise, ngx_connection_t *c,
        ngx_uint_t flags);
ngx_int_t ngx_nlnk_handshake(ngx_connection_t *c);
ngx_int_t ngx_nlnk_shutdown(ngx_connection_t *c);

ssize_t ngx_nlnk_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit);
ssize_t ngx_nlnk_recv(ngx_connection_t *c, u_char *buf, size_t size);
ngx_chain_t * ngx_nlnk_send_chain(ngx_connection_t *c, ngx_chain_t *in,
        off_t limit);
ssize_t ngx_nlnk_write(ngx_connection_t *c, u_char *data, size_t size);
#endif

