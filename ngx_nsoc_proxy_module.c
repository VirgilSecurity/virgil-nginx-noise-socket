/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_nsoc.h"

typedef struct {
    ngx_addr_t *addr;
    ngx_nsoc_complex_value_t *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t transparent; /* unsigned  transparent:1; */
#endif
} ngx_nsoc_upstream_local_t;

typedef struct {
    ngx_msec_t connect_timeout;
    ngx_msec_t timeout;
    ngx_msec_t next_upstream_timeout;
    size_t buffer_size;
    size_t upload_rate;
    size_t download_rate;
    ngx_uint_t responses;
    ngx_uint_t next_upstream_tries;
    ngx_flag_t next_upstream;

    ngx_nsoc_upstream_local_t *local;

    ngx_flag_t noise_enable;

    ngx_noise_t *noise;

    ngx_str_t client_private_key_file;
    ngx_str_t server_public_key_file;

    ngx_nsoc_upstream_srv_conf_t *upstream;
    ngx_nsoc_complex_value_t *upstream_value;

} ngx_nsoc_proxy_srv_conf_t;

static void ngx_nsoc_proxy_handler(ngx_nsoc_session_t *s);
static ngx_int_t ngx_nsoc_proxy_eval(ngx_nsoc_session_t *s,
        ngx_nsoc_proxy_srv_conf_t *pscf);
static ngx_int_t ngx_nsoc_proxy_set_local(ngx_nsoc_session_t *s,
        ngx_nsoc_upstream_t *u, ngx_nsoc_upstream_local_t *local);
static void ngx_nsoc_proxy_connect(ngx_nsoc_session_t *s);
static void ngx_nsoc_proxy_init_upstream(ngx_nsoc_session_t *s);
static void ngx_nsoc_proxy_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_nsoc_proxy_upstream_handler(ngx_event_t *ev);
static void ngx_nsoc_proxy_downstream_handler(ngx_event_t *ev);
static void ngx_nsoc_proxy_process_connection(ngx_event_t *ev,
        ngx_uint_t from_upstream);
static void ngx_nsoc_proxy_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_nsoc_proxy_test_connect(ngx_connection_t *c);
static void ngx_nsoc_proxy_process(ngx_nsoc_session_t *s,
        ngx_uint_t from_upstream, ngx_uint_t do_write);
static void ngx_nsoc_proxy_next_upstream(ngx_nsoc_session_t *s);
static void ngx_nsoc_proxy_finalize(ngx_nsoc_session_t *s, ngx_uint_t rc);
static u_char *ngx_nsoc_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len);

static void *ngx_nsoc_proxy_create_srv_conf(ngx_conf_t *cf);
static char *ngx_nsoc_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent,
        void *child);
static char *ngx_nsoc_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_nsoc_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/*noise*/

static void ngx_nsoc_proxy_noise_init_connection(ngx_nsoc_session_t *s);
static void ngx_nsoc_proxy_noise_handshake(ngx_connection_t *pc);
static ngx_int_t ngx_nsoc_proxy_set_noiselink(ngx_conf_t *cf,
        ngx_nsoc_proxy_srv_conf_t *pscf);

/*end noise*/

static ngx_command_t ngx_nsoc_proxy_commands[] =
{

  { ngx_string("proxy_pass"),
    NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_nsoc_proxy_pass,
    NGX_NSOC_SRV_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("proxy_bind"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE12,
    ngx_nsoc_proxy_bind,
    NGX_NSOC_SRV_CONF_OFFSET,
    0,
    NULL },

  { ngx_string("proxy_connect_timeout"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, connect_timeout),
    NULL },

  { ngx_string("proxy_timeout"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, timeout),
    NULL },

  { ngx_string("block_buffer_size"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, buffer_size),
    NULL },

  { ngx_string("proxy_upload_rate"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, upload_rate),
    NULL },

  { ngx_string("proxy_download_rate"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_size_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, download_rate),
    NULL },

  { ngx_string("proxy_responses"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, responses),
    NULL },

  { ngx_string("proxy_next_upstream"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, next_upstream),
    NULL },

  { ngx_string("proxy_next_upstream_tries"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_num_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, next_upstream_tries),
    NULL },

  { ngx_string("proxy_next_upstream_timeout"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, next_upstream_timeout),
    NULL },

  /*noise*/
  { ngx_string("proxy_noise"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, noise_enable),
    NULL },

  { ngx_string("client_private_key_file"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, client_private_key_file),
    NULL },

  { ngx_string("server_public_key_file"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_proxy_srv_conf_t, server_public_key_file),
    NULL },
  /*end noise*/

  ngx_null_command
};

static ngx_nsoc_module_t ngx_nsoc_proxy_module_ctx =
{
  NULL, /* preconfiguration */
  NULL, /* postconfiguration */

  NULL, /* create main configuration */
  NULL, /* init main configuration */

  ngx_nsoc_proxy_create_srv_conf, /* create server configuration */
  ngx_nsoc_proxy_merge_srv_conf /* merge server configuration */
};

ngx_module_t ngx_nsoc_proxy_module =
{
  NGX_MODULE_V1,
  &ngx_nsoc_proxy_module_ctx, /* module context */
  ngx_nsoc_proxy_commands, /* module directives */
  NGX_NSOC_MODULE, /* module type */
  NULL, /* init master */
  NULL, /* init module */
  NULL, /* init process */
  NULL, /* init thread */
  NULL, /* exit thread */
  NULL, /* exit process */
  NULL, /* exit master */
  NGX_MODULE_V1_PADDING
};

static void ngx_nsoc_proxy_handler(ngx_nsoc_session_t *s)
{
    u_char *p;
    ngx_str_t *host;
    ngx_uint_t i;
    ngx_connection_t *c;
    ngx_resolver_ctx_t *ctx, temp;
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_core_srv_conf_t *cscf;
    ngx_nsoc_proxy_srv_conf_t *pscf;
    ngx_nsoc_upstream_srv_conf_t *uscf, **uscfp;
    ngx_nsoc_upstream_main_conf_t *umcf;

    c = s->connection;

    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connection handler");

    u = ngx_pcalloc(c->pool, sizeof(ngx_nsoc_upstream_t));
    if (u == NULL) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    s->upstream = u;

    s->log_handler = ngx_nsoc_proxy_log_error;

    u->peer.log = c->log;
    u->peer.log_error = NGX_ERROR_ERR;

    if (ngx_nsoc_proxy_set_local(s, u, pscf->local) != NGX_OK) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.type = c->type;
    u->start_sec = ngx_time();

    c->write->handler = ngx_nsoc_proxy_downstream_handler;
    c->read->handler = ngx_nsoc_proxy_downstream_handler;

    s->upstream_states = ngx_array_create(
            c->pool, 1, sizeof(ngx_nsoc_upstream_state_t));
    if (s->upstream_states == NULL) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->type == SOCK_STREAM) {
        p = ngx_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        u->downstream_buf.start = p;
        u->downstream_buf.end = p + pscf->buffer_size;
        u->downstream_buf.pos = p;
        u->downstream_buf.last = p;

        if (c->read->ready) {
            ngx_post_event(c->read, &ngx_posted_events);
        }
    }

    if (pscf->upstream_value) {
        if (ngx_nsoc_proxy_eval(s, pscf) != NGX_OK) {
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->resolved == NULL) {

        uscf = pscf->upstream;

    } else {
        host = &u->resolved->host;

        umcf = ngx_nsoc_get_module_main_conf(s, ngx_nsoc_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                    && ((uscf->port == 0 && u->resolved->no_port)
                            || uscf->port == u->resolved->port)
                    && ngx_strncasecmp(uscf->host.data, host->data, host->len)
                            == 0) {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port
                    == 0&& u->resolved->sockaddr->sa_family != AF_UNIX) {
                ngx_log_error(
                        NGX_LOG_ERR, c->log, 0, "no port in upstream \"%V\"",
                        host);
                ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ngx_nsoc_upstream_create_round_robin_peer(
                    s, u->resolved) != NGX_OK) {
                ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
                return;
            }

            ngx_nsoc_proxy_connect(s);

            return;
        }

        if (u->resolved->port == 0) {
            ngx_log_error(
                    NGX_LOG_ERR, c->log, 0, "no port in upstream \"%V\"", host);
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        cscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_core_module);

        ctx = ngx_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(
                    NGX_LOG_ERR, c->log, 0, "no resolver defined to resolve %V",
                    host);
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->name = *host;
        ctx->handler = ngx_nsoc_proxy_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

    found:

    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, c->log, 0, "no upstream configuration");
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = ngx_current_msec;

    if (pscf->next_upstream_tries
            && u->peer.tries > pscf->next_upstream_tries) {
        u->peer.tries = pscf->next_upstream_tries;
    }

    ngx_nsoc_proxy_connect(s);
}

static ngx_int_t ngx_nsoc_proxy_eval(ngx_nsoc_session_t *s,
        ngx_nsoc_proxy_srv_conf_t *pscf)
{
    ngx_str_t host;
    ngx_url_t url;
    ngx_nsoc_upstream_t *u;

    if (ngx_nsoc_complex_value(s, pscf->upstream_value, &host) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url = host;
    url.no_resolve = 1;

    if (ngx_parse_url(s->connection->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(
                    NGX_LOG_ERR, s->connection->log, 0, "%s in upstream \"%V\"",
                    url.err, &url.url);
        }

        return NGX_ERROR;
    }

    u = s->upstream;

    u->resolved = ngx_pcalloc(
            s->connection->pool, sizeof(ngx_nsoc_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return NGX_OK;
}

static ngx_int_t ngx_nsoc_proxy_set_local(ngx_nsoc_session_t *s,
        ngx_nsoc_upstream_t *u, ngx_nsoc_upstream_local_t *local)
{
    ngx_int_t rc;
    ngx_str_t val;
    ngx_addr_t *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return NGX_OK;
    }

#if (NGX_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return NGX_OK;
    }

    if (ngx_nsoc_complex_value(s, local->value, &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len == 0) {
        return NGX_OK;
    }

    addr = ngx_palloc(s->connection->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_parse_addr_port(s->connection->pool, addr, val.data, val.len);
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc != NGX_OK) {
        ngx_log_error(
                NGX_LOG_ERR, s->connection->log, 0,
                "invalid local address \"%V\"", &val);
        return NGX_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return NGX_OK;
}

static void ngx_nsoc_proxy_connect(ngx_nsoc_session_t *s)
{
    ngx_int_t rc;
    ngx_connection_t *c, *pc;
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_proxy_srv_conf_t *pscf;

    c = s->connection;

    c->log->action = "connecting to upstream";

    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    u = s->upstream;

    u->connected = 0;

    if (u->state) {
        u->state->response_time = ngx_current_msec - u->state->response_time;
    }

    u->state = ngx_array_push(s->upstream_states);
    if (u->state == NULL) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(u->state, sizeof(ngx_nsoc_upstream_state_t));

    u->state->connect_time = (ngx_msec_t) -1;
    u->state->first_byte_time = (ngx_msec_t) -1;
    u->state->response_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0, "proxy connect: %i", rc);

    if (rc == NGX_ERROR) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "no live upstreams");
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_BAD_GATEWAY);
        return;
    }

    if (rc == NGX_DECLINED) {
        ngx_nsoc_proxy_next_upstream(s);
        return;
    }

    /* rc == NGX_OK || rc == NGX_AGAIN || rc == NGX_DONE */

    pc = u->peer.connection;

    pc->data = s;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc != NGX_AGAIN) {
        ngx_nsoc_proxy_init_upstream(s);
        return;
    }

    pc->read->handler = ngx_nsoc_proxy_connect_handler;
    pc->write->handler = ngx_nsoc_proxy_connect_handler;

    ngx_add_timer(pc->write, pscf->connect_timeout);
}

static void ngx_nsoc_proxy_init_upstream(ngx_nsoc_session_t *s)
{
    int tcp_nodelay;
    u_char *p;
    ngx_chain_t *cl;
    ngx_connection_t *c, *pc;
    ngx_log_handler_pt handler;
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_core_srv_conf_t *cscf;
    ngx_nsoc_proxy_srv_conf_t *pscf;

    u = s->upstream;
    pc = u->peer.connection;

    cscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_core_module);

    if (pc->type == SOCK_STREAM && cscf->tcp_nodelay
            && pc->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, pc->log, 0, "tcp_nodelay");

        tcp_nodelay = 1;

        if (setsockopt(
                pc->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay,
                sizeof(int)) == -1) {
            ngx_connection_error(
                    pc, ngx_socket_errno, "setsockopt(TCP_NODELAY) failed");
            ngx_nsoc_proxy_next_upstream(s);
            return;
        }

        pc->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }

    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    /*noise*/
    if ((pc->type == SOCK_STREAM) && (pscf->noise)) {

        if (s->client_noise_connection == NULL) {
            ngx_nsoc_proxy_noise_init_connection(s);
            return;
        }
    }
    /*end noise*/

    c = s->connection;

    if (c->log->log_level >= NGX_LOG_INFO) {
        ngx_str_t str;
        u_char addr[NGX_SOCKADDR_STRLEN];

        str.len = NGX_SOCKADDR_STRLEN;
        str.data = addr;

        if (ngx_connection_local_sockaddr(pc, &str, 1) == NGX_OK) {
            handler = c->log->handler;
            c->log->handler = NULL;

            ngx_log_error(
                    NGX_LOG_INFO, c->log, 0, "%sproxy %V connected to %V",
                    pc->type == SOCK_DGRAM ? "udp " : "", &str, u->peer.name);

            c->log->handler = handler;
        }
    }

    u->state->connect_time = ngx_current_msec - u->state->response_time;

    if (u->peer.notify) {
        u->peer.notify(&u->peer, u->peer.data,
        NGX_NSOC_UPSTREAM_NOTIFY_CONNECT);
    }

    c->log->action = "proxying connection";

    if (u->upstream_buf.start == NULL) {
        p = ngx_pnalloc(c->pool, pscf->buffer_size);
        if (p == NULL) {
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        u->upstream_buf.start = p;
        u->upstream_buf.end = p + pscf->buffer_size;
        u->upstream_buf.pos = p;
        u->upstream_buf.last = p;
    }

    if (c->buffer && c->buffer->pos < c->buffer->last) {
        ngx_log_debug1(
                NGX_LOG_DEBUG_STREAM, c->log, 0,
                "stream proxy add preread buffer: %uz",
                c->buffer->last - c->buffer->pos);

        cl = ngx_chain_get_free_buf(c->pool, &u->free);
        if (cl == NULL) {
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        *cl->buf = *c->buffer;

        cl->buf->tag = (ngx_buf_tag_t) &ngx_nsoc_proxy_module;
        cl->buf->flush = 1;
        cl->buf->last_buf = (c->type == SOCK_DGRAM);

        cl->next = u->upstream_out;
        u->upstream_out = cl;
    }

    if (c->type == SOCK_DGRAM && pscf->responses == 0) {
        pc->read->ready = 0;
        pc->read->eof = 1;
    }

    u->connected = 1;

    pc->read->handler = ngx_nsoc_proxy_upstream_handler;
    pc->write->handler = ngx_nsoc_proxy_upstream_handler;

    if (pc->read->ready || pc->read->eof) {
        ngx_post_event(pc->read, &ngx_posted_events);
    }

    ngx_nsoc_proxy_process(s, 0, 1);
}

/*noise*/
static void ngx_nsoc_proxy_noise_init_connection(ngx_nsoc_session_t *s)
{
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_proxy_srv_conf_t *pscf;
    ngx_connection_t *pc;
    ngx_int_t rc;

    u = s->upstream;
    pc = u->peer.connection;
    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    if (ngx_nsoc_create_connection(
            pscf->noise, pc, NGX_NSOC_BUFFER | NGX_NSOC_CLIENT) != NGX_OK) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    s->connection->log->action = "NOISE handshaking to upstream";

    rc = ngx_nsoc_handshake(pc);

    if (rc == NGX_AGAIN) {

        /*if (!pc->write->timer_set) {
         ngx_add_timer(pc->write, pscf->connect_timeout);
         }*/

        s->client_noise_connection->handler = ngx_nsoc_proxy_noise_handshake;
        return;
    }
    if (rc == NGX_ERROR) {
        ngx_log_error(
                NGX_LOG_ERR, s->connection->log, 0,
                "NOISE error client handshaking");
    }

    ngx_nsoc_proxy_noise_handshake(pc);
}

static void ngx_nsoc_proxy_noise_handshake(ngx_connection_t *pc)
{
    //long                          rc;
    ngx_nsoc_session_t *s;
    //ngx_nsoc_upstream_t        *u;
    //ngx_nsoc_proxy_srv_conf_t  *pscf;

    s = pc->data;

    //pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    ngx_log_debug8(
            NGX_LOG_DEBUG_EVENT,
            pc->log,
            0,
            "wew status: act:%d dis:%d, rdy:%d eof:%d del:%d peof:%d pos:%d clo:%d",
            pc->write->active, pc->write->disabled, pc->write->ready,
            pc->write->eof, pc->write->delayed, pc->write->pending_eof,
            pc->write->posted, pc->write->closed);
    ngx_log_debug8(
            NGX_LOG_DEBUG_EVENT,
            pc->log,
            0,
            "rew status: act:%d dis:%d, rdy:%d eof:%d del:%d peof:%d pos:%d clo:%d",
            pc->read->active, pc->read->disabled, pc->read->ready,
            pc->read->eof, pc->read->delayed, pc->read->pending_eof,
            pc->read->posted, pc->read->closed);

    if (s->client_noise_connection->handshaked) {

        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        ngx_nsoc_proxy_init_upstream(s);

        return;
    }

//failed:

    ngx_nsoc_proxy_next_upstream(s);
}

/*end noise*/

static void ngx_nsoc_proxy_downstream_handler(ngx_event_t *ev)
{
    ngx_nsoc_proxy_process_connection(ev, ev->write);
}

static void ngx_nsoc_proxy_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_nsoc_session_t *s;
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_proxy_srv_conf_t *pscf;
    ngx_nsoc_upstream_resolved_t *ur;

    s = ctx->data;

    u = s->upstream;
    ur = u->resolved;

    ngx_log_debug0(
            NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "stream upstream resolve");

    if (ctx->state) {
        ngx_log_error(
                NGX_LOG_ERR, s->connection->log, 0,
                "%V could not be resolved (%i: %s)", &ctx->name, ctx->state,
                ngx_resolver_strerror(ctx->state));

        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
        u_char text[NGX_SOCKADDR_STRLEN];
        ngx_str_t addr;
        ngx_uint_t i;

        addr.data = text;

        for (i = 0; i < ctx->naddrs; i++) {
            addr.len = ngx_sock_ntop(
                    ur->addrs[i].sockaddr, ur->addrs[i].socklen, text,
                    NGX_SOCKADDR_STRLEN, 0);

            ngx_log_debug1(
                    NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                    "name was resolved to %V", &addr);
        }
    }
#endif

    if (ngx_nsoc_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = ngx_current_msec;

    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    if (pscf->next_upstream_tries
            && u->peer.tries > pscf->next_upstream_tries) {
        u->peer.tries = pscf->next_upstream_tries;
    }

    ngx_nsoc_proxy_connect(s);
}

static void ngx_nsoc_proxy_upstream_handler(ngx_event_t *ev)
{
    ngx_nsoc_proxy_process_connection(ev, !ev->write);
}

static void ngx_nsoc_proxy_process_connection(ngx_event_t *ev,
        ngx_uint_t from_upstream)
{
    ngx_connection_t *c, *pc;
    ngx_nsoc_session_t *s;
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_proxy_srv_conf_t *pscf;

    c = ev->data;
    s = c->data;
    u = s->upstream;

    c = s->connection;
    pc = u->peer.connection;

    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    if (ev->timedout) {
        ev->timedout = 0;

        if (ev->delayed) {
            ev->delayed = 0;

            if (!ev->ready) {
                if (ngx_handle_read_event(ev, 0) != NGX_OK) {
                    ngx_nsoc_proxy_finalize(s,
                    NGX_NSOC_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (u->connected && !c->read->delayed && !pc->read->delayed) {
                    ngx_add_timer(c->write, pscf->timeout);
                }

                return;
            }

        } else {
            if (s->connection->type == SOCK_DGRAM) {
                if (pscf->responses == NGX_MAX_INT32_VALUE) {

                    /*
                     * successfully terminate timed out UDP session
                     * with unspecified number of responses
                     */

                    pc->read->ready = 0;
                    pc->read->eof = 1;

                    ngx_nsoc_proxy_process(s, 1, 0);
                    return;
                }

                if (u->received == 0) {
                    ngx_nsoc_proxy_next_upstream(s);
                    return;
                }
            }

            ngx_connection_error(c, NGX_ETIMEDOUT, "connection timed out");
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_OK);
            return;
        }

    } else if (ev->delayed) {

        ngx_log_debug0(
                NGX_LOG_DEBUG_STREAM, c->log, 0, "stream connection delayed");

        if (ngx_handle_read_event(ev, 0) != NGX_OK) {
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    if (from_upstream && !u->connected) {
        return;
    }

    ngx_nsoc_proxy_process(s, from_upstream, ev->write);
}

static void ngx_nsoc_proxy_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_nsoc_session_t *s;

    c = ev->data;
    s = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, NGX_ETIMEDOUT, "upstream timed out");
        ngx_nsoc_proxy_next_upstream(s);
        return;
    }

    ngx_del_timer(c->write);

    ngx_log_debug0(
            NGX_LOG_DEBUG_STREAM, c->log, 0, "stream proxy connect upstream");

    if (ngx_nsoc_proxy_test_connect(c) != NGX_OK) {
        ngx_nsoc_proxy_next_upstream(s);
        return;
    }

    ngx_nsoc_proxy_init_upstream(s);
}

static ngx_int_t ngx_nsoc_proxy_test_connect(ngx_connection_t *c)
{
    int err;
    socklen_t len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
                == -1) {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static void ngx_nsoc_proxy_process(ngx_nsoc_session_t *s,
        ngx_uint_t from_upstream, ngx_uint_t do_write)
{
    off_t *received, limit;
    size_t size, limit_rate;
    ssize_t n;
    ngx_buf_t *b;
    ngx_int_t rc;
    ngx_uint_t flags;
    ngx_msec_t delay;
    ngx_chain_t *cl, **ll, **out, **busy;
    ngx_connection_t *c, *pc, *src, *dst;
    ngx_log_handler_pt handler;
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_proxy_srv_conf_t *pscf;

    u = s->upstream;

    c = s->connection;
    pc = u->connected ? u->peer.connection : NULL;

    if (c->type == SOCK_DGRAM && (ngx_terminate || ngx_exiting)) {

        /* socket is already closed on worker shutdown */

        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(NGX_LOG_INFO, c->log, 0, "disconnected on shutdown");

        c->log->handler = handler;

        ngx_nsoc_proxy_finalize(s, NGX_NSOC_OK);
        return;
    }

    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    if (from_upstream) {
        src = pc;
        dst = c;
        b = &u->upstream_buf;
        limit_rate = pscf->download_rate;
        received = &u->received;
        out = &u->downstream_out;
        busy = &u->downstream_busy;

    } else {
        src = c;
        dst = pc;
        b = &u->downstream_buf;
        limit_rate = pscf->upload_rate;
        received = &s->received;
        out = &u->upstream_out;
        busy = &u->upstream_busy;
    }

    for (;;) {

        if (do_write && dst) {

            if (*out || *busy || dst->buffered) {
                rc = ngx_nsoc_top_filter(s, *out, from_upstream);

                if (rc == NGX_ERROR) {
                    if (c->type == SOCK_DGRAM && !from_upstream) {
                        ngx_nsoc_proxy_next_upstream(s);
                        return;
                    }

                    ngx_nsoc_proxy_finalize(s, NGX_NSOC_OK);
                    return;
                }

                ngx_chain_update_chains(
                        c->pool, &u->free, busy, out,
                        (ngx_buf_tag_t) &ngx_nsoc_proxy_module);

                if (*busy == NULL) {
                    b->pos = b->start;
                    b->last = b->start;
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready && !src->read->delayed
                && !src->read->error) {
            if (limit_rate) {
                limit = (off_t) limit_rate * (ngx_time() - u->start_sec + 1)
                        - *received;

                if (limit <= 0) {
                    src->read->delayed = 1;
                    delay = (ngx_msec_t) (-limit * 1000 / limit_rate + 1);
                    ngx_add_timer(src->read, delay);
                    break;
                }

                if ((off_t) size > limit) {
                    size = (size_t) limit;
                }
            }

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == NGX_ERROR) {
                if (c->type == SOCK_DGRAM && u->received == 0) {
                    ngx_nsoc_proxy_next_upstream(s);
                    return;
                }

                src->read->eof = 1;
                n = 0;
            }

            if (n >= 0) {
                if (limit_rate) {
                    delay = (ngx_msec_t) (n * 1000 / limit_rate);

                    if (delay > 0) {
                        src->read->delayed = 1;
                        ngx_add_timer(src->read, delay);
                    }
                }

                if (from_upstream) {
                    if (u->state->first_byte_time == (ngx_msec_t) -1) {
                        u->state->first_byte_time = ngx_current_msec
                                - u->state->response_time;
                    }
                }

                if (c->type == SOCK_DGRAM
                        && ++u->responses == pscf->responses) {
                    src->read->ready = 0;
                    src->read->eof = 1;
                }

                for (ll = out; *ll; ll = &(*ll)->next) { /* void */
                }

                cl = ngx_chain_get_free_buf(c->pool, &u->free);
                if (cl == NULL) {
                    ngx_nsoc_proxy_finalize(s,
                    NGX_NSOC_INTERNAL_SERVER_ERROR);
                    return;
                }

                *ll = cl;

                cl->buf->pos = b->last;
                cl->buf->last = b->last + n;
                cl->buf->tag = (ngx_buf_tag_t) &ngx_nsoc_proxy_module;

                cl->buf->temporary = (n ? 1 : 0);
                cl->buf->last_buf = src->read->eof;
                cl->buf->flush = 1;

                *received += n;
                b->last += n;
                do_write = 1;

                continue;
            }
        }

        break;
    }

    if (src->read->eof && dst && (dst->read->eof || !dst->buffered)) {
        handler = c->log->handler;
        c->log->handler = NULL;

        ngx_log_error(
                NGX_LOG_INFO, c->log, 0, "%s%s disconnected"
                        ", bytes from/to client:%O/%O"
                        ", bytes from/to upstream:%O/%O",
                src->type == SOCK_DGRAM ? "udp " : "",
                from_upstream ? "upstream" : "client", s->received, c->sent,
                u->received, pc ? pc->sent : 0);

        c->log->handler = handler;

        ngx_nsoc_proxy_finalize(s, NGX_NSOC_OK);
        return;
    }

    flags = src->read->eof ? NGX_CLOSE_EVENT : 0;

    if (!src->shared && ngx_handle_read_event(src->read, flags) != NGX_OK) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    if (dst) {
        if (!dst->shared && ngx_handle_write_event(dst->write, 0) != NGX_OK) {
            ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
            return;
        }

        if (!c->read->delayed && !pc->read->delayed) {
            ngx_add_timer(c->write, pscf->timeout);

        } else if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
    }
}

static void ngx_nsoc_proxy_next_upstream(ngx_nsoc_session_t *s)
{
    ngx_msec_t timeout;
    ngx_connection_t *pc;
    ngx_nsoc_upstream_t *u;
    ngx_nsoc_proxy_srv_conf_t *pscf;

    ngx_log_debug0(
            NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "stream proxy next upstream");

    u = s->upstream;
    pc = u->peer.connection;

    if (u->upstream_out || u->upstream_busy || (pc && pc->buffered)) {
        ngx_log_error(
                NGX_LOG_ERR, s->connection->log, 0,
                "pending buffers on next upstream");
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, NGX_PEER_FAILED);
        u->peer.sockaddr = NULL;
    }

    pscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_proxy_module);

    timeout = pscf->next_upstream_timeout;

    if (u->peer.tries == 0 || !pscf->next_upstream
            || (timeout && ngx_current_msec - u->peer.start_time >= timeout)) {
        ngx_nsoc_proxy_finalize(s, NGX_NSOC_BAD_GATEWAY);
        return;
    }

    if (pc) {
        ngx_log_debug1(
                NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                "close proxy upstream connection: %d", pc->fd);

        u->state->bytes_received = u->received;
        u->state->bytes_sent = pc->sent;

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    ngx_nsoc_proxy_connect(s);
}

static void ngx_nsoc_proxy_finalize(ngx_nsoc_session_t *s, ngx_uint_t rc)
{
    ngx_connection_t *pc;
    ngx_nsoc_upstream_t *u;

    ngx_log_debug1(
            NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
            "finalize stream proxy: %i", rc);

    u = s->upstream;

    if (u == NULL) {
        goto noupstream;
    }

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    pc = u->peer.connection;

    if (u->state) {
        u->state->response_time = ngx_current_msec - u->state->response_time;

        if (pc) {
            u->state->bytes_received = u->received;
            u->state->bytes_sent = pc->sent;
        }
    }

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

    if (pc) {
        ngx_log_debug1(
                NGX_LOG_DEBUG_STREAM, s->connection->log, 0,
                "close stream proxy upstream connection: %d", pc->fd);

        ngx_close_connection(pc);
        u->peer.connection = NULL;
    }

    noupstream:

    ngx_nsoc_finalize_session(s, rc);
}

static u_char *
ngx_nsoc_proxy_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char *p;
    ngx_connection_t *pc;
    ngx_nsoc_session_t *s;
    ngx_nsoc_upstream_t *u;

    s = log->data;

    u = s->upstream;

    p = buf;

    if (u->peer.name) {
        p = ngx_snprintf(p, len, ", upstream: \"%V\"", u->peer.name);
        len -= p - buf;
    }

    pc = u->peer.connection;

    p = ngx_snprintf(
            p, len, ", bytes from/to client:%O/%O"
                    ", bytes from/to upstream:%O/%O", s->received,
            s->connection->sent, u->received, pc ? pc->sent : 0);

    return p;
}

static void *
ngx_nsoc_proxy_create_srv_conf(ngx_conf_t *cf)
{
    ngx_nsoc_proxy_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_nsoc_proxy_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_name = NULL;
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     *
     *     conf->ssl = NULL;
     *     conf->upstream = NULL;
     *     conf->upstream_value = NULL;
     */

    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->upload_rate = NGX_CONF_UNSET_SIZE;
    conf->download_rate = NGX_CONF_UNSET_SIZE;
    conf->responses = NGX_CONF_UNSET_UINT;
    conf->next_upstream_tries = NGX_CONF_UNSET_UINT;
    conf->next_upstream = NGX_CONF_UNSET;

    conf->local = NGX_CONF_UNSET_PTR;
    /*noise*/
    conf->noise_enable = NGX_CONF_UNSET;
    /*end noise*/

    return conf;
}

static char *
ngx_nsoc_proxy_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_nsoc_proxy_srv_conf_t *prev = parent;
    ngx_nsoc_proxy_srv_conf_t *conf = child;

    ngx_conf_merge_msec_value(
            conf->connect_timeout, prev->connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 10 * 60000);

    ngx_conf_merge_msec_value(
            conf->next_upstream_timeout, prev->next_upstream_timeout, 0);

    ngx_conf_merge_size_value(
            conf->buffer_size, prev->buffer_size, NOISE_PROTOCOL_PAYLOAD_SIZE);

    if (conf->buffer_size > NOISE_PROTOCOL_PAYLOAD_SIZE) {
        ngx_log_error(
                NGX_LOG_EMERG, cf->log, 0, "noise socket proxy buffer too big");
        return NGX_CONF_ERROR ;
    }

    ngx_conf_merge_size_value(conf->upload_rate, prev->upload_rate, 0);

    ngx_conf_merge_size_value(conf->download_rate, prev->download_rate, 0);

    ngx_conf_merge_uint_value(
            conf->responses, prev->responses, NGX_MAX_INT32_VALUE);

    ngx_conf_merge_uint_value(
            conf->next_upstream_tries, prev->next_upstream_tries, 0);

    ngx_conf_merge_value(conf->next_upstream, prev->next_upstream, 1);

    ngx_conf_merge_ptr_value(conf->local, prev->local, NULL);

    /*noise*/
    ngx_conf_merge_value(conf->noise_enable, prev->noise_enable, 0);

    ngx_conf_merge_str_value(
            conf->client_private_key_file, prev->client_private_key_file, "");
    ngx_conf_merge_str_value(
            conf->server_public_key_file, prev->server_public_key_file, "");

    if (conf->noise_enable && ngx_nsoc_proxy_set_noiselink(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR ;
    }

    /*end noise*/

    return NGX_CONF_OK;
}

/*noise*/

static ngx_int_t ngx_nsoc_proxy_set_noiselink(ngx_conf_t *cf,
        ngx_nsoc_proxy_srv_conf_t *pscf)
{
    ngx_pool_cleanup_t *cln;
    ngx_array_t *private_key, *public_key;
    ngx_str_t *key;

    pscf->noise = ngx_pcalloc(cf->pool, sizeof(ngx_noise_t));
    if (pscf->noise == NULL) {
        return NGX_ERROR;
    }

    pscf->noise->log = cf->log;

    if (ngx_nsoc_create(pscf->noise, pscf->buffer_size, NULL) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "noise proxy module merge_conf error: unable to create noise ctx");

        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_nsoc_cleanup_ctx;
    cln->data = pscf->noise;

    if (pscf->client_private_key_file.len == 0){
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "client private key file is not set");

        return NGX_ERROR;
    }

    if (pscf->server_public_key_file.len != 0) {
        public_key = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        key = public_key->elts;
        key->len = NOISE_PROTOCOL_CURVE25519_KEY_LEN;
        key->data = ngx_pnalloc(cf->pool, NOISE_PROTOCOL_CURVE25519_KEY_LEN);

        if (ngx_noise_protocol_load_public_key(
                pscf->server_public_key_file.data, key->data,
                NOISE_PROTOCOL_CURVE25519_KEY_LEN) != NGX_OK) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "unable to open server public key file %s",pscf->server_public_key_file.data);

            return NGX_ERROR;
        }

        public_key->nelts = 1;
        pscf->noise->ctx->public_keys = public_key;
    }

    private_key = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    key = private_key->elts;
    key->len = NOISE_PROTOCOL_CURVE25519_KEY_LEN;
    key->data = ngx_pnalloc(cf->pool, NOISE_PROTOCOL_CURVE25519_KEY_LEN);

    if (ngx_noise_protocol_load_private_key(
            pscf->client_private_key_file.data, key->data,
            NOISE_PROTOCOL_CURVE25519_KEY_LEN) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "unable to open client private key file %s",pscf->client_private_key_file.data);

        return NGX_ERROR;
    }

    private_key->nelts = 1;
    pscf->noise->ctx->private_keys = private_key;
    pscf->noise->handshake_timeout = pscf->connect_timeout;
    memcpy( pscf->noise->prologue.strPrologue,"NoiseSocketInit1",16);
    pscf->noise->prologue.header_len = swapw(NGX_NSOC_1MSG_NEG_DATA_SIZE);
    pscf->noise->prologue.header.version_id = NGX_NSOC_VERSION_ID;
    pscf->noise->prologue.header.cipher_id = (uint8_t)(NOISE_CIPHER_AESGCM & 0x0F);
    pscf->noise->prologue.header.dh_id = (uint8_t)(NOISE_DH_CURVE25519 & 0x0F);
    pscf->noise->prologue.header.hash_id = (uint8_t)(NOISE_HASH_BLAKE2b & 0x0F);
    pscf->noise->prologue.header.pattern_id = (uint8_t)(NOISE_PATTERN_XX & 0x0F);

    return NGX_OK;
}

/*end noise*/

static char *
ngx_nsoc_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_nsoc_proxy_srv_conf_t *pscf = conf;

    ngx_url_t u;
    ngx_str_t *value, *url;
    ngx_nsoc_complex_value_t cv;
    ngx_nsoc_core_srv_conf_t *cscf;
    ngx_nsoc_compile_complex_value_t ccv;

    if (pscf->upstream || pscf->upstream_value) {
        return "is duplicate";
    }

    cscf = ngx_nsoc_conf_get_module_srv_conf(cf, ngx_nsoc_core_module);

    cscf->handler = ngx_nsoc_proxy_handler;

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&ccv, sizeof(ngx_nsoc_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = url;
    ccv.complex_value = &cv;

    if (ngx_nsoc_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR ;
    }

    if (cv.lengths) {
        pscf->upstream_value = ngx_palloc(
                cf->pool, sizeof(ngx_nsoc_complex_value_t));
        if (pscf->upstream_value == NULL) {
            return NGX_CONF_ERROR ;
        }

        *pscf->upstream_value = cv;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = *url;
    u.no_resolve = 1;

    pscf->upstream = ngx_nsoc_upstream_add(cf, &u, 0);
    if (pscf->upstream == NULL) {
        return NGX_CONF_ERROR ;
    }

    return NGX_CONF_OK;
}

static char *
ngx_nsoc_proxy_bind(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_nsoc_proxy_srv_conf_t *pscf = conf;

    ngx_int_t rc;
    ngx_str_t *value;
    ngx_nsoc_complex_value_t cv;
    ngx_nsoc_upstream_local_t *local;
    ngx_nsoc_compile_complex_value_t ccv;

    if (pscf->local != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[1].data, "off") == 0) {
        pscf->local = NULL;
        return NGX_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_nsoc_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_nsoc_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR ;
    }

    local = ngx_pcalloc(cf->pool, sizeof(ngx_nsoc_upstream_local_t));
    if (local == NULL) {
        return NGX_CONF_ERROR ;
    }

    pscf->local = local;

    if (cv.lengths) {
        local->value = ngx_palloc(cf->pool, sizeof(ngx_nsoc_complex_value_t));
        if (local->value == NULL) {
            return NGX_CONF_ERROR ;
        }

        *local->value = cv;

    } else {
        local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
        if (local->addr == NULL) {
            return NGX_CONF_ERROR ;
        }

        rc = ngx_parse_addr_port(
                cf->pool, local->addr, value[1].data, value[1].len);

        switch (rc) {
            case NGX_OK:
                local->addr->name = value[1];
                break;

            case NGX_DECLINED:
                ngx_conf_log_error(
                NGX_LOG_EMERG, cf, 0, "invalid address \"%V\"", &value[1]);
                /* fall through */

            default:
                return NGX_CONF_ERROR ;
        }
    }

    if (cf->args->nelts > 2) {
        if (ngx_strcmp(value[2].data, "transparent") == 0) {
#if (NGX_HAVE_TRANSPARENT_PROXY)
            local->transparent = 1;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "transparent proxying is not supported "
                    "on this platform, ignored");
#endif
        } else {
            ngx_conf_log_error(
            NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR ;
        }
    }

    return NGX_CONF_OK;
}
