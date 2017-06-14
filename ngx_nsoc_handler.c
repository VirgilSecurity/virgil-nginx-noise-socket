/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include "ngx_nsoc.h"

static void ngx_nsoc_log_session(ngx_nsoc_session_t *s);
static void ngx_nsoc_close_connection(ngx_connection_t *c);
static u_char *ngx_nsoc_log_error(ngx_log_t *log, u_char *buf, size_t len);

static void ngx_nsoc_cleanup_connection_pool(void *data);
static ngx_int_t ngx_nsoc_read_handshake_data(ngx_connection_t *c,
        ngx_buf_t **buf, size_t buffer_size);
static ngx_int_t ngx_nsoc_do_handshake_process(ngx_connection_t *c,
        ngx_noise_connection_t *nc);
static void ngx_nsoc_handshake_handler(ngx_event_t *ev);

void ngx_nsoc_cleanup_ctx(void *data)
{
    ngx_noise_t *noise = data;
    ngx_str_t   *keys;
    ngx_uint_t   i;

    if (noise->ctx != NULL) {
        if (noise->ctx->private_keys != NULL) {
            keys=noise->ctx->private_keys->elts;
            for (i = 0; i < noise->ctx->private_keys->nelts; i++) {
                ngx_memzero(keys[i].data, keys[i].len);
            }
            ngx_array_destroy(noise->ctx->private_keys);
        }
        if (noise->ctx->public_keys != NULL) {
            keys=noise->ctx->public_keys->elts;
            for (i = 0; i < noise->ctx->public_keys->nelts; i++) {
                ngx_memzero(keys[i].data, keys[i].len);
            }
            ngx_array_destroy(noise->ctx->public_keys);
        }
        ngx_free(noise->ctx);
        noise->ctx = NULL;
    }
}

ngx_int_t ngx_nsoc_create(ngx_noise_t *noise, void *data)
{
    noise->buffer_size = NGX_NSOC_BUFSIZE;
    noise->ctx = ngx_calloc(sizeof(NOISE_CTX), noise->log);
    if (noise->ctx == NULL)
        return NGX_ERROR;
    return NGX_OK;
}

static void ngx_nsoc_cleanup_connection_pool(void *data)
{
    ngx_noise_connection_t **nc = data;
    noise_protocol_conn_t *npc=&((*nc)->noise_connection);
    if (npc != NULL) {
        if (npc->NoiseHandshakeObj != NULL) {
            noise_handshakestate_free(npc->NoiseHandshakeObj);
        }
        if (npc->NoiseSendCipherObj != NULL) {
            noise_cipherstate_free(npc->NoiseSendCipherObj);
        }
        if (npc->NoiseRecvCipherObj != NULL) {
            noise_cipherstate_free(npc->NoiseRecvCipherObj);
        }
        if (npc->NoiseRandObj != NULL) {
            noise_randstate_free(npc->NoiseRandObj);
        }
    }
    *nc = NULL;
}

ngx_int_t ngx_nsoc_create_connection(ngx_noise_t *noise, ngx_connection_t *c,
        ngx_uint_t flags)
{
    ngx_noise_connection_t *nc;
    ngx_pool_cleanup_t *cln;
    ngx_nsoc_session_t *s;

    s = c->data;

    nc = ngx_pcalloc(c->pool, sizeof(ngx_noise_connection_t));
    if (nc == NULL) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_nsoc_cleanup_connection_pool;

    nc->buffer = ((flags & NGX_NSOC_BUFFER) != 0);
    nc->buffer_size = noise->buffer_size;

    nc->noise_ctx = noise->ctx;

    nc->connection = c;

    nc->handshake_phase = NGX_NSOC_HANDSHAKE_NONE_PHASE;
    nc->last = 0;

    if (flags & NGX_NSOC_CLIENT) {
        nc->noise_role = NGX_NSOC_CLIENT_ROLE;

        s->client_noise_connection = nc;
        cln->data = &s->client_noise_connection;

    } else {
        nc->noise_role = NGX_NSOC_SERVER_ROLE;
        s->server_noise_connection = nc;
        cln->data = &s->server_noise_connection;
    }

    return NGX_OK;
}

static ngx_int_t ngx_nsoc_read_handshake_data(ngx_connection_t *c,
        ngx_buf_t **buf, size_t buffer_size)
{
    size_t size;
    ssize_t n;
    ngx_buf_t *b = *buf;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, buffer_size);
        if (b == NULL) {
            return NGX_ERROR;
        }
    }

    *buf = b;
    size = b->end - b->last;
    if (size == 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0, "NOISE preread buffer full");
        return NGX_ERROR;
    }
    if (c->read->eof) {
        return NGX_OK;
    }

    n = ngx_recv(c, b->last, size);

    if (n >= 0) {
        b->last += n;
        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }
    }

    return n;
}

ngx_int_t ngx_nsoc_handshake(ngx_connection_t *c)
{
    ngx_nsoc_session_t *s;

    s = c->data;
    if (s->client_noise_connection != NULL
            && s->client_noise_connection->connection == c) {
        return ngx_nsoc_do_handshake_process(c, s->client_noise_connection);
    } else if (s->server_noise_connection != NULL
            && s->server_noise_connection->connection == c) {
        return ngx_nsoc_do_handshake_process(c, s->server_noise_connection);
    }
    return NGX_ERROR;
}


static ngx_int_t ngx_nsoc_do_handshake_process(ngx_connection_t *c,
        ngx_noise_connection_t *nc)
{
    ngx_noise_handshake_phases_e *hp;
    ngx_buf_t *b;
    ssize_t n, size;
    ngx_int_t action = 0;
    NoiseBuffer mbuf;
    ngx_nsoc_core_srv_conf_t *cscf;
    ngx_nsoc_session_t *s;

    s = c->data;
    cscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_core_module);

    hp = &nc->handshake_phase;

    for (;;) {
        switch (*hp) {
            case NGX_NSOC_HANDSHAKE_NONE_PHASE:

                ngx_log_debug1(
                        NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE handshake start: %d",
                        nc->noise_role);

                n = ngx_noise_protocol_init_handshake(
                        nc->noise_ctx, &nc->noise_connection, nc->noise_role);
                if (n == NGX_ERROR)
                    return n;

                n = noise_handshakestate_start(
                        nc->noise_connection.NoiseHandshakeObj);
                if (n == NGX_ERROR)
                    return n;
                *hp = NGX_NSOC_HANDSHAKE_PROCESS_PHASE;
                nc->last = 0;

            case NGX_NSOC_HANDSHAKE_PROCESS_PHASE:
                if (nc->last == NOISE_ACTION_WRITE_MESSAGE) {

                    ngx_log_debug1(
                            NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE handshake write again start: %d",
                            nc->noise_role);

                    b = nc->buf;
                    nc->last = 0;
                    goto m_write_action;

                } else if (nc->last == NOISE_ACTION_READ_MESSAGE) {

                    ngx_log_debug1(
                            NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE handshake read again start: %d",
                            nc->noise_role);

                    nc->last = 0;
                    goto m_start_read_action;

                }

                action = noise_handshakestate_get_action(
                        nc->noise_connection.NoiseHandshakeObj);

                ngx_log_debug1(
                        NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE handshake process: %d",
                        nc->noise_role);

                if (action == NOISE_ACTION_WRITE_MESSAGE) {

                    ngx_log_debug0(
                            NGX_LOG_DEBUG_EVENT, c->log, 0,
                            "NOISE handshake process action write");

                    b = ngx_calloc_buf(c->pool);
                    if (b == NULL) {
                        return NGX_ERROR;
                    }
                    b->memory = 1;
                    b->start = b->pos = ngx_pcalloc(c->pool, NGX_NSOC_BUFSIZE);
                    b->end = b->last = b->pos + NGX_NSOC_BUFSIZE;
                    b->last_buf = 1;

                    noise_buffer_set_output(mbuf, b->pos + 2, NGX_NSOC_BUFSIZE-2);
                    n = noise_handshakestate_write_message(
                            nc->noise_connection.NoiseHandshakeObj, &mbuf,
                            NULL);
                    if (n != NOISE_ERROR_NONE)
                        return n;

                    b->pos[0] = (uint8_t) (mbuf.size >> 8);
                    b->pos[1] = (uint8_t) mbuf.size;
                    b->last = b->pos + mbuf.size + 2;

m_write_action:
                    size = b->last - b->pos;

                    n = c->send(c, b->pos, size);

                    if ((n == NGX_AGAIN) || (n < size)) {
                        c->write->ready = 0;
                        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                            return NGX_ERROR;
                        }
                        nc->buf = b;
                        nc->last = NOISE_ACTION_WRITE_MESSAGE;

                        ngx_log_debug0(
                                NGX_LOG_DEBUG_EVENT, c->log, 0,
                                "NOISE handshake process action write again");
                    } else {
                        c->read->ready = 0;
                        nc->buf = NULL;
                    }
                    c->read->handler = ngx_nsoc_handshake_handler;
                    c->write->handler = ngx_nsoc_handshake_handler;

                    action = noise_handshakestate_get_action(
                                            nc->noise_connection.NoiseHandshakeObj);

                    if (action == NOISE_ACTION_READ_MESSAGE) {
                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_ERROR;
                        }
                        if (!c->read->timer_set) {
                            ngx_add_timer(c->read, cscf->preread_timeout);
                        }
                        return NGX_AGAIN;
                    }
                    else {

                        if (c->read->timer_set) {
                            ngx_del_timer(c->read);
                        }
                        continue;
                    }

                } else if (action == NOISE_ACTION_READ_MESSAGE) {

                    ngx_log_debug0(
                            NGX_LOG_DEBUG_EVENT, c->log, 0,
                            "NOISE handshake process action read");

m_start_read_action:
                    c->read->ready = 1;
                    c->read->available = 1;
                    c->read->handler = ngx_nsoc_handshake_handler;
                    c->write->handler = ngx_nsoc_handshake_handler;

                    n = ngx_nsoc_read_handshake_data(
                            c, &nc->buf, nc->buffer_size);
                    if (n == NGX_AGAIN) {
                        ngx_log_debug0(
                                NGX_LOG_DEBUG_EVENT, c->log, 0,
                                "NOISE handshake read ServerHello again");
                        nc->last = NOISE_ACTION_READ_MESSAGE;
                        return NGX_AGAIN;
                    }
                    if (n == NGX_ERROR) {
                        c->read->eof = 1;
                        return NGX_ERROR;
                    }
                    size = ((ssize_t) (nc->buf->start[0]) << 8)
                            | ((ssize_t) (nc->buf->start[1]));
                    if (n - 2 < size) {
                        nc->last = NOISE_ACTION_READ_MESSAGE;
                        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                            return NGX_ERROR;
                        }
                        if (!c->read->timer_set) {
                            ngx_add_timer(c->read, cscf->preread_timeout);
                        }
                        return NGX_AGAIN;
                    }
                    noise_buffer_set_input(mbuf, nc->buf->start + 2, size);
                    n = noise_handshakestate_read_message(
                            nc->noise_connection.NoiseHandshakeObj, &mbuf,
                            NULL);
                    if (n != NOISE_ERROR_NONE)
                        return NGX_ERROR;

                    nc->last = 0;
                    continue;

                } else if (action == NOISE_ACTION_SPLIT) {

                    ngx_log_debug1(
                            NGX_LOG_DEBUG_EVENT, c->log, 0,
                            "NOISE handshake end success: %d", nc->noise_role);

                    n = noise_handshakestate_split(
                            nc->noise_connection.NoiseHandshakeObj,
                            &nc->noise_connection.NoiseSendCipherObj,
                            &nc->noise_connection.NoiseRecvCipherObj);

                    noise_handshakestate_free(
                            nc->noise_connection.NoiseHandshakeObj);
                    nc->noise_connection.NoiseHandshakeObj = NULL;

                    if (n != NOISE_ERROR_NONE)
                        return NGX_ERROR;

                    *hp = NGX_NSOC_HANDSHAKE_END_PHASE;

                    if(nc->buf!=NULL){
                        nc->buf->flush = 1;
                        nc->buf->pos = nc->buf->start;
                        nc->buf->last = nc->buf->start;
                    }

                    nc->handshaked = 1;

                    c->sent = 0;
                    c->recv = ngx_nsoc_recv;
                    c->send = ngx_nsoc_write;
                    c->recv_chain = ngx_nsoc_recv_chain;
                    c->send_chain = ngx_nsoc_send_chain;

                    return NGX_OK;

                } else
                    return NGX_ERROR;
            default:
                break;
        }
    }
    return NGX_ERROR;
}

static void ngx_nsoc_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t *c;
    ngx_nsoc_session_t *s;
    ngx_noise_connection_t *nc;

    c = ev->data;
    s = c->data;

    if (s->client_noise_connection != NULL
            && s->client_noise_connection->connection == c) {
        nc = s->client_noise_connection;
    } else if (s->server_noise_connection != NULL
            && s->server_noise_connection->connection == c) {
        nc = s->server_noise_connection;
    } else
        return;

    ngx_log_debug1(
            NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE handshake handler: %d",
            ev->write);

    if (ev->timedout) {
        ngx_log_debug0(
                NGX_LOG_DEBUG_EVENT, c->log, 0,
                "NOISE handshake handler: timedout");
        nc->handler(c);
        return;
    }

    if (ngx_nsoc_handshake(c) == NGX_AGAIN) {
        return;
    }

    nc->handler(c);
}

ngx_int_t ngx_nsoc_shutdown(ngx_connection_t *c)
{
    return NGX_OK;
}

ssize_t ngx_nsoc_recv_chain(ngx_connection_t *c, ngx_chain_t *cl, off_t limit)
{
    u_char *last;
    ssize_t n, bytes, size;
    ngx_buf_t *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for (;;) {
        size = b->end - last;

        if (limit) {
            if (bytes >= limit) {
                return bytes;
            }

            if (bytes + size > limit) {
                size = (ssize_t) (limit - bytes);
            }
        }

        n = c->recv(c, last, size);

        if (n > 0) {
            last += n;
            bytes += n;

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {

            if (n == 0 || n == NGX_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}

ssize_t ngx_nsoc_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int n;
    ngx_nsoc_session_t *s;
    ngx_noise_connection_t *nc;
    NoiseBuffer mbuf;
    ngx_buf_t *b;
    s = c->data;

    if (s->client_noise_connection != NULL
            && s->client_noise_connection->connection == c) {
        nc = s->client_noise_connection;
    } else if (s->server_noise_connection != NULL
            && s->server_noise_connection->connection == c) {
        nc = s->server_noise_connection;
    } else
        return NGX_ERROR;

    if (nc->last == NGX_ERROR) {
        c->read->error = 1;
        return NGX_ERROR;
    }

    c->read->ready = 1;
    for (;;) {
        if(nc->recv_buf == NULL) {
            b = ngx_create_temp_buf(c->pool, nc->buffer_size);
            if (b == NULL) {
                return NGX_ERROR;
            }
            b->temporary = 0;
            nc->recv_buf = b;
        } else {
            b = nc->recv_buf;
        }
        n = ngx_recv(c, b->pos, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE_read: %d", n);

        if (n > 0) {
            if (nc->last == 0) {
                nc->recv_size = ((ssize_t) (b->start[0]) << 8)
                        | ((ssize_t) (b->start[1]));
            }
            if (n == nc->recv_size + 2) {
                noise_buffer_set_inout(mbuf, b->start+2, nc->recv_size, size);
                n = noise_cipherstate_decrypt(
                        nc->noise_connection.NoiseRecvCipherObj, &mbuf);
                if (n != NOISE_ERROR_NONE)
                    return NGX_ERROR;
                ngx_memcpy(buf, mbuf.data, mbuf.size);
                c->read->ready = 1;
                return mbuf.size;
            }
            nc->last = n;
            c->read->ready = 0;
            return NGX_AGAIN;
        }
        if (n == NGX_AGAIN) {
            c->read->ready = 0;
        }
        break;
    }
    return n;
}

ngx_chain_t *
ngx_nsoc_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int n;
    ngx_uint_t flush;
    ssize_t send, size;
    ngx_buf_t *buf;
    ngx_nsoc_session_t *s;
    ngx_noise_connection_t *nc;

    s = c->data;

    if (s->client_noise_connection != NULL
            && s->client_noise_connection->connection == c) {
        nc = s->client_noise_connection;
    } else if (s->server_noise_connection != NULL
            && s->server_noise_connection->connection == c) {
        nc = s->server_noise_connection;
    } else
        return NGX_CHAIN_ERROR ;

    if (!nc->buffer) {

        while (in) {
            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = c->send(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR ;
            }

            if (n == NGX_AGAIN) {
                return in;
            }

            in->buf->pos += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }

    /* the maximum limit size is the maximum int32_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_INT32_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_INT32_VALUE - ngx_pagesize;
    }

    buf = nc->buf;

    if (buf == NULL) {
        buf = ngx_create_temp_buf(c->pool, nc->buffer_size);
        if (buf == NULL) {
            return NGX_CHAIN_ERROR ;
        }

        nc->buf = buf;
    }

    if (buf->start == NULL) {
        buf->start = ngx_palloc(c->pool, nc->buffer_size);
        if (buf->start == NULL) {
            return NGX_CHAIN_ERROR ;
        }

        buf->pos = buf->start;
        buf->last = buf->start;
        buf->end = buf->start + nc->buffer_size;
    }

    send = buf->last - buf->pos;
    flush = (in == NULL) ? 1 : buf->flush;

    for (;;) {

        while (in && buf->last < buf->end && send < limit) {
            if (in->buf->last_buf || in->buf->flush) {
                flush = 1;
            }

            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
            }

            ngx_log_debug1(
                    NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE buf copy: %z", size);

            ngx_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;
            in->buf->pos += size;
            send += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        if (!flush && send < limit && buf->last < buf->end) {
            break;
        }

        size = buf->last - buf->pos;

        if (size == 0) {
            buf->flush = 0;
            c->buffered &= ~NGX_NSOC_BUFFERED;
            return in;
        }

        n = c->send(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR ;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        buf->pos += n;

        if (n < size) {
            break;
        }

        flush = 0;

        buf->pos = buf->start;
        buf->last = buf->start;

        if (in == NULL || send == limit) {
            break;
        }
    }

    buf->flush = flush;

    if (buf->pos < buf->last) {
        c->buffered |= NGX_NSOC_BUFFERED;

    } else {
        c->buffered &= ~NGX_NSOC_BUFFERED;
    }

    return in;
}

ssize_t ngx_nsoc_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int n;
    ngx_nsoc_session_t *s;
    ngx_noise_connection_t *nc;
    ngx_buf_t *b;
    NoiseBuffer mbuf;

    s = c->data;

    if (s->client_noise_connection != NULL
            && s->client_noise_connection->connection == c) {
        nc = s->client_noise_connection;
    } else if (s->server_noise_connection != NULL
            && s->server_noise_connection->connection == c) {
        nc = s->server_noise_connection;
    } else
        return NGX_ERROR;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE to write: %uz", size);

    if (size > NOISE_PROTOCOL_PAYLOAD_SIZE)
        return NGX_ERROR;

    if (nc->send_buf == NULL)
    {
        b = ngx_calloc_buf(c->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }

        b->memory = 1;
        b->start = ngx_pcalloc(c->pool, NGX_NSOC_BUFSIZE);
        if (b->start == NULL) {
            return NGX_ERROR;
        }

        b->pos = b->start + 2;
        b->end = b->start + NGX_NSOC_BUFSIZE;
        b->last_buf = 1;

        ngx_memcpy(b->pos, data, size);

        noise_buffer_set_inout(mbuf, b->pos, size, NGX_NSOC_BUFSIZE-2);
        n  = noise_cipherstate_encrypt(nc->noise_connection.NoiseSendCipherObj, &mbuf);
        if (n != NOISE_ERROR_NONE)
            return NGX_ERROR;

        b->last = b->pos + mbuf.size;
        b->start[0] = (uint8_t)(mbuf.size >> 8);
        b->start[1] = (uint8_t)mbuf.size;
        b->pos = b->start;

    } else {
        b=nc->send_buf;
    }

    size = b->last - b->pos;
    n = ngx_send(c, b->pos, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "NOISE_write: %d", n);

    if ((n == NGX_AGAIN) || (n < (ssize_t)mbuf.size + 2))
    {
        b->pos += n;
        nc->send_buf = b;
        nc->send_size = mbuf.size + 2;

    }

    if (n > 0) {
        c->sent += n;
    }

    return n;

}

char *
ngx_nsoc_conf_set_char_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;

    ngx_str_t *value;
    char *field;
    ngx_conf_post_t *post;

    field = (char *) (p + cmd->offset);

    if (*field != -1) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[1].data[0];

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

void ngx_nsoc_init_connection(ngx_connection_t *c)
{
    u_char text[NGX_SOCKADDR_STRLEN];
    size_t len;
    ngx_uint_t i;
    ngx_time_t *tp;
    ngx_event_t *rev;
    struct sockaddr *sa;
    ngx_nsoc_port_t *port;
    struct sockaddr_in *sin;
    ngx_nsoc_in_addr_t *addr;
    ngx_nsoc_session_t *s;
    ngx_nsoc_addr_conf_t *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
    ngx_nsoc_in6_addr_t *addr6;
#endif
    ngx_nsoc_core_srv_conf_t *cscf;
    ngx_nsoc_core_main_conf_t *cmcf;

    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() and recvmsg() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_nsoc_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) sa;

                addr6 = port->addrs;

                /* the last address is "*" */

                for (i = 0; i < port->naddrs - 1; i++) {
                    if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16)
                            == 0) {
                        break;
                    }
                }

                addr_conf = &addr6[i].conf;

                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) sa;

                addr = port->addrs;

                /* the last address is "*" */

                for (i = 0; i < port->naddrs - 1; i++) {
                    if (addr[i].addr == sin->sin_addr.s_addr) {
                        break;
                    }
                }

                addr_conf = &addr[i].conf;

                break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                addr6 = port->addrs;
                addr_conf = &addr6[0].conf;
                break;
#endif

            default: /* AF_INET */
                addr = port->addrs;
                addr_conf = &addr[0].conf;
                break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_nsoc_session_t));
    if (s == NULL) {
        ngx_nsoc_close_connection(c);
        return;
    }

    s->signature = NGX_NSOC_MODULE;
    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    /*noise*/
    s->noise_on = addr_conf->noise_on;
    /*end noise*/

    if (c->buffer) {
        s->received += c->buffer->last - c->buffer->pos;
    }

    s->connection = c;
    c->data = s;

    cscf = ngx_nsoc_get_module_srv_conf(s, ngx_nsoc_core_module);

    ngx_set_connection_log(c, cscf->error_log);

    len = ngx_sock_ntop(c->sockaddr, c->socklen, text, NGX_SOCKADDR_STRLEN, 1);

    ngx_log_error(
            NGX_LOG_INFO, c->log, 0, "*%uA %sclient %*s connected to %V",
            c->number, c->type == SOCK_DGRAM ? "udp " : "", len, text,
            &addr_conf->addr_text);

    c->log->connection = c->number;
    c->log->handler = ngx_nsoc_log_error;
    c->log->data = s;
    c->log->action = "initializing session";
    c->log_error = NGX_ERROR_INFO;

    s->ctx = ngx_pcalloc(c->pool, sizeof(void *) * ngx_nsoc_max_module);
    if (s->ctx == NULL) {
        ngx_nsoc_close_connection(c);
        return;
    }

    cmcf = ngx_nsoc_get_module_main_conf(s, ngx_nsoc_core_module);

    s->variables = ngx_pcalloc(
            s->connection->pool,
            cmcf->variables.nelts * sizeof(ngx_nsoc_variable_value_t));

    if (s->variables == NULL) {
        ngx_nsoc_close_connection(c);
        return;
    }

    tp = ngx_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;

    rev = c->read;
    rev->handler = ngx_nsoc_session_handler;

    if (ngx_use_accept_mutex) {
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }

    rev->handler(rev);
}


void ngx_nsoc_session_handler(ngx_event_t *rev)
{
    ngx_connection_t *c;
    ngx_nsoc_session_t *s;

    c = rev->data;
    s = c->data;

    ngx_nsoc_core_run_phases(s);
}

void ngx_nsoc_finalize_session(ngx_nsoc_session_t *s, ngx_uint_t rc)
{
    ngx_log_debug1(
            NGX_LOG_DEBUG_EVENT, s->connection->log, 0,
            "finalize stream session: %i", rc);

    s->status = rc;

    ngx_nsoc_log_session(s);

    ngx_nsoc_close_connection(s->connection);
}

static void ngx_nsoc_log_session(ngx_nsoc_session_t *s)
{
    ngx_uint_t i, n;
    ngx_nsoc_handler_pt *log_handler;
    ngx_nsoc_core_main_conf_t *cmcf;

    cmcf = ngx_nsoc_get_module_main_conf(s, ngx_nsoc_core_module);

    log_handler = cmcf->phases[NGX_NSOC_LOG_PHASE].handlers.elts;
    n = cmcf->phases[NGX_NSOC_LOG_PHASE].handlers.nelts;

    for (i = 0; i < n; i++) {
        log_handler[i](s);
    }
}

static void ngx_nsoc_close_connection(ngx_connection_t *c)
{
    ngx_pool_t *pool;
    ngx_nsoc_session_t *s;
    ngx_noise_connection_t *nc;

    ngx_log_debug1(
            NGX_LOG_DEBUG_EVENT, c->log, 0, "close stream connection: %d",
            c->fd);

    s = c->data;
    if (s->noise_on) {
        if (s->client_noise_connection != NULL
                && s->client_noise_connection->connection == c) {
            nc = s->client_noise_connection;
        } else if (s->server_noise_connection != NULL
                && s->server_noise_connection->connection == c) {
            nc = s->server_noise_connection;
        } else
            return;

        if (ngx_nsoc_shutdown(c) == NGX_AGAIN) {
            nc->handler = ngx_nsoc_close_connection;
            return;
        }
    }

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}

static u_char *
ngx_nsoc_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char *p;
    ngx_nsoc_session_t *s;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    s = log->data;

    p = ngx_snprintf(
            buf, len, ", %sclient: %V, server: %V",
            s->connection->type == SOCK_DGRAM ? "udp " : "",
            &s->connection->addr_text, &s->connection->listening->addr_text);
    len -= p - buf;
    buf = p;

    if (s->log_handler) {
        p = s->log_handler(log, buf, len);
    }

    return p;
}
