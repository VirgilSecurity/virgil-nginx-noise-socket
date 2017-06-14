/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_nsoc.h"

typedef ngx_int_t (*ngx_noise_variable_handler_pt)(ngx_connection_t *c,
        ngx_pool_t *pool, ngx_str_t *s);

#define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NGX_DEFAULT_ECDH_CURVE  "auto"

static ngx_int_t ngx_nsoc_noiseserver_handler(
        ngx_nsoc_session_t *s);
static ngx_int_t ngx_nsoc_noiseserver_init_connection(ngx_noise_t *noise,
        ngx_connection_t *c);
static void ngx_nsoc_noiseserver_handshake_handler(ngx_connection_t *c);
//static ngx_int_t ngx_nsoc_noiseserver_static_variable(ngx_nsoc_session_t *s,
//        ngx_nsoc_variable_value_t *v, uintptr_t data);
//static ngx_int_t ngx_nsoc_noiseserver_variable(ngx_nsoc_session_t *s,
//        ngx_nsoc_variable_value_t *v, uintptr_t data);
//
//static ngx_int_t ngx_nsoc_noiseserver_add_variables(ngx_conf_t *cf);
static void *ngx_nsoc_noiseserver_create_conf(ngx_conf_t *cf);
static char *ngx_nsoc_noiseserver_merge_conf(ngx_conf_t *cf,
        void *parent, void *child);

static ngx_int_t ngx_nsoc_noiseserver_init(ngx_conf_t *cf);

static ngx_command_t ngx_nsoc_noiseserver_commands[] =
{

  { ngx_string("noise_handshake_timeout"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_msec_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, handshake_timeout),
    NULL },

  { ngx_string("server_private_key_file"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, server_private_key_file),
    NULL },

  { ngx_string("client_public_key_file"),
    NGX_NSOC_MAIN_CONF | NGX_NSOC_SRV_CONF | NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_NSOC_SRV_CONF_OFFSET,
    offsetof(ngx_nsoc_noiseserver_conf_t, client_public_key_file),
    NULL },

  ngx_null_command
};

static ngx_nsoc_module_t ngx_nsoc_noiseserver_module_ctx =
{ //ngx_nsoc_noiseserver_add_variables, /* preconfiguration */
  NULL,/* preconfiguration */
  ngx_nsoc_noiseserver_init, /* postconfiguration */

  NULL, /* create main configuration */
  NULL, /* init main configuration */

  ngx_nsoc_noiseserver_create_conf, /* create server configuration */
  ngx_nsoc_noiseserver_merge_conf /* merge server configuration */
};

ngx_module_t ngx_nsoc_noiseserver_module =
{
  NGX_MODULE_V1,
  &ngx_nsoc_noiseserver_module_ctx, /* module context */
  ngx_nsoc_noiseserver_commands, /* module directives */
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

//static ngx_nsoc_variable_t ngx_nsoc_noiseserver_vars[] =
//{
//
//  { ngx_string("noise_protocol"),
//    NULL,
//    ngx_nsoc_noiseserver_static_variable,
//    (uintptr_t) ngx_ssl_get_protocol,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_cipher"),
//    NULL,
//    ngx_nsoc_noiseserver_static_variable,
//    (uintptr_t) ngx_ssl_get_cipher_name,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_ciphers"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_ciphers,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_curves"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_curves,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_session_id"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_session_id,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_session_reused"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_session_reused,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_server_name"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_server_name,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_cert"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_certificate,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_raw_cert"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_raw_certificate,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_s_dn"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_subject_dn,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_i_dn"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_issuer_dn,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_serial"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_serial_number,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_fingerprint"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_fingerprint,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_verify"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_client_verify,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_v_start"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_client_v_start,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_v_end"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_client_v_end,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_string("noise_client_v_remain"),
//    NULL,
//    ngx_nsoc_noiseserver_variable,
//    (uintptr_t) ngx_ssl_get_client_v_remain,
//    NGX_NSOC_VAR_CHANGEABLE,
//    0 },
//
//  { ngx_null_string,
//    NULL,
//    NULL,
//    0,
//    0,
//    0 }
//};

//static ngx_str_t ngx_nsoc_noiseserver_sess_id_ctx = ngx_string("NOISE");

static ngx_int_t ngx_nsoc_noiseserver_handler(
        ngx_nsoc_session_t *s)
{
    // long                    rc;
    //X509                   *cert;
    ngx_int_t rv;
    ngx_connection_t *c;
    ngx_nsoc_noiseserver_conf_t *noisecf;

    if (!s->noise_on) {
        return NGX_OK;
    }

    c = s->connection;

    noisecf = ngx_nsoc_get_module_srv_conf(
            s, ngx_nsoc_noiseserver_module);

    if (s->server_noise_connection == NULL) {
        c->log->action = "NOISE handshaking";
        rv = ngx_nsoc_noiseserver_init_connection(noisecf->noise, c);

        if (rv != NGX_OK) {
            return rv;
        }
    }

    return NGX_OK;
}

static ngx_int_t ngx_nsoc_noiseserver_init_connection(ngx_noise_t *noise,
        ngx_connection_t *c)
{
    ngx_int_t rc;
    ngx_nsoc_session_t *s;

    s = c->data;

    if (ngx_nsoc_create_connection(noise, c, 0) == NGX_ERROR) {
        return NGX_ERROR;
    }

    rc = ngx_nsoc_handshake(c);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_AGAIN) {

        s->server_noise_connection->handler =
                ngx_nsoc_noiseserver_handshake_handler;

        return NGX_AGAIN;
    }

    return NGX_OK;
}

static void ngx_nsoc_noiseserver_handshake_handler(ngx_connection_t *c)
{
    ngx_nsoc_session_t *s;

    s = c->data;

    if (!s->server_noise_connection->handshaked) {
        ngx_nsoc_finalize_session(s, NGX_NSOC_INTERNAL_SERVER_ERROR);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    ngx_nsoc_core_run_phases(s);
}

//static ngx_int_t ngx_nsoc_noiseserver_static_variable(
//        ngx_nsoc_session_t *s, ngx_nsoc_variable_value_t *v,
//        uintptr_t data)
//{
//    ngx_noise_variable_handler_pt handler = (ngx_noise_variable_handler_pt) data;
//
//    size_t len;
//    ngx_str_t str;
//
//    if (s->noise_on) {
//
//        (void) handler(s->connection, NULL, &str);
//
//        v->data = str.data;
//
//        for (len = 0; v->data[len]; len++) { /* void */
//        }
//
//        v->len = len;
//        v->valid = 1;
//        v->no_cacheable = 0;
//        v->not_found = 0;
//
//        return NGX_OK;
//    }
//
//    v->not_found = 1;
//
//    return NGX_OK;
//}
//
//static ngx_int_t ngx_nsoc_noiseserver_variable(
//        ngx_nsoc_session_t *s, ngx_nsoc_variable_value_t *v,
//        uintptr_t data)
//{
//    ngx_noise_variable_handler_pt handler = (ngx_noise_variable_handler_pt) data;
//
//    ngx_str_t str;
//
//    if (s->noise_on) {
//
//        if (handler(s->connection, s->connection->pool, &str) != NGX_OK) {
//            return NGX_ERROR;
//        }
//
//        v->len = str.len;
//        v->data = str.data;
//
//        if (v->len) {
//            v->valid = 1;
//            v->no_cacheable = 0;
//            v->not_found = 0;
//
//            return NGX_OK;
//        }
//    }
//
//    v->not_found = 1;
//
//    return NGX_OK;
//}
//
//static ngx_int_t ngx_nsoc_noiseserver_add_variables(ngx_conf_t *cf)
//{
//    ngx_nsoc_variable_t *var, *v;
//
//    for (v = ngx_nsoc_noiseserver_vars; v->name.len; v++) {
//        var = ngx_nsoc_add_variable(cf, &v->name, v->flags);
//        if (var == NULL) {
//            return NGX_ERROR;
//        }
//
//        var->get_handler = v->get_handler;
//        var->data = v->data;
//    }
//
//    return NGX_OK;
//}

static void *
ngx_nsoc_noiseserver_create_conf(ngx_conf_t *cf)
{
    ngx_nsoc_noiseserver_conf_t *noisecf;

    noisecf = ngx_pcalloc(cf->pool, sizeof(ngx_nsoc_noiseserver_conf_t));
    if (noisecf == NULL) {
        return NULL;
    }

    noisecf->handshake_timeout = NGX_CONF_UNSET_MSEC;

    return noisecf;
}

static char *
ngx_nsoc_noiseserver_merge_conf(ngx_conf_t *cf, void *parent,
        void *child)
{
    ngx_nsoc_noiseserver_conf_t *prev = parent;
    ngx_nsoc_noiseserver_conf_t *conf = child;

    ngx_pool_cleanup_t *cln;

    ngx_conf_merge_msec_value(
            conf->handshake_timeout, prev->handshake_timeout, 60000);

    ngx_conf_merge_str_value(conf->server_private_key_file, prev->server_private_key_file, "");
    ngx_conf_merge_str_value(conf->client_public_key_file, prev->client_public_key_file, "");

    conf->noise = ngx_pcalloc(cf->pool, sizeof(ngx_noise_t));
    if (conf->noise == NULL) {
        return NGX_CONF_ERROR ;
    }

    conf->noise->log = cf->log;

    if (ngx_nsoc_create(conf->noise, NULL) != NGX_OK) {
        return NGX_CONF_ERROR ;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR ;
    }

    cln->handler = ngx_nsoc_cleanup_ctx;
    cln->data = conf->noise;

    return NGX_CONF_OK;
}

static ngx_int_t ngx_nsoc_noiseserver_init(ngx_conf_t *cf)
{
    ngx_nsoc_handler_pt *h;
    ngx_nsoc_core_main_conf_t *cmcf;
    ngx_nsoc_noiseserver_conf_t *noisecf;
    ngx_array_t *private_key,*public_key;
    ngx_str_t *key;

    noisecf = ngx_nsoc_conf_get_module_srv_conf(
            cf, ngx_nsoc_noiseserver_module);

    if (noisecf->server_private_key_file.len == 0)
        return NGX_ERROR ;

    private_key = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    key = private_key->elts;
    key->len = NOISE_PROTOCOL_CURVE25519_KEY_LEN;
    key->data = ngx_pnalloc(cf->pool, NOISE_PROTOCOL_CURVE25519_KEY_LEN);
    if (ngx_noise_protocol_load_private_key(
            noisecf->server_private_key_file.data, key->data,
            NOISE_PROTOCOL_CURVE25519_KEY_LEN) != NGX_OK) {
        return NGX_ERROR;
    }
    private_key->nelts=1;
    noisecf->noise->ctx->private_keys = private_key;

    if (noisecf->client_public_key_file.len != 0) {
        public_key = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
        key = public_key->elts;
        key->len = NOISE_PROTOCOL_CURVE25519_KEY_LEN;
        key->data = ngx_pnalloc(
                cf->pool, NOISE_PROTOCOL_CURVE25519_KEY_LEN);
        if (ngx_noise_protocol_load_public_key(
                noisecf->client_public_key_file.data, key->data,
                NOISE_PROTOCOL_CURVE25519_KEY_LEN) != NGX_OK) {
            return NGX_ERROR;
        }
        public_key->nelts = 1;
        noisecf->noise->ctx->public_keys = public_key;
    }
    cmcf = ngx_nsoc_conf_get_module_main_conf(cf, ngx_nsoc_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_NSOC_PROTECT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_nsoc_noiseserver_handler;

    return NGX_OK;
}
