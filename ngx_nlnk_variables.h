/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_NLNK_VARIABLES_H_INCLUDED_
#define _NGX_NLNK_VARIABLES_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_nlnk.h"

typedef ngx_variable_value_t ngx_nlnk_variable_value_t;

#define ngx_nlnk_variable(v)     { sizeof(v) - 1, 1, 0, 0, 0, (u_char *) v }

typedef struct ngx_nlnk_variable_s ngx_nlnk_variable_t;

typedef void (*ngx_nlnk_set_variable_pt)(ngx_nlnk_session_t *s,
        ngx_nlnk_variable_value_t *v, uintptr_t data);
typedef ngx_int_t (*ngx_nlnk_get_variable_pt)(
        ngx_nlnk_session_t *s, ngx_nlnk_variable_value_t *v,
        uintptr_t data);

#define NGX_NLNK_VAR_CHANGEABLE   1
#define NGX_NLNK_VAR_NOCACHEABLE  2
#define NGX_NLNK_VAR_INDEXED      4
#define NGX_NLNK_VAR_NOHASH       8
#define NGX_NLNK_VAR_WEAK         16
#define NGX_NLNK_VAR_PREFIX       32

struct ngx_nlnk_variable_s {
        ngx_str_t name; /* must be first to build the hash */
        ngx_nlnk_set_variable_pt set_handler;
        ngx_nlnk_get_variable_pt get_handler;
        uintptr_t data;
        ngx_uint_t flags;
        ngx_uint_t index;
};

ngx_nlnk_variable_t *ngx_nlnk_add_variable(ngx_conf_t *cf,
        ngx_str_t *name, ngx_uint_t flags);
ngx_int_t ngx_nlnk_get_variable_index(ngx_conf_t *cf, ngx_str_t *name);
ngx_nlnk_variable_value_t *ngx_nlnk_get_indexed_variable(
        ngx_nlnk_session_t *s, ngx_uint_t index);
ngx_nlnk_variable_value_t *ngx_nlnk_get_flushed_variable(
        ngx_nlnk_session_t *s, ngx_uint_t index);

ngx_nlnk_variable_value_t *ngx_nlnk_get_variable(
        ngx_nlnk_session_t *s, ngx_str_t *name, ngx_uint_t key);

#if (NGX_PCRE)

typedef struct {
        ngx_uint_t capture;
        ngx_int_t index;
} ngx_nlnk_regex_variable_t;

typedef struct {
        ngx_regex_t *regex;
        ngx_uint_t ncaptures;
        ngx_nlnk_regex_variable_t *variables;
        ngx_uint_t nvariables;
        ngx_str_t name;
} ngx_nlnk_regex_t;

typedef struct {
        ngx_nlnk_regex_t *regex;
        void *value;
} ngx_nlnk_map_regex_t;

ngx_nlnk_regex_t *ngx_nlnk_regex_compile(ngx_conf_t *cf,
        ngx_regex_compile_t *rc);
ngx_int_t ngx_nlnk_regex_exec(ngx_nlnk_session_t *s,
        ngx_nlnk_regex_t *re, ngx_str_t *str);

#endif

typedef struct {
        ngx_hash_combined_t hash;
#if (NGX_PCRE)
        ngx_nlnk_map_regex_t *regex;
        ngx_uint_t nregex;
#endif
} ngx_nlnk_map_t;

void *ngx_nlnk_map_find(ngx_nlnk_session_t *s,
        ngx_nlnk_map_t *map, ngx_str_t *match);

ngx_int_t ngx_nlnk_variables_add_core_vars(ngx_conf_t *cf);
ngx_int_t ngx_nlnk_variables_init_vars(ngx_conf_t *cf);

extern ngx_nlnk_variable_value_t ngx_nlnk_variable_null_value;
extern ngx_nlnk_variable_value_t ngx_nlnk_variable_true_value;

#endif /* _NGX_NLNK_VARIABLES_H_INCLUDED_ */
