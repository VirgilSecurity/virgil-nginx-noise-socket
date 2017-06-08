/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#ifndef _NGX_NSOC_SCRIPT_H_INCLUDED_
#define _NGX_NSOC_SCRIPT_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_nsoc.h"

typedef struct {
        u_char *ip;
        u_char *pos;
        ngx_nsoc_variable_value_t *sp;

        ngx_str_t buf;
        ngx_str_t line;

        unsigned flushed :1;
        unsigned skip :1;

        ngx_nsoc_session_t *session;
} ngx_nsoc_script_engine_t;

typedef struct {
        ngx_conf_t *cf;
        ngx_str_t *source;

        ngx_array_t **flushes;
        ngx_array_t **lengths;
        ngx_array_t **values;

        ngx_uint_t variables;
        ngx_uint_t ncaptures;
        ngx_uint_t size;

        void *main;

        unsigned complete_lengths :1;
        unsigned complete_values :1;
        unsigned zero :1;
        unsigned conf_prefix :1;
        unsigned root_prefix :1;
} ngx_nsoc_script_compile_t;

typedef struct {
        ngx_str_t value;
        ngx_uint_t *flushes;
        void *lengths;
        void *values;
} ngx_nsoc_complex_value_t;

typedef struct {
        ngx_conf_t *cf;
        ngx_str_t *value;
        ngx_nsoc_complex_value_t *complex_value;

        unsigned zero :1;
        unsigned conf_prefix :1;
        unsigned root_prefix :1;
} ngx_nsoc_compile_complex_value_t;

typedef void (*ngx_nsoc_script_code_pt)(
        ngx_nsoc_script_engine_t *e);
typedef size_t (*ngx_nsoc_script_len_code_pt)(
        ngx_nsoc_script_engine_t *e);

typedef struct {
        ngx_nsoc_script_code_pt code;
        uintptr_t len;
} ngx_nsoc_script_copy_code_t;

typedef struct {
        ngx_nsoc_script_code_pt code;
        uintptr_t index;
} ngx_nsoc_script_var_code_t;

typedef struct {
        ngx_nsoc_script_code_pt code;
        uintptr_t n;
} ngx_nsoc_script_copy_capture_code_t;

typedef struct {
        ngx_nsoc_script_code_pt code;
        uintptr_t conf_prefix;
} ngx_nsoc_script_full_name_code_t;

void ngx_nsoc_script_flush_complex_value(ngx_nsoc_session_t *s,
        ngx_nsoc_complex_value_t *val);
ngx_int_t ngx_nsoc_complex_value(ngx_nsoc_session_t *s,
        ngx_nsoc_complex_value_t *val, ngx_str_t *value);
ngx_int_t ngx_nsoc_compile_complex_value(
        ngx_nsoc_compile_complex_value_t *ccv);
char *ngx_nsoc_set_complex_value_slot(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);

ngx_uint_t ngx_nsoc_script_variables_count(ngx_str_t *value);
ngx_int_t ngx_nsoc_script_compile(ngx_nsoc_script_compile_t *sc);
u_char *ngx_nsoc_script_run(ngx_nsoc_session_t *s,
        ngx_str_t *value, void *code_lengths, size_t reserved,
        void *code_values);
void ngx_nsoc_script_flush_no_cacheable_variables(
        ngx_nsoc_session_t *s, ngx_array_t *indices);

void *ngx_nsoc_script_add_code(ngx_array_t *codes, size_t size,
        void *code);

size_t ngx_nsoc_script_copy_len_code(ngx_nsoc_script_engine_t *e);
void ngx_nsoc_script_copy_code(ngx_nsoc_script_engine_t *e);
size_t ngx_nsoc_script_copy_var_len_code(
        ngx_nsoc_script_engine_t *e);
void ngx_nsoc_script_copy_var_code(ngx_nsoc_script_engine_t *e);
size_t ngx_nsoc_script_copy_capture_len_code(
        ngx_nsoc_script_engine_t *e);
void ngx_nsoc_script_copy_capture_code(
        ngx_nsoc_script_engine_t *e);

#endif /* _NGX_NSOC_SCRIPT_H_INCLUDED_ */
