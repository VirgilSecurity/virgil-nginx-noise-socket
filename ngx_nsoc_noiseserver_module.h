/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */


#ifndef _NGX_NSOC_NOISESERVER_H_INCLUDED_
#define _NGX_NSOC_NOISESERVER_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_nsoc.h"

typedef struct {
        ngx_msec_t handshake_timeout;

        ngx_flag_t prefer_server_ciphers;
        ngx_noise_t *noise;
        char xor_symb;
} ngx_nsoc_noiseserver_conf_t;

extern ngx_module_t ngx_nsoc_noiseserver_module;

#endif /* _NGX_NSOC_NOISESERVER_H_INCLUDED_ */
