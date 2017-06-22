/*
 * Copyright (C) Maxim Grigoryev
 * Copyright (C) Virgil Security, Inc.
 */

#ifndef _NGX_NOISE_PROTOCOL_H_INCLUDED_
#define _NGX_NOISE_PROTOCOL_H_INCLUDED_

#include <ngx_core.h>
#include <noise/protocol.h>

#define NOISE_PROTOCOL_CURVE25519_KEY_LEN 32
#define NOISE_PROTOCOL_CURVE448_KEY_LEN 56

#define NOISE_PROTOCOL_MAX_DH_KEY_LEN 2048
#define NOISE_PROTOCOL_PAYLOAD_SIZE 65519
#define NOISE_PROTOCOL_MAC_DATA_SIZE 16
#define NOISE_PROTOCOL_MAX_HANDSHAKE_LEN NOISE_PROTOCOL_CURVE25519_KEY_LEN*2+NOISE_PROTOCOL_MAC_DATA_SIZE*2

typedef struct noise_ctx_st {
        ngx_array_t *private_keys;
        ngx_array_t *public_keys;
} NOISE_CTX;

typedef enum {
    NGX_NSOC_UNSET_ROLE = -1,
    NGX_NSOC_CLIENT_ROLE,
    NGX_NSOC_SERVER_ROLE
} ngx_noise_role_e;

typedef struct noise_protocol_conn_s {
        NoiseHandshakeState *NoiseHandshakeObj;
        NoiseCipherState *NoiseSendCipherObj;
        NoiseCipherState *NoiseRecvCipherObj;
        NoiseRandState *NoiseRandObj;
        void *NoisePrologue;
        ngx_int_t NoisePrologueLen;
} noise_protocol_conn_t;

ngx_int_t ngx_noise_protocol_init_handshake(NOISE_CTX *noise_ctx,
        noise_protocol_conn_t *noise_conn, ngx_noise_role_e noise_role);
ngx_int_t ngx_noise_protocol_load_private_key(const unsigned char *filename,
        uint8_t *key, size_t len);
ngx_int_t ngx_noise_protocol_load_public_key(const unsigned char *filename, uint8_t *key,
        size_t len);
void ngx_noise_protocol_log_error(ngx_int_t err, char* strError, ngx_log_t *log,
        ngx_uint_t log_level);
#endif
