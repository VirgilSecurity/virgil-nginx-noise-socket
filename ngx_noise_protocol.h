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
#define NOISE_PROTOCOL_PAYLOAD_SIZE 65517
#define NOISE_PROTOCOL_MAC_DATA_SIZE 16
#define NOISE_PROTOCOL_MAX_HANDSHAKE_LEN NOISE_PROTOCOL_CURVE25519_KEY_LEN*2+NOISE_PROTOCOL_MAC_DATA_SIZE*2

#define swapw(x)((((uint16_t)x & 0xFF00)>>8)| (((uint16_t)x & 0x00FF)<<8))

typedef struct noise_ctx_st {
        ngx_array_t *private_keys;
        ngx_array_t *public_keys;
} NOISE_CTX;

typedef enum {
    NGX_NLNK_UNSET_ROLE = -1,
    NGX_NLNK_CLIENT_ROLE,
    NGX_NLNK_SERVER_ROLE
} ngx_noise_role_e;

#pragma pack(push, 1)
typedef struct noise_handshake_first_hdr_s {
	uint16_t version_id;
	uint8_t pattern_id;
	uint8_t dh_id;
	uint8_t cipher_id;
	uint8_t hash_id;
}noise_handshake_first_hdr_t;

typedef struct noise_handshake_second_hdr_s {
	uint16_t version_id;
	uint8_t status;
}noise_handshake_second_hdr_t;

typedef struct noise_handshake_third_hdr_s {
	uint16_t version_id;
}noise_handshake_third_hdr_t;

typedef struct noise_prologue_data_s {
	uint8_t strPrologue[13];
	uint16_t header_len;
	noise_handshake_first_hdr_t header;
}noise_prologue_data_t;

typedef struct noise_prologue_fallback_data_t {
    uint8_t strPrologue[15];
    noise_prologue_data_t first_msg;
    uint16_t header_len;
    noise_handshake_first_hdr_t header;
}noise_prologue_fallback_data_t;
#pragma pack (pop)

typedef struct noise_protocol_conn_s {
        NoiseHandshakeState *NoiseHandshakeObj;
        NoiseCipherState *NoiseSendCipherObj;
        NoiseCipherState *NoiseRecvCipherObj;
        NoiseRandState *NoiseRandObj;
        void *NoisePrologue;
        ngx_int_t NoisePrologueLen;
        NoiseProtocolId protocol_id;
} noise_protocol_conn_t;

ngx_int_t ngx_noise_protocol_init_handshake(NOISE_CTX *noise_ctx,
        noise_protocol_conn_t *noise_conn, noise_prologue_data_t *prologue_data, ngx_noise_role_e noise_role);
ngx_int_t ngx_noise_protocol_load_private_key(const unsigned char *filename,
        uint8_t *key, size_t len);
ngx_int_t ngx_noise_protocol_load_public_key(const unsigned char *filename, uint8_t *key,
        size_t len);
void ngx_noise_protocol_log_error(ngx_int_t err, char* strError, ngx_log_t *log,
        ngx_uint_t log_level);
#endif
