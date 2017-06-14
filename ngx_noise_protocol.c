
#include "ngx_noise_protocol.h"

static const char strProtocolName[]="Noise_XX_25519_AESGCM_SHA256";
static const char strPrologue[]="Virgil";

ngx_int_t ngx_noise_protocol_init_handshake(NOISE_CTX *noise_ctx,
        noise_protocol_conn_t *noise_conn, ngx_noise_role_e noise_role)
{
    ngx_int_t err;
    NoiseDHState *dh;
    size_t key_len = 0;
    ngx_int_t role;

    if ((noise_role != NGX_NSOC_CLIENT_ROLE)
            && (noise_role != NGX_NSOC_SERVER_ROLE))
        return NGX_ERROR;
    if (noise_init() != NOISE_ERROR_NONE) return NGX_ERROR;

    noise_conn->NoisePrologue = (void *) strPrologue;
    noise_conn->NoisePrologueLen = sizeof(strPrologue)-1;

    if (noise_role == NGX_NSOC_CLIENT_ROLE) {
        role = NOISE_ROLE_INITIATOR;
    } else {
        role = NOISE_ROLE_RESPONDER;
    }

    err = noise_handshakestate_new_by_name(
            &noise_conn->NoiseHandshakeObj, strProtocolName, role);
    if (err != NOISE_ERROR_NONE)
        return NGX_ERROR;

    err = noise_handshakestate_set_prologue(
            noise_conn->NoiseHandshakeObj, noise_conn->NoisePrologue,
            noise_conn->NoisePrologueLen);
    if (err != NOISE_ERROR_NONE)
        return NGX_ERROR;

    if (noise_handshakestate_needs_local_keypair(
            noise_conn->NoiseHandshakeObj)) {
        dh = noise_handshakestate_get_local_keypair_dh(
                noise_conn->NoiseHandshakeObj);
        key_len = noise_dhstate_get_private_key_length(dh);
        err = noise_dhstate_set_keypair_private(
                dh, noise_ctx->private_keys->elts, key_len);
        if (err != NOISE_ERROR_NONE)
            return NGX_ERROR;
    }

    if (noise_handshakestate_needs_remote_public_key(
            noise_conn->NoiseHandshakeObj)) {
        dh = noise_handshakestate_get_remote_public_key_dh(
                noise_conn->NoiseHandshakeObj);
        key_len = noise_dhstate_get_public_key_length(dh);
        err = noise_dhstate_set_public_key(
                dh, noise_ctx->public_keys->elts, key_len);
        if (err != NOISE_ERROR_NONE)
            return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t ngx_noise_protocol_load_private_key(const unsigned char *filename,
        uint8_t *key, size_t len)
{
    FILE *file = fopen((const char *)filename, "rb");
    size_t posn = 0;
    int ch;
    if (len > NOISE_PROTOCOL_MAX_DH_KEY_LEN) {
        return NGX_ERROR;
    }
    if (!file) {
        return NGX_ERROR;
    }
    while ((ch = getc(file)) != EOF) {
        if (posn >= len) {
            fclose(file);
            return NGX_ERROR;
        }
        key[posn++] = (uint8_t) ch;
    }
    if (posn < len) {
        fclose(file);
        return NGX_ERROR;
    }
    fclose(file);
    return NGX_OK;
}

ngx_int_t ngx_noise_protocol_load_public_key(const unsigned char *filename, uint8_t *key,
        size_t len)
{
    FILE *file = fopen((const char *)filename, "rb");
    uint32_t group = 0;
    size_t group_size = 0;
    uint32_t digit = 0;
    size_t posn = 0;
    int ch;
    if (len > NOISE_PROTOCOL_MAX_DH_KEY_LEN) {
        return NGX_ERROR;
    }
    if (!file) {
        return NGX_ERROR;
    }
    while ((ch = getc(file)) != EOF) {
        if (ch >= 'A' && ch <= 'Z') {
            digit = ch - 'A';
        } else if (ch >= 'a' && ch <= 'z') {
            digit = ch - 'a' + 26;
        } else if (ch >= '0' && ch <= '9') {
            digit = ch - '0' + 52;
        } else if (ch == '+') {
            digit = 62;
        } else if (ch == '/') {
            digit = 63;
        } else if (ch == '=') {
            break;
        } else if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            fclose(file);
            return NGX_ERROR;
        }
        group = (group << 6) | digit;
        if (++group_size >= 4) {
            if ((len - posn) < 3) {
                fclose(file);
                return NGX_ERROR;
            }
            group_size = 0;
            key[posn++] = (uint8_t) (group >> 16);
            key[posn++] = (uint8_t) (group >> 8);
            key[posn++] = (uint8_t) group;
        }
    }
    if (group_size == 3) {
        if ((len - posn) < 2) {
            fclose(file);
            return NGX_ERROR;
        }
        key[posn++] = (uint8_t) (group >> 10);
        key[posn++] = (uint8_t) (group >> 2);
    } else if (group_size == 2) {
        if ((len - posn) < 1) {
            fclose(file);
            return NGX_ERROR;
        }
        key[posn++] = (uint8_t) (group >> 4);
    }
    if (posn < len) {
        fclose(file);
        return NGX_ERROR;
    }
    fclose(file);
    return NGX_OK;
}
