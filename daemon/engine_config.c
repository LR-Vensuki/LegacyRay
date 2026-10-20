#include "engine_config.h"
#include "core/ws_path.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char *out;
    size_t cap;
    size_t len;
    int failed;
} eout_t;

static void put(eout_t *o, const char *text) {
    size_t n;
    if (o->failed || !text) return;
    n = strlen(text);
    if (n >= o->cap - o->len) {
        o->failed = 1;
        return;
    }
    memcpy(o->out + o->len, text, n + 1);
    o->len += n;
}

static void putf(eout_t *o, const char *format, ...) {
    int n;
    va_list ap;
    if (o->failed) return;
    va_start(ap, format);
    n = vsnprintf(o->out + o->len, o->cap - o->len, format, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= o->cap - o->len) {
        o->failed = 1;
        return;
    }
    o->len += (size_t)n;
}

/* a json string, which yaml reads as a double-quoted scalar */
static void put_str(eout_t *o, const char *value) {
    const unsigned char *p = (const unsigned char *)(value ? value : "");
    put(o, "\"");
    for (; !o->failed && *p; ++p) {
        char one[8];
        if (*p == '"' || *p == '\\') {
            one[0] = '\\';
            one[1] = (char)*p;
            one[2] = '\0';
        } else if (*p < 0x20 || *p == 0x7f) {
            snprintf(one, sizeof one, "\\u%04x", *p);
        } else {
            one[0] = (char)*p;
            one[1] = '\0';
        }
        put(o, one);
    }
    put(o, "\"");
}

static void put_key(eout_t *o, const char *key, const char *value) {
    put_str(o, key);
    put(o, ":");
    put_str(o, value);
}

static int is_vision(const vl_server_t *s) {
    return s->proto == VL_PROTO_VLESS && strncmp(s->flow, "xtls-rprx-vision", 16) == 0;
}

/* ciphers the engine implements, by the names links and xray use */
static int ss_cipher_known(const char *method) {
    static const char *known[] = {
        "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305", "2022-blake3-chacha20-ietf-poly1305", NULL
    };
    for (int i = 0; known[i]; ++i)
        if (strcmp(method, known[i]) == 0) return 1;
    return 0;
}

int engine_config_supports(const vl_server_t *s) {
    if (!s || !s->host[0] || !s->port) return 0;
    switch (s->proto) {
        case VL_PROTO_VLESS:
            /* xray's post-quantum vless encryption is a different wire format */
            if (s->encryption[0] && strcmp(s->encryption, "none") != 0) return 0;
            if (!s->uuid[0]) return 0;
            break;
        case VL_PROTO_TROJAN:
            if (!s->pass[0] || s->security == VL_SEC_NONE) return 0;
            break;
        case VL_PROTO_SHADOWSOCKS:
            return s->security == VL_SEC_NONE && s->net == VL_NET_TCP &&
                   s->pass[0] && ss_cipher_known(s->user);
        case VL_PROTO_HYSTERIA2:
            /* salamander is the one obfuscation the engine's client knows */
            if (!s->pass[0]) return 0;
            if (!s->obfs[0] || strcmp(s->obfs, "none") == 0) return 1;
            return strcmp(s->obfs, "salamander") == 0 && s->obfs_password[0];
        default:
            /* plain socks/http proxies need no engine */
            return 0;
    }
    if (s->security != VL_SEC_NONE && s->security != VL_SEC_TLS &&
        s->security != VL_SEC_REALITY)
        return 0;
    if (s->security == VL_SEC_REALITY && !s->pbk[0]) return 0;
    if (s->net != VL_NET_TCP && s->net != VL_NET_WS && s->net != VL_NET_XHTTP)
        return 0; /* grpc and h2 stay on the c core */
    if (is_vision(s) && (s->net != VL_NET_TCP || s->security == VL_SEC_NONE))
        return 0;
    return 1;
}

static void put_proxy(eout_t *o, const vl_server_t *s) {
    if (s->proto == VL_PROTO_TROJAN) {
        put(o, "{");
        put_key(o, "type", "trojan");
        put(o, ",");
        put_key(o, "password", s->pass);
        put(o, "}");
        return;
    }
    if (s->proto == VL_PROTO_SHADOWSOCKS) {
        const char *cipher = s->user;
        /* xray spells it without "ietf", the engine with it */
        if (strcmp(cipher, "2022-blake3-chacha20-poly1305") == 0)
            cipher = "2022-blake3-chacha20-ietf-poly1305";
        put(o, "{");
        put_key(o, "type", "shadowsocks");
        put(o, ",");
        put_key(o, "cipher", cipher);
        put(o, ",");
        put_key(o, "password", s->pass);
        put(o, "}");
        return;
    }
    put(o, "{");
    put_key(o, "type", "vless");
    put(o, ",");
    put_key(o, "user_id", s->uuid);
    put(o, "}");
}

static const char *tls_name(const vl_server_t *s) {
    return s->sni[0] ? s->sni : s->host;
}

/* the http host: the link's own, else the name the tls layer sends, as xray
   does. never the dial ip, which a cdn in front of the server would refuse */
static const char *http_host(const vl_server_t *s) {
    return s->ws_host[0] ? s->ws_host : tls_name(s);
}

static void put_opt(eout_t *o, const char *key, const char *value) {
    if (!value[0]) return;
    put(o, ",");
    put_key(o, key, value);
}

/* xray's newer request shaping, by the engine's names */
static void put_xh_shape(eout_t *o, const vl_server_t *s) {
    put_opt(o, "uplink_http_method", s->xh_method);
    put_opt(o, "uplink_data_placement", s->xh_data_place);
    put_opt(o, "uplink_data_key", s->xh_data_key);
    if (s->xh_chunk_max)
        putf(o, ",\"uplink_chunk_size\":\"%lu-%lu\"",
             (unsigned long)s->xh_chunk_min, (unsigned long)s->xh_chunk_max);
    put_opt(o, "session_placement", s->xh_sess_place);
    put_opt(o, "session_key", s->xh_sess_key);
    put_opt(o, "seq_placement", s->xh_seq_place);
    put_opt(o, "seq_key", s->xh_seq_key);
    if (s->xh_pad_obfs) {
        put(o, ",\"x_padding_obfs_mode\":true");
        put_opt(o, "x_padding_placement",
                strcmp(s->xh_pad_place, "queryInHeader") == 0 ? "query-in-header"
                                                               : s->xh_pad_place);
        put_opt(o, "x_padding_key", s->xh_pad_key);
        put_opt(o, "x_padding_header", s->xh_pad_header);
    }
    if (s->xh_gap_max)
        putf(o, ",\"sc_min_posts_interval_ms\":\"%lu-%lu\"",
             (unsigned long)s->xh_gap_min, (unsigned long)s->xh_gap_max);
}

/* the http layer between the security layer and the proxy protocol */
static void put_carrier(eout_t *o, const vl_server_t *s) {
    if (s->net == VL_NET_WS) {
        char path[sizeof s->path];
        ws_path_without_early_data(s->path, path, sizeof path);
        put(o, "{");
        put_key(o, "type", "websocket");
        put(o, ",");
        put_key(o, "matching_path", path);
        put(o, ",\"matching_headers\":{");
        put_key(o, "host", http_host(s));
        put(o, "},\"protocol\":");
        put_proxy(o, s);
        put(o, "}");
        return;
    }
    if (s->net == VL_NET_XHTTP) {
        const char *mode = "auto";
        if (strcmp(s->mode, "packet-up") == 0 || strcmp(s->mode, "stream-up") == 0 ||
            strcmp(s->mode, "stream-one") == 0)
            mode = s->mode;
        /* data outside the body and get uploads exist only in packet-up */
        if (strcmp(s->xh_data_place, "header") == 0 ||
            strcmp(s->xh_data_place, "cookie") == 0 || strcmp(s->xh_method, "GET") == 0)
            mode = "packet-up";
        put(o, "{");
        put_key(o, "type", "xhttp");
        put(o, ",");
        put_key(o, "path", s->path[0] ? s->path : "/");
        put(o, ",");
        put_key(o, "host", http_host(s));
        put(o, ",");
        put_key(o, "mode", mode);
        /* behind tls or reality xray speaks h2; in the clear, http/1.1 */
        put(o, ",");
        put_key(o, "http_version", s->security == VL_SEC_NONE ? "h1" : "h2");
        /* what the server holds its clients to, when the profile says */
        if (s->xh_pad_max)
            putf(o, ",\"x_padding_bytes\":\"%lu-%lu\"",
                 (unsigned long)s->xh_pad_min, (unsigned long)s->xh_pad_max);
        if (s->xh_post_max)
            putf(o, ",\"sc_max_each_post_bytes\":%lu", (unsigned long)s->xh_post_max);
        if (s->xh_no_grpc)
            put(o, ",\"no_grpc_header\":true");
        put_xh_shape(o, s);
        put(o, ",\"protocol\":");
        put_proxy(o, s);
        put(o, "}");
        return;
    }
    put_proxy(o, s);
}

static void put_security(eout_t *o, const vl_server_t *s) {
    if (s->security == VL_SEC_REALITY) {
        put(o, "{");
        put_key(o, "type", "reality");
        put(o, ",");
        put_key(o, "public_key", s->pbk);
        put(o, ",");
        put_key(o, "short_id", s->sid);
        put(o, ",");
        put_key(o, "sni_hostname", tls_name(s));
        putf(o, ",\"vision\":%s,\"protocol\":", is_vision(s) ? "true" : "false");
        put_carrier(o, s);
        put(o, "}");
        return;
    }
    if (s->security == VL_SEC_TLS) {
        put(o, "{");
        put_key(o, "type", "tls");
        put(o, ",");
        put_key(o, "sni_hostname", tls_name(s));
        putf(o, ",\"verify\":%s", s->insecure ? "false" : "true");
        /* what xray offers: h2 and http/1.1 by default, only http/1.1 for a
           websocket upgrade. for xhttp the engine offers exactly the http
           version it speaks (h2) and refuses any other list */
        if (s->net == VL_NET_WS)
            put(o, ",\"alpn_protocols\":[\"http/1.1\"]");
        else if (s->net == VL_NET_TCP)
            put(o, ",\"alpn_protocols\":[\"h2\",\"http/1.1\"]");
        putf(o, ",\"vision\":%s,\"protocol\":", is_vision(s) ? "true" : "false");
        put_carrier(o, s);
        put(o, "}");
        return;
    }
    put_carrier(o, s);
}

/* hysteria2 rides its own quic connection, so tls sits beside the protocol
   rather than around it. a pinned certificate is trusted on its own, as xray
   and hysteria trust it: those servers mostly carry a self-signed one */
static void put_hysteria2(eout_t *o, const vl_server_t *s) {
    put(o, "{");
    put_key(o, "type", "hysteria2");
    put(o, ",");
    put_key(o, "password", s->pass);
    if (s->obfs[0] && strcmp(s->obfs, "none") != 0) {
        put(o, ",");
        put_key(o, "salamander_password", s->obfs_password);
    }
    put(o, "},\"transport\":\"quic\",\"quic_settings\":{");
    put_key(o, "sni_hostname", tls_name(s));
    put(o, ",\"alpn_protocols\":[\"h3\"]");
    if (s->pin_sha256[0]) {
        /* comma separated sha256 digests, hex with or without colons
           (openssl's form). anything else, such as a second pin cut short
           by the profile's field, is left out rather than failing the start */
        const char *p = s->pin_sha256;
        int first = 1;
        put(o, ",\"verify\":false,\"server_fingerprints\":[");
        while (*p) {
            char hex[65];
            size_t n = 0;
            int bad = 0;
            for (; *p && *p != ','; ++p) {
                if (*p == ':' || *p == '-' || *p == ' ') continue;
                if (!isxdigit((unsigned char)*p) || n == 64) bad = 1;
                else hex[n++] = *p;
            }
            hex[n] = '\0';
            if (*p == ',') ++p;
            if (bad || n != 64) continue;
            if (!first) put(o, ",");
            put_str(o, hex);
            first = 0;
        }
        put(o, "]");
    } else {
        putf(o, ",\"verify\":%s", s->insecure ? "false" : "true");
    }
    put(o, "}");
}

int engine_config_render(const vl_server_t *s, const char *dial_ip,
                         int socks_port, char *out, size_t out_cap) {
    eout_t o;
    char address[96];
    if (!s || !dial_ip || !dial_ip[0] || !out || out_cap < 2 ||
        socks_port <= 0 || socks_port > 65535 || !engine_config_supports(s))
        return -1;
    o.out = out;
    o.cap = out_cap;
    o.len = 0;
    o.failed = 0;
    out[0] = '\0';
    if (strchr(dial_ip, ':'))
        snprintf(address, sizeof address, "[%s]:%u", dial_ip, (unsigned)s->port);
    else
        snprintf(address, sizeof address, "%s:%u", dial_ip, (unsigned)s->port);

    putf(&o, "[{\"address\":\"127.0.0.1:%d\",\"protocol\":{\"type\":\"socks\"},"
             "\"rules\":[{\"masks\":[\"0.0.0.0/0\",\"::/0\"],\"action\":\"allow\","
             "\"client_chain\":{", socks_port);
    put_key(&o, "address", address);
    put(&o, ",\"protocol\":");
    if (s->proto == VL_PROTO_HYSTERIA2)
        put_hysteria2(&o, s);
    else
        put_security(&o, s);
    put(&o, "}}]}]\n");
    return o.failed ? -1 : 0;
}
