/* select xhttp stream mode and keep upload and download framing compatible */
#include "transport.h"
#include "grpc_core.h"
#include "hpack.h"
#include "reality_handshake.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#define XH_RX   (64 * 1024)
#define XH_TX   (32 * 1024)
#define XH_APP  (64 * 1024)
#define XH_PKT  16384 /* max packet-up body: one data frame at the default size */
#define XH_PATH 2048  /* base, session, sequence, query and padding */
/* packet-up posts in flight at once. xray's server holds at most 30 posts
   that wait for the upstream and others refuse more, so stay well under */
#define XH_POSTS 16

enum {
    H2_DATA = 0, H2_HEADERS = 1, H2_RST_STREAM = 3, H2_SETTINGS = 4,
    H2_PING = 6, H2_GOAWAY = 7, H2_WINDOW_UPDATE = 8, H2_CONTINUATION = 9
};

enum { H2_FLAG_END_STREAM = 0x01, H2_FLAG_END_HEADERS = 0x04, H2_FLAG_PADDED = 0x08 };

enum { XH_MODE_ONE = 0, XH_MODE_UP = 1, XH_MODE_PKT = 2 };

enum {
    XH_ST_BOOT = 0,
    XH_ST_OPEN,
    XH_ST_FAIL
};

typedef struct {
    const transport_vt_t *sub_vt;
    void                 *sub_h;
    int                   mode;
    int                   state;
    int                   saw_settings;
    int                   peer_end;
    int                   security_tls; /* 1 if tls/reality (scheme https) */
    int                   grpc; /* use the xray gRPC stream envelope */
    int                   stream_ct; /* grpc content type on streamed requests */
    size_t                pad_min, pad_max; /* x_padding length range */
    size_t                pkt_max; /* largest packet-up body */

/* http/2 response header assembly and failure reporting */
    int                   hdr_wait; /* expecting CONTINUATION */
    uint8_t               hdr_blk[4096]; /* xray pads responses with up to 1000 bytes */
    size_t                hdr_len;
    int                   we_end; /* our END_STREAM queued */
    int                   saw_status;
    char                  last_err[128];

    uint32_t peer_win, our_win;
    uint32_t up_peer_win, up_our_win; /* upload stream windows */
    uint32_t dn_peer_win, dn_our_win; /* download stream windows */
    uint32_t up_stream; /* continuous upload stream id */
    uint32_t dn_stream; /* download stream id */
    uint32_t next_sid; /* next client stream id (odd) */
    int64_t  seq;

    char host[256];
    char base_path[256]; /* normalized base, trailing / */
    char query[256];     /* query of the configured path, sent on every request */
    char session[48];
    uint32_t peer_init_win; /* the peer's initial stream window */
    uint32_t peer_max_streams;
    uint32_t posts[XH_POSTS]; /* packet-up posts the server has not finished */
    int      posts_open;

    uint8_t tx[XH_TX];
    size_t  tx_len, tx_off;
    uint8_t rx[XH_RX];
    size_t  rx_len, rx_off;
    uint8_t app[XH_APP];
    size_t  app_len, app_off;
    uint8_t grpc_rx[XH_APP];
    size_t  grpc_rx_len;
} xh_t;

static int h2_u24(const uint8_t *p) {
    return ((int)p[0] << 16) | ((int)p[1] << 8) | (int)p[2];
}
static void h2_put_u24(uint8_t *p, int v) {
    p[0] = (uint8_t)((v >> 16) & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)(v & 0xff);
}
static void h2_put_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}
static uint32_t h2_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int tx_append(xh_t *h, const uint8_t *p, size_t n) {
    if (n > sizeof h->tx - h->tx_len) return -1;
    memcpy(h->tx + h->tx_len, p, n);
    h->tx_len += n;
    return 0;
}

/* record the failure at the owning boundary and fail the connection */
static int h2_fail(xh_t *h, const char *reason) {
    if (h->state == XH_ST_FAIL) return TRANSPORT_ERR;
    snprintf(h->last_err, sizeof h->last_err, "%s", reason);
    fprintf(stderr, "legacyrayd: http2: %s\n", reason);
    h->state = XH_ST_FAIL;
    return TRANSPORT_ERR;
}

static const char *h2_error_name(uint32_t code) {
    switch (code) {
        case 0:  return "no error";
        case 1:  return "protocol error";
        case 2:  return "internal error";
        case 3:  return "flow control error";
        case 7:  return "refused stream";
        case 8:  return "cancel";
        case 10: return "remote refused";
        case 11: return "cancel by peer";
        case 12: return "compression error";
        case 13: return "connection error";
        default: return "http/2 error";
    }
}

static int frame_append(xh_t *h, uint8_t type, uint8_t flags,
                        uint32_t stream, const uint8_t *payload, size_t plen) {
    if (plen > 0xffffff || 9 + plen > sizeof h->tx - h->tx_len) return -1;
    uint8_t hdr[9];
    h2_put_u24(hdr, (int)plen);
    hdr[3] = type; hdr[4] = flags;
    h2_put_u32(hdr + 5, stream & 0x7fffffffu);
    if (tx_append(h, hdr, 9) != 0) return -1;
    if (plen && tx_append(h, payload, plen) != 0) return -1;
    return 0;
}

/* hpack integer with an n-bit prefix (rfc 7541 5.1); first carries the
   pattern bits above the prefix */
static int hpack_int(uint8_t *out, size_t cap, size_t *off,
                     unsigned bits, uint8_t first, size_t v) {
    size_t max = ((size_t)1 << bits) - 1;
    if (*off >= cap) return -1;
    if (v < max) {
        out[(*off)++] = (uint8_t)(first | v);
        return 0;
    }
    out[(*off)++] = (uint8_t)(first | max);
    v -= max;
    for (;;) {
        if (*off >= cap) return -1;
        if (v < 128) {
            out[(*off)++] = (uint8_t)v;
            return 0;
        }
        out[(*off)++] = (uint8_t)(0x80 | (v & 0x7f));
        v >>= 7;
    }
}

static int hpack_str(uint8_t *out, size_t cap, size_t *off, const char *s) {
    size_t n = strlen(s);
    if (hpack_int(out, cap, off, 7, 0x00, n) != 0 || n > cap - *off) return -1;
    memcpy(out + *off, s, n);
    *off += n;
    return 0;
}

static int hpack_lit(uint8_t *out, size_t cap, size_t *off,
                     const char *name, const char *val) {
    if (*off >= cap) return -1;
    out[(*off)++] = 0x00;
    if (hpack_str(out, cap, off, name) != 0) return -1;
    return hpack_str(out, cap, off, val);
}

/* literal without indexing, name from the static table */
static int hpack_idx_name(uint8_t *out, size_t cap, size_t *off,
                          uint8_t name_idx, const char *val) {
    if (hpack_int(out, cap, off, 4, 0x00, name_idx) != 0) return -1;
    return hpack_str(out, cap, off, val);
}

/* xray servers refuse a request whose x_padding is outside their
   xPaddingBytes, 100-1000 bytes unless the profile says otherwise; like xray,
   pick a length in that range. the cap keeps a request inside XH_PATH */
#define XH_PAD_MIN 100
#define XH_PAD_MAX 1000
#define XH_PAD_CAP 1400

static size_t rand_pad_len(const xh_t *h) {
    uint8_t rb[2];
    size_t span = h->pad_max - h->pad_min + 1;
    if (RAND_bytes(rb, 2) != 1) return h->pad_min;
    return h->pad_min + (((size_t)rb[0] << 8) | rb[1]) % span;
}

static void gen_session_id(char out[48]) {
/* use a uuid-shaped session id so common servers accept the request */
    uint8_t b[16];
    if (RAND_bytes(b, 16) != 1) memset(b, 0x11, 16);
    b[6] = (uint8_t)((b[6] & 0x0f) | 0x40);
    b[8] = (uint8_t)((b[8] & 0x3f) | 0x80);
    snprintf(out, 48,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

/* the base keeps a trailing / except for grpc, whose path is the method:
   xray serves xhttp under "<path>/" and answers 404 to "<path>" itself. a
   query in the configured path goes on every request, as in xray */
static void normalize_base_path(const char *raw, char *out, size_t cap,
                                char *query, size_t qcap, int trail) {
    if (!raw || !raw[0]) raw = "/";
    if (raw[0] == '/')
        snprintf(out, cap, "%s", raw);
    else
        snprintf(out, cap, "/%s", raw);
    char *q = strchr(out, '?');
    query[0] = 0;
    if (q) {
        snprintf(query, qcap, "%s", q + 1);
        *q = 0;
    }
    size_t n = strlen(out);
    if (trail && n + 1 < cap && (n == 0 || out[n - 1] != '/')) {
        out[n] = '/'; out[n + 1] = 0;
    }
}

/* pick mode knowing which open_* was used */
/* auto follows xray: stream-one over reality, packet-up otherwise, since
   cdns in front of tls servers buffer a streamed upload */
static int mode_for_open(const transport_tls_cfg_t *cfg, int reality) {
    const char *m = (cfg && cfg->xhttp_mode) ? cfg->xhttp_mode : "";
    if (!m[0] || strcmp(m, "auto") == 0)
        return reality ? XH_MODE_ONE : XH_MODE_PKT;
    if (strcmp(m, "stream-up") == 0) return XH_MODE_UP;
    if (strcmp(m, "packet-up") == 0) return XH_MODE_PKT;
    return XH_MODE_ONE;
}

/* :authority before :path, the order every real client and grpc-go's own
   stack produce. a real grpc stream also says te: trailers, which grpc-go's
   server checks before it looks at :path */
static int build_headers(uint8_t *out, size_t cap, size_t *n,
                         int is_post, const char *path, const char *host,
                         int with_grpc, size_t content_len, int has_cl,
                         int is_https, int te_trailers, const char *referer) {
    size_t off = 0;
    if (is_post) out[off++] = 0x83; /* post method */
    else         out[off++] = 0x82; /* get method */
    out[off++] = is_https ? 0x87 : 0x86; /* :scheme https/http */
    if (hpack_idx_name(out, cap, &off, 1, host) != 0) return -1;
    if (hpack_idx_name(out, cap, &off, 4, path) != 0) return -1;
    if (with_grpc) {
        if (hpack_lit(out, cap, &off, "content-type", "application/grpc") != 0)
            return -1;
    }
    if (te_trailers) {
        if (hpack_lit(out, cap, &off, "te", "trailers") != 0) return -1;
    }
    if (has_cl) {
        char cl[16];
        snprintf(cl, sizeof cl, "%zu", content_len);
        if (hpack_lit(out, cap, &off, "content-length", cl) != 0) return -1;
    }
    if (referer) {
        if (hpack_lit(out, cap, &off, "referer", referer) != 0) return -1;
    }
    *n = off;
    return 0;
}

/* like xray's client, the padding never touches the real :path: the request
   url goes into Referer with x_padding as its whole query. the configured
   query stays on the path itself. a server that expects a clean session/seq
   path refuses one that grows a padding query */
static void path_with_padding(const xh_t *h, const char *path, char *out, size_t cap,
                              char *referer, size_t ref_cap) {
    char pad[XH_PAD_CAP + 1];
    size_t n = rand_pad_len(h);
    memset(pad, 'X', n);
    pad[n] = 0;
    if (h->query[0])
        snprintf(out, cap, "%s?%s", path, h->query);
    else
        snprintf(out, cap, "%s", path);
    snprintf(referer, ref_cap, "%s://%s%s?x_padding=%s",
             h->security_tls ? "https" : "http", h->host, path, pad);
}

static int flush_tx(xh_t *h) {
    while (h->tx_off < h->tx_len) {
        int w = h->sub_vt->write(h->sub_h, h->tx + h->tx_off,
                                 h->tx_len - h->tx_off);
        if (w > 0) { h->tx_off += (size_t)w; continue; }
        if (w == 0) return TRANSPORT_WANT_WRITE;
        return w;
    }
    h->tx_len = h->tx_off = 0;
    return 0;
}

static int feed_window(xh_t *h, uint32_t stream, uint32_t credit) {
    uint8_t p[4];
    h2_put_u32(p, credit);
    return frame_append(h, H2_WINDOW_UPDATE, 0, stream, p, 4);
}

static int app_push(xh_t *h, const uint8_t *p, size_t n) {
    if (n == 0) return 0;
    if (h->app_off) {
        memmove(h->app, h->app + h->app_off, h->app_len - h->app_off);
        h->app_len -= h->app_off;
        h->app_off = 0;
    }
    if (h->app_len + n > sizeof h->app) return -1;
    memcpy(h->app + h->app_len, p, n);
    h->app_len += n;
    return 0;
}

static int read_varint(const uint8_t *p, size_t n, size_t *used, uint32_t *value) {
    uint32_t v = 0;
    unsigned shift = 0;
    size_t i;
    for (i = 0; i < n && i < 5; ++i) {
        uint8_t b = p[i];
        v |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *used = i + 1;
            *value = v;
            return 0;
        }
        shift += 7;
    }
    return -1;
}

/* xray hunk payloads use protobuf field 1 for application bytes */
static int grpc_message_to_app(xh_t *h, const uint8_t *msg, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        size_t used;
        uint32_t key, field_len;
        unsigned wire;
        if (read_varint(msg + pos, len - pos, &used, &key) != 0) return -1;
        pos += used;
        wire = key & 7u;
        if ((key >> 3) == 1 && wire == 2) {
            if (read_varint(msg + pos, len - pos, &used, &field_len) != 0)
                return -1;
            pos += used;
            if (field_len > len - pos) return -1;
            if (app_push(h, msg + pos, field_len) != 0) return -1;
            pos += field_len;
            continue;
        }
        switch (wire) {
            case 0:
                if (read_varint(msg + pos, len - pos, &used, &field_len) != 0)
                    return -1;
                pos += used;
                break;
            case 1:
                if (len - pos < 8) return -1;
                pos += 8;
                break;
            case 2:
                if (read_varint(msg + pos, len - pos, &used, &field_len) != 0)
                    return -1;
                pos += used;
                if (field_len > len - pos) return -1;
                pos += field_len;
                break;
            case 5:
                if (len - pos < 4) return -1;
                pos += 4;
                break;
            default:
                return -1;
        }
    }
    return 0;
}

static int grpc_rx_push(xh_t *h, const uint8_t *data, size_t len) {
    if (len > sizeof h->grpc_rx - h->grpc_rx_len) return -1;
    memcpy(h->grpc_rx + h->grpc_rx_len, data, len);
    h->grpc_rx_len += len;
    while (h->grpc_rx_len >= 5) {
        uint32_t msg_len = h2_u32(h->grpc_rx + 1);
        size_t total = (size_t)msg_len + 5;
        if (h->grpc_rx[0] != 0) return -1; /* compressed gRPC is unsupported */
        if (total > sizeof h->grpc_rx) return -1;
        if (h->grpc_rx_len < total) break;
        if (grpc_message_to_app(h, h->grpc_rx + 5, msg_len) != 0) return -1;
        if (h->grpc_rx_len > total)
            memmove(h->grpc_rx, h->grpc_rx + total, h->grpc_rx_len - total);
        h->grpc_rx_len -= total;
    }
    return 0;
}

/* collect one header block across CONTINUATION and run it through hpack */
static int process_header_block(xh_t *h, uint8_t type, uint8_t flags,
                                const uint8_t *pay, size_t plen) {
    if (type == H2_HEADERS) {
        if (h->hdr_wait) return h2_fail(h, "headers inside unfinished block");
        h->hdr_len = 0;
        h->hdr_wait = !(flags & H2_FLAG_END_HEADERS);
        if (flags & H2_FLAG_PADDED) {
            if (plen < 1) return h2_fail(h, "truncated padded headers");
            size_t pad = pay[0];
            pay++; plen--;
            if (plen < pad) return h2_fail(h, "truncated padded headers");
            plen -= pad;
        }
    } else { /* H2_CONTINUATION */
        if (!h->hdr_wait)
            return h2_fail(h, "continuation without headers");
        h->hdr_wait = !(flags & H2_FLAG_END_HEADERS);
    }
    if (plen > sizeof h->hdr_blk - h->hdr_len)
        return h2_fail(h, "header block too large");
    memcpy(h->hdr_blk + h->hdr_len, pay, plen);
    h->hdr_len += plen;
    if (h->hdr_wait) return 0;

    senko_hpack_fields_t f;
    if (senko_hpack_parse(h->hdr_blk, h->hdr_len, &f) != 0)
        return h2_fail(h, "malformed response headers");

    if (f.have_status) {
        if (f.status != 200) {
            char msg[96];
            snprintf(msg, sizeof msg, "http status %d", f.status);
            return h2_fail(h, msg);
        }
        h->saw_status = 1;
    } else if (!h->saw_status) {
/* a first response without :status cannot be verified */
        return h2_fail(h, "response status missing");
    }

    if ((flags & H2_FLAG_END_STREAM) && h->grpc) {
        if (f.have_grpc_status && f.grpc_status != 0) {
            char msg[160];
            snprintf(msg, sizeof msg, "grpc status %d: %s",
                     f.grpc_status, f.grpc_message);
            return h2_fail(h, msg);
        }
        if (!f.have_grpc_status)
            return h2_fail(h, "grpc trailers without status");
    }
    return 0;
}

static void win_adjust(uint32_t *win, int64_t delta) {
    int64_t v = (int64_t)*win + delta;
    *win = v < 0 ? 0 : v > 0x7fffffff ? 0x7fffffffu : (uint32_t)v;
}

/* packet-up posts are streams we opened besides the two long-lived ones */
static int our_stream(const xh_t *h, uint32_t stream) {
    if (stream == h->up_stream || stream == h->dn_stream) return 1;
    return h->mode == XH_MODE_PKT && (stream & 1u) && stream < h->next_sid;
}

/* the posts allowed in flight: ours, and one stream fewer than the peer
   takes so the download stream keeps its place */
static int post_limit(const xh_t *h) {
    uint32_t peer = h->peer_max_streams > 1 ? h->peer_max_streams - 1 : 1;
    return peer < XH_POSTS ? (int)peer : XH_POSTS;
}

/* the server answered or reset a post, which frees its slot */
static void post_done(xh_t *h, uint32_t stream) {
    for (int i = 0; i < h->posts_open; ++i) {
        if (h->posts[i] != stream) continue;
        h->posts[i] = h->posts[--h->posts_open];
        return;
    }
}

static int process_frames(xh_t *h) {
    while (h->rx_len - h->rx_off >= 9) {
        const uint8_t *hdr = h->rx + h->rx_off;
        int plen = h2_u24(hdr);
        uint8_t type = hdr[3], flags = hdr[4];
        uint32_t stream = h2_u32(hdr + 5) & 0x7fffffffu;
        if (h->rx_len - h->rx_off < (size_t)(9 + plen)) break;
        const uint8_t *pay = hdr + 9;
        h->rx_off += (size_t)(9 + plen);

/* we never advertise SETTINGS_MAX_FRAME_SIZE above the default */
        if (plen > 16384) return h2_fail(h, "frame size above advertised max");
        if (stream == 0 &&
            (type == H2_DATA || type == H2_HEADERS ||
             type == H2_CONTINUATION))
            return h2_fail(h, "frame on stream 0");
        if (stream != 0 && type == H2_SETTINGS)
            return h2_fail(h, "settings on a stream");
        if (h->hdr_wait && type != H2_CONTINUATION)
            return h2_fail(h, "frame inside header block");

        if (type == H2_SETTINGS) {
            if (!(flags & 0x01)) {
                for (int i = 0; i + 6 <= plen; i += 6) {
                    uint16_t id = (uint16_t)((pay[i] << 8) | pay[i + 1]);
                    uint32_t val = h2_u32(pay + i + 2);
                    if (id == 0x4) {
/* the initial window moves every stream window by its change and leaves the
   connection window alone (rfc 7540 6.9.2) */
                        if (val > 0x7fffffffu)
                            return h2_fail(h, "peer initial window overflow");
                        int64_t delta = (int64_t)val - (int64_t)h->peer_init_win;
                        win_adjust(&h->up_peer_win, delta);
                        win_adjust(&h->dn_peer_win, delta);
                        h->peer_init_win = val;
                    } else if (id == 0x3) {
                        h->peer_max_streams = val;
                    }
                }
                if (frame_append(h, H2_SETTINGS, 0x01, 0, NULL, 0) != 0)
                    return TRANSPORT_ERR;
            }
            h->saw_settings = 1;
            if (h->state == XH_ST_BOOT && h->saw_settings)
                h->state = XH_ST_OPEN;
            continue;
        }
        if (type == H2_WINDOW_UPDATE && plen == 4) {
            uint32_t inc = h2_u32(pay) & 0x7fffffffu; /* reserved bit ignored */
            if (inc == 0)
                return h2_fail(h, "window update increment 0");
            uint32_t *win = stream == 0 ? &h->peer_win :
                            stream == h->up_stream ? &h->up_peer_win :
                            stream == h->dn_stream ? &h->dn_peer_win : NULL;
            if (win) {
                if (*win > 0x7fffffffu - inc)
                    return h2_fail(h, "flow control window overflow");
                *win += inc;
            }
            continue;
        }
        if (type == H2_PING && plen == 8) {
            if (!(flags & 0x01) &&
                frame_append(h, H2_PING, 0x01, 0, pay, 8) != 0)
                return TRANSPORT_ERR;
            continue;
        }
        if (type == H2_GOAWAY) {
            if (plen < 8)
                return h2_fail(h, "short goaway");
            char msg[96];
            snprintf(msg, sizeof msg, "goaway: %s",
                     h2_error_name(h2_u32(pay + 4)));
            return h2_fail(h, msg);
        }
        if (type == H2_RST_STREAM) {
            if (plen != 4)
                return h2_fail(h, "short rst stream");
            post_done(h, stream);
/* rst for a finished packet-up stream can still be in flight, but a
   refused post lost its bytes */
            if (stream == h->up_stream || stream == h->dn_stream ||
                (our_stream(h, stream) && h2_u32(pay) == 7)) {
                char msg[96];
                snprintf(msg, sizeof msg, "rst stream: %s",
                         h2_error_name(h2_u32(pay)));
                return h2_fail(h, msg);
            }
            continue;
        }
        if (type == H2_HEADERS || type == H2_CONTINUATION) {
            if (!our_stream(h, stream))
                continue; /* never opened: server-side stray stream */
            if (type == H2_HEADERS && (flags & H2_FLAG_END_STREAM))
                post_done(h, stream);
            int r = process_header_block(h, type, flags, pay, (size_t)plen);
            if (r != 0) return r;
            continue;
        }
        if (type == H2_DATA) {
            const uint8_t *data = pay;
            size_t dlen = (size_t)plen;
            if (flags & H2_FLAG_PADDED) {
                if (dlen < 1) return h2_fail(h, "truncated padded data");
                size_t pad = data[0];
                data++; dlen--;
                if (dlen < pad) return h2_fail(h, "truncated padded data");
                dlen -= pad;
            }
            if (flags & H2_FLAG_END_STREAM)
                post_done(h, stream);
            if (stream != h->up_stream && stream != h->dn_stream)
                continue; /* never opened: server-side stray stream */
            if (stream == h->dn_stream && dlen > 0) {
                if (h->grpc) {
                    if (grpc_rx_push(h, data, dlen) != 0)
                        return h2_fail(h, "bad grpc message stream");
                } else if (app_push(h, data, dlen) != 0) {
                    return h2_fail(h, "app buffer overflow");
                }
                if (h->our_win > dlen) h->our_win -= (uint32_t)dlen;
                else h->our_win = 0;
                if (h->dn_our_win > dlen) h->dn_our_win -= (uint32_t)dlen;
                else h->dn_our_win = 0;
                if (h->our_win < 16000) {
                    if (feed_window(h, 0, 65535) != 0) return TRANSPORT_ERR;
                    h->our_win += 65535;
                }
                if (h->dn_our_win < 16000) {
                    if (feed_window(h, h->dn_stream, 65535) != 0)
                        return TRANSPORT_ERR;
                    h->dn_our_win += 65535;
                }
            }
            if ((flags & H2_FLAG_END_STREAM) && stream == h->dn_stream) {
                if (h->grpc && h->grpc_rx_len != 0)
                    return h2_fail(h, "truncated grpc message at end stream");
                h->peer_end = 1;
            }
            continue;
        }
    }
    if (h->rx_off) {
        if (h->rx_off < h->rx_len)
            memmove(h->rx, h->rx + h->rx_off, h->rx_len - h->rx_off);
        h->rx_len -= h->rx_off;
        h->rx_off = 0;
    }
    return 0;
}

static int pump_rx(xh_t *h) {
    if (h->rx_len < sizeof h->rx) {
        int r = h->sub_vt->read(h->sub_h, h->rx + h->rx_len,
                                sizeof h->rx - h->rx_len);
        if (r > 0) h->rx_len += (size_t)r;
        else if (r == TRANSPORT_EOF) return TRANSPORT_EOF;
        else if (r < 0 && r != TRANSPORT_WANT_READ && r != TRANSPORT_WANT_WRITE)
            return r;
        else if (r < 0 && h->rx_len == 0) return r;
    }
    return process_frames(h);
}

static uint32_t alloc_sid(xh_t *h) {
    uint32_t s = h->next_sid;
    h->next_sid += 2;
    return s;
}

enum { XH_SEC_NONE = 0, XH_SEC_TLS, XH_SEC_REALITY };

static int queue_boot(xh_t *h, const transport_tls_cfg_t *cfg, int sec) {
    h->mode = mode_for_open(cfg, sec == XH_SEC_REALITY);
    h->security_tls = sec != XH_SEC_NONE;
    h->grpc = cfg && cfg->xhttp_mode && strcmp(cfg->xhttp_mode, "grpc") == 0;
    h->stream_ct = h->grpc || !(cfg && cfg->xh.no_grpc);
    h->pad_min = XH_PAD_MIN;
    h->pad_max = XH_PAD_MAX;
    if (cfg && cfg->xh.pad_max) {
        h->pad_max = cfg->xh.pad_max < XH_PAD_CAP ? cfg->xh.pad_max : XH_PAD_CAP;
        h->pad_min = cfg->xh.pad_min < h->pad_max ? cfg->xh.pad_min : h->pad_max;
        if (h->pad_min == 0) h->pad_min = 1; /* some servers refuse an empty one */
    }
    h->pkt_max = XH_PKT;
    if (cfg && cfg->xh.post_max && cfg->xh.post_max < XH_PKT)
        h->pkt_max = cfg->xh.post_max;
    h->next_sid = 1;
    h->seq = 0;
    h->peer_win = h->our_win = 65535;
    h->up_peer_win = h->up_our_win = 65535;
    h->dn_peer_win = h->dn_our_win = 65535;
    h->peer_init_win = 65535;
    h->peer_max_streams = 100; /* rfc 7540 suggests at least this much */

/* http/2 authority: explicit host param wins. gRPC routes on the dial target
   like xray and only falls back to sni; ws keeps sni as its camouflage host */
    const char *authority;
    if (cfg && cfg->ws_host && cfg->ws_host[0]) {
        authority = cfg->ws_host;
    } else if (h->grpc && cfg && cfg->peer_host && cfg->peer_host[0]) {
        authority = cfg->peer_host;
    } else if (cfg && cfg->sni && cfg->sni[0]) {
        authority = cfg->sni;
    } else if (cfg && cfg->peer_host && cfg->peer_host[0]) {
        authority = cfg->peer_host;
    } else {
        authority = "localhost";
    }
    snprintf(h->host, sizeof h->host, "%s", authority);

    normalize_base_path(cfg && cfg->path ? cfg->path : "/",
                        h->base_path, sizeof h->base_path,
                        h->query, sizeof h->query, !h->grpc);
    if (h->mode != XH_MODE_ONE)
        gen_session_id(h->session);
    else
        h->session[0] = 0;

    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (tx_append(h, (const uint8_t *)preface, sizeof preface - 1) != 0)
        return -1;
/* raise max concurrent streams for packet-up; keep the initial stream window
   at the 65535 default because the app buffers hold at most one 64k window */
    uint8_t settings[6];
    settings[0] = 0; settings[1] = 0x3;
    h2_put_u32(settings + 2, 128);
    if (frame_append(h, H2_SETTINGS, 0, 0, settings, 6) != 0) return -1;

    uint8_t block[2 * XH_PATH + 768];
    size_t blen = 0;
    char path[XH_PATH], path_pad[XH_PATH], referer[XH_PATH + 256];

    if (h->mode == XH_MODE_ONE) {
        if (h->grpc)
            snprintf(path_pad, sizeof path_pad, "%s", h->base_path);
        else
            path_with_padding(h, h->base_path, path_pad, sizeof path_pad,
                              referer, sizeof referer);
        if (build_headers(block, sizeof block, &blen, 1, path_pad, h->host, h->stream_ct,
                          0, 0, h->security_tls, h->grpc, h->grpc ? NULL : referer) != 0)
            return -1;
        h->up_stream = h->dn_stream = alloc_sid(h); /* stream 1 both ways */
        if (frame_append(h, H2_HEADERS, 0x04, h->up_stream, block, blen) != 0)
            return -1;
        h->state = XH_ST_BOOT;
        return 0;
    }

/* the other modes open the long-lived download stream first */
    snprintf(path, sizeof path, "%s%s", h->base_path, h->session);
    path_with_padding(h, path, path_pad, sizeof path_pad, referer, sizeof referer);
    if (build_headers(block, sizeof block, &blen, 0, path_pad, h->host, 0, 0, 0,
                      h->security_tls, 0, referer) != 0)
        return -1;
    h->dn_stream = alloc_sid(h);
    if (frame_append(h, H2_HEADERS, 0x04 | 0x01, h->dn_stream, block, blen) != 0)
        return -1; /* end the get request with headers */

    if (h->mode == XH_MODE_UP) {
/* keep upload on its own stream for stream-up mode */
        blen = 0;
        path_with_padding(h, path, path_pad, sizeof path_pad, referer, sizeof referer);
        if (build_headers(block, sizeof block, &blen, 1, path_pad, h->host, h->stream_ct,
                          0, 0, h->security_tls, 0, referer) != 0)
            return -1;
        h->up_stream = alloc_sid(h);
        if (frame_append(h, H2_HEADERS, 0x04, h->up_stream, block, blen) != 0)
            return -1;
    } else {
        h->up_stream = 0; /* packet-up posts once per write */
    }

    h->state = XH_ST_BOOT;
    return 0;
}

/* one packet-up post: headers and a single data frame that ends the stream.
   nothing is queued unless both fit */
static int send_packet(xh_t *h, const uint8_t *buf, size_t len) {
    if (len == 0 || len > h->pkt_max) return -1;
    char path[XH_PATH], path_pad[XH_PATH], referer[XH_PATH + 256];
    snprintf(path, sizeof path, "%s%s/%lld",
             h->base_path, h->session, (long long)h->seq);
    path_with_padding(h, path, path_pad, sizeof path_pad, referer, sizeof referer);

    uint8_t block[2 * XH_PATH + 768];
    size_t blen = 0;
    if (build_headers(block, sizeof block, &blen, 1, path_pad, h->host, 0, len, 1,
                      h->security_tls, 0, referer) != 0)
        return -1;
    if (9 + blen + 9 + len > sizeof h->tx - h->tx_len) return -1;
    if (h->posts_open >= post_limit(h)) return -1;
    uint32_t sid = alloc_sid(h);
    h->seq++;
/* leave end stream for the data frame */
    if (frame_append(h, H2_HEADERS, 0x04, sid, block, blen) != 0) return -1;
    if (frame_append(h, H2_DATA, 0x01, sid, buf, len) != 0) return -1; /* end stream */
    h->posts[h->posts_open++] = sid;
    return 0;
}

static void *xh_open_common(int fd, const transport_tls_cfg_t *cfg,
                            const transport_vt_t *sub, int sec) {
    xh_t *h = (xh_t *)calloc(1, sizeof *h);
    if (!h) return NULL;
    h->sub_vt = sub;
    h->sub_h = sub->open(fd, cfg);
    if (!h->sub_h) { free(h); return NULL; }
    if (queue_boot(h, cfg, sec) != 0) {
        sub->close(h->sub_h);
        free(h);
        return NULL;
    }
    return h;
}

static void *xh_open_tcp(int fd, const transport_tls_cfg_t *cfg) {
    return xh_open_common(fd, cfg, &transport_tcp, XH_SEC_NONE);
}
static void *xh_open_tls(int fd, const transport_tls_cfg_t *cfg) {
    transport_tls_cfg_t h2;
    if (cfg) h2 = *cfg;
    else memset(&h2, 0, sizeof h2);
    h2.alpn_h2 = 1;
    return xh_open_common(fd, &h2, &transport_tls, XH_SEC_TLS);
}
static void *xh_open_reality(int fd, const transport_tls_cfg_t *cfg) {
    return xh_open_common(fd, cfg, &transport_reality, XH_SEC_REALITY);
}

static void xh_close(void *handle) {
    xh_t *h = (xh_t *)handle;
    if (!h) return;
    if (h->sub_h) h->sub_vt->close(h->sub_h);
    free(h);
}

static int grpc_frame_append(xh_t *h, const uint8_t *data, size_t len,
                             size_t *wire_len) {
    uint8_t frame[16384 + 16];
    size_t frame_len = 0;

    if (senko_grpc_encode(data, len, frame, sizeof frame, &frame_len) != 0)
        return -1;
    if (frame_append(h, H2_DATA, 0, h->up_stream, frame, frame_len) != 0)
        return -1;
    if (wire_len) *wire_len = frame_len;
    return 0;
}

/* bytes one write can put on the wire now; 0 while a window or every post
   slot waits on the peer */
static size_t xh_room(const xh_t *h) {
    size_t room;
    if (h->state != XH_ST_OPEN) return 0;
    if (h->mode == XH_MODE_PKT) {
        if (h->posts_open >= post_limit(h)) return 0;
        room = h->pkt_max;
        if (room > h->peer_win) room = h->peer_win;
        if (room > h->peer_init_win) room = h->peer_init_win;
        return room;
    }
    room = h->peer_win < h->up_peer_win ? h->peer_win : h->up_peer_win;
    if (h->grpc) return room > 8 ? room - 8 : 0; /* the envelope takes 8 */
    return room;
}

static int xh_blocked(void *handle) {
    xh_t *h = (xh_t *)handle;
    return h && h->state != XH_ST_FAIL && xh_room(h) == 0;
}

static int xh_write(void *handle, const uint8_t *buf, size_t len) {
    xh_t *h = (xh_t *)handle;
    if (!h || h->state == XH_ST_FAIL) return TRANSPORT_ERR;

    int fr = flush_tx(h);
    if (fr < 0) return fr;

    if (h->state != XH_ST_OPEN) {
        int pr = pump_rx(h);
        if (pr < 0 && pr != TRANSPORT_WANT_READ && pr != TRANSPORT_WANT_WRITE)
            return pr;
        fr = flush_tx(h);
        if (fr < 0) return fr;
        if (h->state != XH_ST_OPEN) return TRANSPORT_WANT_WRITE;
    }
    if (len == 0) return 0;

    if (h->mode == XH_MODE_PKT) {
/* one post per write, sized to a data frame and to the peer's windows. when
   nothing fits, read what the peer sent (window updates, finished posts)
   and try once more */
        for (int tries = 0;; ++tries) {
            size_t take = xh_room(h);
            if (take > len) take = len;
            if (take > 0 && send_packet(h, buf, take) == 0) {
                h->peer_win -= (uint32_t)take;
                fr = flush_tx(h);
                if (fr < 0 && fr != TRANSPORT_WANT_WRITE) return fr;
                return (int)take;
            }
            if (tries) return TRANSPORT_WANT_WRITE;
            int pr = pump_rx(h);
            if (pr < 0 && pr != TRANSPORT_WANT_READ && pr != TRANSPORT_WANT_WRITE)
                return pr;
            fr = flush_tx(h);
            if (fr < 0 && fr != TRANSPORT_WANT_WRITE) return fr;
        }
    }

    if (h->grpc) {
        size_t max = len;
        size_t wire_len;
        if (max > 16368) max = 16368;
        if (h->peer_win < 8 || h->up_peer_win < 8) max = 0;
        else {
            if (max > h->peer_win - 8) max = h->peer_win - 8;
            if (max > h->up_peer_win - 8) max = h->up_peer_win - 8;
        }
        if (max == 0) {
            int pr = pump_rx(h);
            if (pr < 0 && pr != TRANSPORT_WANT_READ) return pr;
            fr = flush_tx(h);
            if (fr < 0) return fr;
            return TRANSPORT_WANT_WRITE;
        }
        if (grpc_frame_append(h, buf, max, &wire_len) != 0)
            return TRANSPORT_WANT_WRITE;
        h->peer_win -= (uint32_t)wire_len;
        h->up_peer_win -= (uint32_t)wire_len;
        fr = flush_tx(h);
        if (fr < 0 && fr != TRANSPORT_WANT_WRITE) return fr;
        return (int)max;
    }

/* stream modes write data on the upload stream */
    size_t max = len;
    if (h->peer_win < max) max = h->peer_win;
    if (h->up_peer_win < max) max = h->up_peer_win;
    if (max == 0) {
        int pr = pump_rx(h);
        if (pr < 0 && pr != TRANSPORT_WANT_READ) return pr;
        fr = flush_tx(h);
        if (fr < 0) return fr;
        return TRANSPORT_WANT_WRITE;
    }
    if (max > 16384) max = 16384;
    if (frame_append(h, H2_DATA, 0, h->up_stream, buf, max) != 0)
        return TRANSPORT_WANT_WRITE;
    h->peer_win -= (uint32_t)max;
    h->up_peer_win -= (uint32_t)max;
    fr = flush_tx(h);
    if (fr < 0 && fr != TRANSPORT_WANT_WRITE) return fr;
    return (int)max;
}

static int xh_read(void *handle, uint8_t *buf, size_t len) {
    xh_t *h = (xh_t *)handle;
    if (!h || h->state == XH_ST_FAIL) return TRANSPORT_ERR;
    if (len == 0) return 0;

    int fr = flush_tx(h);
    if (fr < 0 && fr != TRANSPORT_WANT_WRITE) return fr;

    if (h->app_off < h->app_len) {
        size_t n = h->app_len - h->app_off;
        if (n > len) n = len;
        memcpy(buf, h->app + h->app_off, n);
        h->app_off += n;
        if (h->app_off == h->app_len) h->app_off = h->app_len = 0;
        return (int)n;
    }

    int pr = pump_rx(h);
    if (pr < 0 && pr != TRANSPORT_WANT_READ && pr != TRANSPORT_WANT_WRITE)
        return pr;
    fr = flush_tx(h);
    if (fr < 0 && fr != TRANSPORT_WANT_WRITE) return fr;

    if (h->app_off < h->app_len) {
        size_t n = h->app_len - h->app_off;
        if (n > len) n = len;
        memcpy(buf, h->app + h->app_off, n);
        h->app_off += n;
        if (h->app_off == h->app_len) h->app_off = h->app_len = 0;
        return (int)n;
    }
    if (h->peer_end) return TRANSPORT_EOF;
    return TRANSPORT_WANT_READ;
}

static int xh_want_write(void *handle) {
    xh_t *h = (xh_t *)handle;
    if (!h) return 0;
    if (h->tx_len > h->tx_off) return 1;
    if (h->sub_vt && h->sub_vt->want_write && h->sub_h)
        return h->sub_vt->want_write(h->sub_h);
    return 0;
}

/* half close after the relay drained: end the upload stream so grpc and
   xhttp servers see a complete request instead of a transport reset */
static void xh_shutdown(void *handle) {
    xh_t *h = (xh_t *)handle;
    if (!h || h->we_end || h->state == XH_ST_FAIL) return;
    h->we_end = 1;
    if (h->mode == XH_MODE_PKT) return; /* every post already ended its stream */
    if (frame_append(h, H2_DATA, H2_FLAG_END_STREAM, h->up_stream, NULL, 0) != 0)
        return;
    (void)flush_tx(h);
}

const transport_vt_t transport_xhttp_tcp = {
    xh_open_tcp, xh_read, xh_write, NULL, xh_close, xh_want_write, xh_shutdown,
    xh_blocked
};
const transport_vt_t transport_xhttp_tls = {
    xh_open_tls, xh_read, xh_write, NULL, xh_close, xh_want_write, xh_shutdown,
    xh_blocked
};
const transport_vt_t transport_xhttp_reality = {
    xh_open_reality, xh_read, xh_write, NULL, xh_close, xh_want_write,
    xh_shutdown, xh_blocked
};
