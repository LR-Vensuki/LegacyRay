#define _DEFAULT_SOURCE

#include "session.h"
#include "socks5.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmess_fixture.inc"

static int g_fail = 0;
static void ok(const char *what, int cond) {
    if (cond) return;
    g_fail++;
    fprintf(stderr, "FAIL %s\n", what);
}

typedef struct {
    const uint8_t *rx;
    size_t rx_len;
    int rx_done;
    int write_calls;
    int raw_calls;
    int mark_calls;
    uint8_t raw_buf[64];
    size_t raw_len;
} fake_transport_t;

static void *fake_open(int fd, const transport_tls_cfg_t *cfg) {
    (void)fd;
    (void)cfg;
    return NULL;
}

static int fake_read(void *h, uint8_t *buf, size_t len) {
    fake_transport_t *ft = (fake_transport_t *)h;
    if (ft->rx_done) return TRANSPORT_WANT_READ;
    size_t n = ft->rx_len < len ? ft->rx_len : len;
    memcpy(buf, ft->rx, n);
    ft->rx_done = 1;
    return (int)n;
}

static int fake_write(void *h, const uint8_t *buf, size_t len) {
    (void)buf;
    fake_transport_t *ft = (fake_transport_t *)h;
    /* len 0 is a flush probe (reality wpend); not a real app write */
    if (len == 0) return 0;
    ft->write_calls++;
    return (int)len;
}

static int fake_raw_write(void *h, const uint8_t *buf, size_t len) {
    fake_transport_t *ft = (fake_transport_t *)h;
    if (len == 0) {
        ft->mark_calls++;
        return 0;
    }
    ft->raw_calls++;
    if (len > sizeof ft->raw_buf) len = sizeof ft->raw_buf;
    memcpy(ft->raw_buf, buf, len);
    ft->raw_len = len;
    return (int)len;
}

static void fake_close(void *h) {
    (void)h;
}

static const transport_vt_t fake_vt = {
    fake_open, fake_read, fake_write, fake_raw_write, fake_close, NULL
};

/* a server stream handed out as the session asks; once it is used up the
   socket either stays quiet (eof == 0) or reports the server's close */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t off;
    int eof;
    int eof_seen;
} stream_transport_t;

static int stream_read(void *h, uint8_t *buf, size_t len) {
    stream_transport_t *st = (stream_transport_t *)h;
    if (st->off >= st->len) {
        if (!st->eof) return TRANSPORT_WANT_READ;
        st->eof_seen = 1;
        return TRANSPORT_EOF;
    }
    size_t n = st->len - st->off < len ? st->len - st->off : len;
    memcpy(buf, st->data + st->off, n);
    st->off += n;
    return (int)n;
}

static int stream_write(void *h, const uint8_t *buf, size_t len) {
    (void)h;
    (void)buf;
    return (int)len;
}

/* what a loop sees: the socket is readable while bytes remain, and a closed
   one stays readable */
static int stream_readable(const stream_transport_t *st) {
    return st->off < st->len || st->eof;
}

static const transport_vt_t stream_vt = {
    fake_open, stream_read, stream_write, NULL, fake_close, NULL
};

static uint8_t g_fixture_counter;
static int fixture_random(uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(g_fixture_counter++ * 37 + 11);
    return 0;
}

#define VMESS_SLOW_CHUNKS 12
#define VMESS_SLOW_CHUNK 8000

/* a client queue too full for the next chunk must neither overflow the vmess
   stage nor strand chunks once the server has sent everything: taking from
   the queue opens them, and the end chunk closes the session */
static void check_vmess_slow_client(int eof, int chunks) {
    static session_t s;
    static vmess_client_t server;
    static uint8_t wire[64 + VMESS_SLOW_CHUNKS * (VMESS_SLOW_CHUNK + 81) + 81];
    static uint8_t chunk[VMESS_SLOW_CHUNK];
    const char *what = eof ? "vmess slow client, server closes" : "vmess slow client, server idles";
    uint8_t uuid[VLESS_UUID_LEN];
    ok(what, vless_uuid_parse("b831381d-6324-4d53-ad4f-8cda48b30811", uuid) == VLESS_OK);
    stream_transport_t st;
    memset(&st, 0, sizeof st);
    ok(what, session_init(&s, &stream_vt, &st, VL_PROTO_VMESS, uuid, NULL,
                          "aes-128-gcm", NULL) == SESS_OK);
    /* the fixture's response header was sealed for these per connection keys */
    g_fixture_counter = 0;
    ok(what, vmess_client_init(&s.u.mc, uuid, "aes-128-gcm", NULL, fixture_random) == VMESS_OK);

    /* the server side of the body is the client's sealer run with the
       response key, iv and mask */
    server = s.u.mc;
    memcpy(server.req_key, s.u.mc.resp_key, sizeof server.req_key);
    memcpy(server.req_iv, s.u.mc.resp_iv, sizeof server.req_iv);
    memcpy(server.req_body_key, s.u.mc.resp_body_key, sizeof server.req_body_key);
    server.enc_mask = s.u.mc.dec_mask;
    server.enc_count = 0;
    size_t wl = 38; /* sealed length and the empty sealed response header */
    memcpy(wire, vmess_aes_response, wl);
    for (int c = 0; c < chunks; ++c) {
        size_t n = 0;
        for (int i = 0; i < VMESS_SLOW_CHUNK; ++i) chunk[i] = (uint8_t)(c * 7 + i);
        ok(what, vmess_client_encrypt_chunk(&server, chunk, sizeof chunk, wire + wl,
                                            sizeof wire - wl, &n) == VMESS_OK);
        wl += n;
    }
    size_t end_len = 0;
    ok(what, vmess_client_encrypt_chunk(&server, NULL, 0, wire + wl, sizeof wire - wl,
                                        &end_len) == VMESS_OK);
    wl += end_len;
    st.data = wire;
    st.len = wl;
    st.eof = eof;

    vless_dest_t dest;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_DOMAIN;
    strcpy(dest.domain, "example.com");
    dest.port = 443;
    size_t used = 0;
    ok(what, session_start_from_transparent_dest(&s, &dest, NULL, 0, &used) == SESS_OK &&
       s.state == SESS_RELAY);

    /* a client that has read nothing yet: 100 bytes of room left */
    size_t skip = sizeof s.to_client - 100;
    s.to_client_len = skip;
    for (int i = 0; i < 256 && stream_readable(&st) && !st.eof_seen; ++i)
        if (session_pump_remote(&s) != SESS_OK) break;
    ok("vmess stage stays bounded under a full client queue", s.state == SESS_RELAY);

    size_t total = 0, bad = 0;
    for (int i = 0; i < 8192 && !session_is_done(&s); ++i) {
        uint8_t buf[1000];
        size_t n = session_take_client(&s, buf, sizeof buf);
        if (n == 0) {
            if (!stream_readable(&st)) break;
            if (session_pump_remote(&s) != SESS_OK) break;
            continue;
        }
        for (size_t k = 0; k < n; ++k) {
            if (skip) {
                --skip;
                continue;
            }
            size_t c = total / VMESS_SLOW_CHUNK, i2 = total % VMESS_SLOW_CHUNK;
            if (buf[k] != (uint8_t)(c * 7 + i2)) ++bad;
            ++total;
        }
    }
    ok("vmess slow client gets every byte in order",
       total == (size_t)chunks * VMESS_SLOW_CHUNK && bad == 0);
    ok("vmess end chunk closes the session", s.state == SESS_CLOSED);
    printf("ok %s\n", what);
}

/* an inner tls 1.2 stream ends the vision padding with END, not DIRECT. the
   server keeps reading the rest through the outer tls, so every later byte
   has to be sealed; bare bytes get a protocol_version alert back */
static void check_tls12_end_stays_sealed(const uint8_t uuid[VLESS_UUID_LEN]) {
    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx_done = 1;

    session_t s;
    ok("tls12 init", session_init(&s, &fake_vt, &ft, VL_PROTO_VLESS,
                                  uuid, "xtls-rprx-vision", NULL, NULL) == SESS_OK);
    s.state = SESS_RELAY;
    s.u.vc.state = VC_ST_OPEN;

    size_t consumed = 0;
    uint8_t hello[] = {0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};
    ok("tls12 hello", session_feed_client(&s, hello, sizeof hello, &consumed) == SESS_OK &&
                      consumed == sizeof hello);
    uint8_t app[] = {0x17, 0x03, 0x03, 0x00, 0x03, 'a', 'b', 'c'};
    ok("tls12 app data", session_feed_client(&s, app, sizeof app, &consumed) == SESS_OK &&
                         consumed == sizeof app);
    ok("tls12 padding ended", s.vwrap.end_sent == 1 && s.vwrap.direct_sent == 0);
    ok("tls12 upstream not direct", s.vision_upstream_direct == 0 &&
                                    s.vision_upstream_direct_pending == 0);
    ok("tls12 transport not marked raw", ft.mark_calls == 0);

    ok("tls12 more data", session_feed_client(&s, app, sizeof app, &consumed) == SESS_OK &&
                          consumed == sizeof app);
    ok("tls12 later bytes sealed", ft.write_calls == 3 && ft.raw_calls == 0);
    printf("ok tls 1.2 end stays sealed\n");
}

/* trojan and shadowsocks carry no distinct response header, so the local
   socks client only learns the tunnel is up from the connect reply below */
static void check_socks_connect_ack(vl_proto_t proto, const char *user,
                                    const char *pass, const char *what) {
    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx_done = 1;

    session_t s;
    ok(what, session_init(&s, &fake_vt, &ft, proto, NULL, NULL, user, pass) == SESS_OK);

    uint8_t greet[] = {0x05, 0x01, 0x00};
    size_t consumed = 0;
    ok(what, session_feed_client(&s, greet, sizeof greet, &consumed) == SESS_OK);
    ok(what, consumed == sizeof greet);

    uint8_t req[] = {0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xbb};
    ok(what, session_feed_client(&s, req, sizeof req, &consumed) == SESS_OK);
    ok(what, s.state == SESS_RELAY);

    uint8_t out[32];
    size_t got = session_take_client(&s, out, sizeof out);
    uint8_t expect[12] = {0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    ok(what, got == sizeof expect && memcmp(out, expect, sizeof expect) == 0);

    printf("ok %s\n", what);
}

int main(void) {
    uint8_t uuid[VLESS_UUID_LEN];
    for (size_t i = 0; i < sizeof uuid; ++i) uuid[i] = (uint8_t)(i + 1);

/* more than the stage holds, then less: the close arrives while whole chunks
   still wait for room */
    check_vmess_slow_client(0, VMESS_SLOW_CHUNKS);
    check_vmess_slow_client(1, VMESS_SLOW_CHUNKS);
    check_vmess_slow_client(1, 3);

    uint8_t direct[16 + 5 + 3];
    memcpy(direct, uuid, 16);
    direct[16] = VISION_CMD_DIRECT;
    direct[17] = 0;
    direct[18] = 0;
    direct[19] = 0;
    direct[20] = 0;
    memcpy(direct + 21, "RAW", 3);

    fake_transport_t ft;
    memset(&ft, 0, sizeof ft);
    ft.rx = direct;
    ft.rx_len = sizeof direct;

    session_t s;
    ok("session init", session_init(&s, &fake_vt, &ft, VL_PROTO_VLESS,
                                    uuid, "xtls-rprx-vision", NULL, NULL) == SESS_OK);
    s.state = SESS_RELAY;
    s.u.vc.state = VC_ST_OPEN;

    ok("pump direct", session_pump_remote(&s) == SESS_OK);
    ok("downstream direct latched", s.vision_downstream_direct == 1);
    ok("upstream direct stays framed", s.vision_upstream_direct == 0);
    ok("transport raw stays framed", ft.mark_calls == 0);

    uint8_t out[8];
    size_t got = session_take_client(&s, out, sizeof out);
    ok("direct payload delivered", got == 3 && memcmp(out, "RAW", 3) == 0);

    size_t consumed = 0;
    ok("feed raw client", session_feed_client(&s, (const uint8_t *)"GET", 3, &consumed) == SESS_OK);
    ok("client consumed", consumed == 3);
    ok("framed write used", ft.write_calls == 1);
    ok("raw write not used", ft.raw_calls == 0);

    check_tls12_end_stays_sealed(uuid);
    check_socks_connect_ack(VL_PROTO_TROJAN, NULL, "secret", "trojan socks connect ack");
    check_socks_connect_ack(VL_PROTO_SHADOWSOCKS, "aes-256-gcm", "secret", "shadowsocks socks connect ack");

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all session direct checks passed\n");
    return 0;
}
