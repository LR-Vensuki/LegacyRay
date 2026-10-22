/* the requests the xhttp transport puts on the wire: paths, padding and the
   packet-up posts, read back from a local socketpair */
#include "transport.h"
#include "hpack.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fail = 0;
static void ok(const char *what, int cond) {
    if (cond) return;
    g_fail++;
    fprintf(stderr, "FAIL %s\n", what);
}

static void nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

typedef struct {
    int sv[2];
    void *th;
    uint8_t out[256 * 1024];
    size_t len, off;
} xh_test_t;

typedef struct {
    int post;
    int grpc_ct; /* content-type: application/grpc in the headers */
    char path[2048];
    size_t data; /* bytes of the data frames that follow on the stream */
    size_t biggest_frame;
} request_t;

static int start_opts(xh_test_t *t, const char *path, const char *mode,
                      const transport_xhttp_opts_t *xh) {
    memset(t, 0, sizeof *t);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, t->sv) != 0) return -1;
    nonblock(t->sv[0]);
    nonblock(t->sv[1]);
    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.path = path;
    cfg.ws_host = "front.example";
    cfg.xhttp_mode = mode;
    if (xh) cfg.xh = *xh;
    t->th = transport_xhttp_tcp.open(t->sv[0], &cfg);
    if (!t->th) return -1;
    uint8_t none = 0;
    transport_xhttp_tcp.write(t->th, &none, 0); /* flushes the queued preface */
    return 0;
}

static int start(xh_test_t *t, const char *path, const char *mode) {
    return start_opts(t, path, mode, NULL);
}

static void stop(xh_test_t *t) {
    if (t->th) transport_xhttp_tcp.close(t->th);
    close(t->sv[0]);
    close(t->sv[1]);
}

static void collect(xh_test_t *t) {
    for (;;) {
        ssize_t n = read(t->sv[1], t->out + t->len, sizeof t->out - t->len);
        if (n > 0) { t->len += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return;
    }
}

/* one server setting (id 0 sends none) */
static void server_settings_id(xh_test_t *t, int id, int value) {
    uint8_t f[15] = { 0, 0, 0, 4, 0, 0, 0, 0, 0 };
    size_t n = 9;
    if (id > 0) {
        f[2] = 6;
        f[10] = (uint8_t)id;
        f[11] = (uint8_t)(value >> 24);
        f[12] = (uint8_t)(value >> 16);
        f[13] = (uint8_t)(value >> 8);
        f[14] = (uint8_t)value;
        n = 15;
    }
    ok("server settings", write(t->sv[1], f, n) == (ssize_t)n);
}

static void server_settings(xh_test_t *t, int initial_window) {
    server_settings_id(t, initial_window > 0 ? 4 : 0, initial_window);
}

/* a finished response to one post: :status 200 and end of stream */
static void server_done(xh_test_t *t, uint32_t stream) {
    uint8_t f[10] = { 0, 0, 1, 1, 0x05, (uint8_t)(stream >> 24), (uint8_t)(stream >> 16),
                      (uint8_t)(stream >> 8), (uint8_t)stream, 0x88 };
    ok("server answers a post", write(t->sv[1], f, sizeof f) == (ssize_t)sizeof f);
}

/* the next request the client sent: its method, :path and data */
static int next_request(xh_test_t *t, request_t *r) {
    memset(r, 0, sizeof *r);
    if (t->off == 0 && t->len >= 24 && memcmp(t->out, "PRI * HTTP/2.0", 14) == 0) t->off = 24;
    uint32_t sid = 0;
    while (t->off + 9 <= t->len) {
        const uint8_t *f = t->out + t->off;
        size_t plen = ((size_t)f[0] << 16) | ((size_t)f[1] << 8) | f[2];
        uint32_t stream = (((uint32_t)f[5] & 0x7f) << 24) | ((uint32_t)f[6] << 16) |
                          ((uint32_t)f[7] << 8) | f[8];
        if (t->off + 9 + plen > t->len) return -1;
        if (f[3] == 1) {
            if (sid) return 0; /* the next request starts */
            const uint8_t *p = f + 9;
            size_t used;
            sid = stream;
            r->post = p[0] == 0x83;
            if (p[2] != 0x04) return -1; /* :path, name from the static table */
            if (senko_hpack_string(p + 3, plen - 3, r->path, sizeof r->path, &used) != 0)
                return -1;
            for (size_t i = 0; i + 16 <= plen; ++i)
                if (memcmp(p + i, "application/grpc", 16) == 0) r->grpc_ct = 1;
        } else if (f[3] == 0 && sid && stream == sid) {
            r->data += plen;
            if (plen > r->biggest_frame) r->biggest_frame = plen;
        }
        t->off += 9 + plen;
    }
    return sid ? 0 : -1;
}

/* the padding sits in the query, within the range the server requires */
static int padding_in(const char *path, size_t lo, size_t hi) {
    const char *p = strstr(path, "x_padding=");
    if (!p) return 0;
    p += 10;
    size_t n = strspn(p, "X");
    return n >= lo && n <= hi && p[n] == 0;
}

/* xray's default xPaddingBytes */
static int padding_ok(const char *path) {
    return padding_in(path, 100, 1000);
}

static void test_stream_one_path(void) {
    xh_test_t *t = malloc(sizeof *t);
    request_t r;
    ok("stream-one open", t && start(t, "/xh", "stream-one") == 0);
    collect(t);
    ok("stream-one request", next_request(t, &r) == 0);
    ok("stream-one posts under the base with a trailing slash",
       r.post && strncmp(r.path, "/xh/?x_padding=", 15) == 0);
    ok("stream-one padding", padding_ok(r.path));
    stop(t);
    free(t);
}

static void test_auto_packet_up(void) {
    xh_test_t *t = malloc(sizeof *t);
    request_t r;
    char session[64];
    static uint8_t big[40000];
    memset(big, 'a', sizeof big);
    ok("auto open", t && start(t, "/xh?ed=2048", "auto") == 0);
    collect(t);
    ok("auto download request", next_request(t, &r) == 0);
    ok("auto over plain http is packet-up: a get first", !r.post);
    ok("download path keeps the configured query",
       strncmp(r.path, "/xh/", 4) == 0 && strstr(r.path, "?ed=2048&x_padding=") != NULL);
    ok("download padding", padding_ok(r.path));
    size_t sl = strcspn(r.path + 4, "/?");
    snprintf(session, sizeof session, "%.*s", (int)sl, r.path + 4);
    ok("session is uuid shaped", sl == 36);

    server_settings(t, 0);
    int w = transport_xhttp_tcp.write(t->th, big, 3000);
    ok("small write is one post", w == 3000);
    collect(t);
    ok("first post", next_request(t, &r) == 0);
    char want[128];
    snprintf(want, sizeof want, "/xh/%s/0?ed=2048&x_padding=", session);
    ok("first post path", r.post && strncmp(r.path, want, strlen(want)) == 0);
    ok("first post padding", padding_ok(r.path));
    ok("first post carries the bytes", r.data == 3000);

    w = transport_xhttp_tcp.write(t->th, big, sizeof big);
    ok("big write is cut to one data frame", w == 16384);
    collect(t);
    ok("second post", next_request(t, &r) == 0);
    snprintf(want, sizeof want, "/xh/%s/1?", session);
    ok("second post path", strncmp(r.path, want, strlen(want)) == 0);
    ok("second post fits a frame", r.data == 16384 && r.biggest_frame <= 16384);
    stop(t);
    free(t);
}

/* a big initial stream window from the peer must not stretch the
   connection window, which only window updates on stream 0 raise */
static void test_packet_up_connection_window(void) {
    xh_test_t *t = malloc(sizeof *t);
    static uint8_t big[16384];
    size_t sent = 0;
    memset(big, 'b', sizeof big);
    ok("window open", t && start(t, "/w", "packet-up") == 0);
    collect(t);
    server_settings(t, 1 << 20);
    for (int i = 0; i < 16; ++i) {
        int w = transport_xhttp_tcp.write(t->th, big, sizeof big);
        if (w <= 0) break;
        sent += (size_t)w;
        collect(t);
        t->len = t->off = 0;
    }
    ok("posts stop at the connection window", sent == 65535);
    stop(t);
    free(t);
}

/* posts wait for a free slot once the peer's stream limit is reached, and
   the loop sees the transport as blocked meanwhile */
static void test_packet_up_post_slots(void) {
    xh_test_t *t = malloc(sizeof *t);
    ok("slots open", t && start(t, "/s", "packet-up") == 0);
    collect(t);
    server_settings_id(t, 3, 3); /* the download and two posts */
    ok("first post", transport_xhttp_tcp.write(t->th, (const uint8_t *)"one", 3) == 3);
    ok("second post", transport_xhttp_tcp.write(t->th, (const uint8_t *)"two", 3) == 3);
    ok("third waits", transport_xhttp_tcp.write(t->th, (const uint8_t *)"three", 5) ==
                      TRANSPORT_WANT_WRITE);
    ok("blocked while every slot is taken", transport_xhttp_tcp.blocked(t->th) == 1);
    server_done(t, 3);
    ok("a finished post frees its slot",
       transport_xhttp_tcp.write(t->th, (const uint8_t *)"three", 5) == 5);
    collect(t);
    request_t r;
    int posts = 0;
    while (next_request(t, &r) == 0) posts += r.post;
    ok("three posts on the wire", posts == 3);
    stop(t);
    free(t);
}

/* a profile's extra: its padding range, a smaller post size, and streamed
   requests without the grpc content type */
static void test_profile_knobs(void) {
    xh_test_t *t = malloc(sizeof *t);
    request_t r;
    static uint8_t big[20000];
    transport_xhttp_opts_t xh;
    memset(big, 'k', sizeof big);
    memset(&xh, 0, sizeof xh);
    xh.pad_min = 20;
    xh.pad_max = 30;
    xh.post_max = 4096;
    ok("knobs open", t && start_opts(t, "/k", "packet-up", &xh) == 0);
    collect(t);
    ok("knobs download", next_request(t, &r) == 0 && !r.post);
    ok("download padding in the profile's range", padding_in(r.path, 20, 30));
    server_settings(t, 0);
    ok("posts stop at the server's size",
       transport_xhttp_tcp.write(t->th, big, sizeof big) == 4096);
    collect(t);
    ok("knobs post", next_request(t, &r) == 0 && r.post && r.data == 4096);
    ok("post padding in the profile's range", padding_in(r.path, 20, 30));
    stop(t);

    ok("stream-one keeps the grpc type by default", start(t, "/k", "stream-one") == 0);
    collect(t);
    ok("default stream-one request", next_request(t, &r) == 0 && r.grpc_ct);
    stop(t);

    memset(&xh, 0, sizeof xh);
    xh.no_grpc = 1;
    ok("no grpc header open", start_opts(t, "/k", "stream-one", &xh) == 0);
    collect(t);
    ok("noGRPCHeader drops the grpc type", next_request(t, &r) == 0 && r.post && !r.grpc_ct);
    ok("and keeps the default padding", padding_ok(r.path));
    stop(t);
    free(t);
}

int main(void) {
    test_stream_one_path();
    test_auto_packet_up();
    test_packet_up_connection_window();
    test_packet_up_post_slots();
    test_profile_knobs();
    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    puts("all xhttp transport checks passed");
    return 0;
}
