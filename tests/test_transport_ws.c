#include "transport.h"
#include "ws_path.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/evp.h>

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

static int b64(const uint8_t *in, size_t len, char *out, size_t cap) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    if (cap < ((len + 2) / 3) * 4 + 1) return -1;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = ((uint32_t)in[i] << 16) |
                       ((i + 1 < len ? (uint32_t)in[i + 1] : 0) << 8) |
                        (i + 2 < len ? (uint32_t)in[i + 2] : 0);
        out[j++] = chars[(val >> 18) & 0x3f];
        out[j++] = chars[(val >> 12) & 0x3f];
        out[j++] = (i + 1 < len) ? chars[(val >> 6) & 0x3f] : '=';
        out[j++] = (i + 2 < len) ? chars[val & 0x3f] : '=';
    }
    out[j] = '\0';
    return 0;
}

static int header_value(const char *req, const char *name, char *out, size_t cap) {
    size_t nl = strlen(name);
    const char *p = req;
    while ((p = strstr(p, "\r\n")) != NULL) {
        p += 2;
        if (strncmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1;
            while (*v == ' ' || *v == '\t') ++v;
            const char *e = strstr(v, "\r\n");
            if (!e) return -1;
            size_t n = (size_t)(e - v);
            if (n + 1 > cap) return -1;
            memcpy(out, v, n);
            out[n] = '\0';
            return 0;
        }
    }
    return -1;
}

static int accept_for_key(const char *key, char *out, size_t cap) {
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char input[96];
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    int n = snprintf(input, sizeof input, "%s%s", key, guid);
    if (n < 0 || (size_t)n >= sizeof input) return -1;
    if (EVP_Digest(input, (size_t)n, digest, &digest_len, EVP_sha1(), NULL) != 1)
        return -1;
    if (digest_len != 20) return -1;
    return b64(digest, digest_len, out, cap);
}

static void close_pair(int sv[2], void *h) {
    if (h) transport_ws_tcp.close(h);
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
}

static int start_ws(int sv[2], void **h, char *req, size_t req_cap) {
    sv[0] = -1;
    sv[1] = -1;
    *h = NULL;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    nonblock(sv[0]);
    nonblock(sv[1]);

    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.sni = "tls.example";
    cfg.ws_host = "cdn.example";
    cfg.path = "/ws";

    *h = transport_ws_tcp.open(sv[0], &cfg);
    if (!*h) return -1;

    uint8_t one = 0;
    int wr = transport_ws_tcp.write(*h, &one, 1);
    if (wr != TRANSPORT_WANT_READ && wr != TRANSPORT_WANT_WRITE) return -1;

    ssize_t n = read(sv[1], req, req_cap - 1);
    if (n <= 0) return -1;
    req[n] = '\0';
    return 0;
}

static int write_response(int fd, const char *accept) {
    char resp[256];
    int n = snprintf(resp, sizeof resp,
                     "HTTP/1.1 101 Switching Protocols\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Accept: %s\r\n"
                     "\r\n",
                     accept);
    if (n < 0 || (size_t)n >= sizeof resp) return -1;
    return write(fd, resp, (size_t)n) == n ? 0 : -1;
}

static int complete_ws(int fd, void *h, const char *req) {
    char key[64];
    char accept[64];
    uint8_t tmp[8];
    if (header_value(req, "Sec-WebSocket-Key", key, sizeof key) != 0) return -1;
    if (accept_for_key(key, accept, sizeof accept) != 0) return -1;
    if (write_response(fd, accept) != 0) return -1;
    return transport_ws_tcp.read(h, tmp, sizeof tmp) == TRANSPORT_WANT_READ ? 0 : -1;
}

static int write_ping(int fd, const uint8_t *payload, size_t len) {
    uint8_t frame[2 + 125];
    if (len > 125) return -1;
    frame[0] = 0x89;
    frame[1] = (uint8_t)len;
    memcpy(frame + 2, payload, len);
    return write(fd, frame, 2 + len) == (ssize_t)(2 + len) ? 0 : -1;
}

static int read_masked_pong(int fd, const uint8_t *payload, size_t len) {
    uint8_t frame[2 + 4 + 125];
    if (len > 125) return -1;
    ssize_t n = read(fd, frame, sizeof frame);
    if (n != (ssize_t)(6 + len)) return -1;
    if (frame[0] != 0x8a) return -1;
    if ((frame[1] & 0x80) == 0 || (frame[1] & 0x7f) != len) return -1;
    for (size_t i = 0; i < len; ++i)
        if ((uint8_t)(frame[6 + i] ^ frame[2 + (i % 4)]) != payload[i])
            return -1;
    return 0;
}

static int write_masked_binary(int fd) {
    uint8_t mask[4] = { 0x10, 0x20, 0x30, 0x40 };
    uint8_t frame[7];
    frame[0] = 0x82;
    frame[1] = 0x81;
    memcpy(frame + 2, mask, sizeof mask);
    frame[6] = (uint8_t)('x' ^ mask[0]);
    return write(fd, frame, sizeof frame) == (ssize_t)sizeof frame ? 0 : -1;
}

static int write_oversized_ping_header(int fd) {
    uint8_t frame[4] = { 0x89, 126, 0, 126 };
    return write(fd, frame, sizeof frame) == (ssize_t)sizeof frame ? 0 : -1;
}

static int write_bad_u64_length(int fd) {
    uint8_t frame[10] = { 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1 };
    return write(fd, frame, sizeof frame) == (ssize_t)sizeof frame ? 0 : -1;
}

/* one binary frame larger than the receive buffer, drained in small reads: the
   caller's read size is bounded by how much the client socket can still take,
   so a big frame has to survive many partial reads */
#define BIG_FRAME_TOTAL 200000

static int big_frame_roundtrip(int fd, void *h) {
    static const uint8_t hdr[10] = { 0x82, 127, 0, 0, 0, 0, 0, 0x03, 0x0d, 0x40 };
    size_t sent_hdr = 0, sent = 0, got = 0;
    int idle = 0;

    while (sent_hdr < sizeof hdr) {
        ssize_t n = write(fd, hdr + sent_hdr, sizeof hdr - sent_hdr);
        if (n <= 0) return -1;
        sent_hdr += (size_t)n;
    }

    while (got < BIG_FRAME_TOTAL && idle < 100000) {
        while (sent < BIG_FRAME_TOTAL) {
            uint8_t chunk[4096];
            size_t want = BIG_FRAME_TOTAL - sent < sizeof chunk
                        ? BIG_FRAME_TOTAL - sent : sizeof chunk;
            for (size_t i = 0; i < want; ++i)
                chunk[i] = (uint8_t)((sent + i) & 0xff);
            ssize_t n = write(fd, chunk, want);
            if (n <= 0) break; /* socket buffer full, drain the client side */
            sent += (size_t)n;
        }

        uint8_t out[4096];
        int r = transport_ws_tcp.read(h, out, sizeof out);
        if (r == TRANSPORT_EOF) return -2;
        if (r == TRANSPORT_WANT_READ || r == TRANSPORT_WANT_WRITE) { idle++; continue; }
        if (r < 0) return -3;
        for (int i = 0; i < r; ++i)
            if (out[i] != (uint8_t)((got + (size_t)i) & 0xff)) return -4;
        got += (size_t)r;
        idle = 0;
    }
    return got == BIG_FRAME_TOTAL ? 0 : -5;
}

/* a server on its own thread for opens that finish the upgrade themselves:
   it reads the request and answers 101 with the right accept */
static void *upgrade_server(void *arg) {
    int fd = *(int *)arg;
    char req[2048], key[64], accept[64];
    size_t len = 0;
    while (len < sizeof req - 1) {
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 2000) <= 0) return NULL;
        ssize_t n = read(fd, req + len, sizeof req - 1 - len);
        if (n <= 0) return NULL;
        len += (size_t)n;
        req[len] = '\0';
        if (strstr(req, "\r\n\r\n")) break;
    }
    /* xray's early-data setting never reaches the server as part of the path */
    if (strncmp(req, "GET /ws HTTP/1.1\r\n", 18) != 0) return NULL;
    if (header_value(req, "Sec-WebSocket-Key", key, sizeof key) == 0 &&
        accept_for_key(key, accept, sizeof accept) == 0)
        (void)write_response(fd, accept);
    return NULL;
}

static long ms_now(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + (long)(tv.tv_usec / 1000);
}

static void *open_with_budget(int sv[2], int budget_ms) {
    transport_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.ws_host = "cdn.example";
    cfg.path = "/ws?ed=2048";
    cfg.handshake_ms = budget_ms;
    return transport_ws_tcp.open(sv[0], &cfg);
}

static void test_open_handshake(void) {
    int sv[2];
    void *h;
    pthread_t server;
    static const char refused[] =
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

    /* a 5xx fails the open itself, so the opener can dial again */
    ok("refused pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    ok("queue 502", write(sv[1], refused, sizeof refused - 1) == (ssize_t)(sizeof refused - 1));
    h = open_with_budget(sv, 2000);
    ok("502 fails the open", h == NULL);
    close_pair(sv, NULL);

    /* a silent server fails it once the budget runs out */
    ok("silent pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    long started = ms_now();
    h = open_with_budget(sv, 150);
    long took = ms_now() - started;
    ok("silent server fails the open", h == NULL);
    ok("silent server waits the budget", took >= 140 && took < 1500);
    close_pair(sv, NULL);

    /* a 101 comes back established: the first write goes out as a frame */
    ok("upgrade pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    ok("server thread", pthread_create(&server, NULL, upgrade_server, &sv[1]) == 0);
    h = open_with_budget(sv, 2000);
    pthread_join(server, NULL);
    ok("101 opens", h != NULL);
    if (h) {
        uint8_t one = 0x5a, frame[16];
        ok("established write", transport_ws_tcp.write(h, &one, 1) == 1);
        ssize_t n = read(sv[1], frame, sizeof frame);
        ok("one masked frame", n == 7 && frame[0] == 0x82 && frame[1] == 0x81 &&
                               (frame[6] ^ frame[2]) == 0x5a);
    }
    close_pair(sv, h);
}

/* a socket that takes a little at a time: the writer's count of taken bytes
   and the payload the peer decodes must match, with nothing sent twice */
static int slow_socket_once(int sv[2], void *h) {
    static uint8_t big[100000];
    static uint8_t wire[300000];
    size_t taken = 0, wire_len = 0, payload = 0;
    int small = 4096;
    for (size_t i = 0; i < sizeof big; ++i) big[i] = (uint8_t)(i * 31);
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof small);
    for (int round = 0; round < 100000 && (taken < sizeof big || transport_ws_tcp.want_write(h));
         ++round) {
        int w = transport_ws_tcp.write(h, big + taken, sizeof big - taken);
        if (w > 0) taken += (size_t)w;
        else if (w != TRANSPORT_WANT_WRITE) return -1;
        ssize_t n = read(sv[1], wire + wire_len, sizeof wire - wire_len);
        if (n > 0) wire_len += (size_t)n;
    }
    for (;;) {
        ssize_t n = read(sv[1], wire + wire_len, sizeof wire - wire_len);
        if (n <= 0) break;
        wire_len += (size_t)n;
    }
    for (size_t off = 0; off + 2 <= wire_len;) {
        size_t len = wire[off + 1] & 0x7f, hl = 2;
        if (len == 126) { len = ((size_t)wire[off + 2] << 8) | wire[off + 3]; hl = 4; }
        else if (len == 127) return -1;
        hl += 4; /* mask */
        if (off + hl + len > wire_len) return -1;
        for (size_t i = 0; i < len; ++i) {
            uint8_t b = wire[off + hl + i] ^ wire[off + hl - 4 + (i % 4)];
            if (b != big[payload + i]) return -1;
        }
        payload += len;
        off += hl + len;
    }
    return taken == sizeof big && payload == sizeof big ? 0 : -1;
}

/* xray's early-data setting leaves the path, the other parameters stay */
static void test_path_without_early_data(void) {
    char out[128];
    ws_path_without_early_data("/ws?ed=2048", out, sizeof out);
    ok("ed alone", strcmp(out, "/ws") == 0);
    ws_path_without_early_data("/p?a=1&ed=5&b=2", out, sizeof out);
    ok("ed among others", strcmp(out, "/p?a=1&b=2") == 0);
    ws_path_without_early_data("?ed=1", out, sizeof out);
    ok("only ed leaves the root", strcmp(out, "/") == 0);
    ws_path_without_early_data(NULL, out, sizeof out);
    ok("no path is the root", strcmp(out, "/") == 0);
}

int main(void) {
    int sv[2];
    void *h = NULL;
    char req[2048];
    test_path_without_early_data();
    test_open_handshake();
    ok("start ws", start_ws(sv, &h, req, sizeof req) == 0);
    ok("path in request", strstr(req, "GET /ws HTTP/1.1\r\n") != NULL);
    ok("ws host header", strstr(req, "\r\nHost: cdn.example\r\n") != NULL);
    ok("sni not used as host", strstr(req, "\r\nHost: tls.example\r\n") == NULL);

    char key[64];
    char accept[64];
    ok("request has key", header_value(req, "Sec-WebSocket-Key", key, sizeof key) == 0);
    ok("accept computed", accept_for_key(key, accept, sizeof accept) == 0);
    ok("write accept", write_response(sv[1], accept) == 0);

    uint8_t one = 0;
    int wr = transport_ws_tcp.write(h, &one, 1);
    ok("valid accept establishes", wr == 1 || wr == TRANSPORT_WANT_WRITE);
    close_pair(sv, h);

    h = NULL;
    ok("start ws invalid", start_ws(sv, &h, req, sizeof req) == 0);
    ok("write bad accept", write_response(sv[1], "badaccept") == 0);
    wr = transport_ws_tcp.write(h, &one, 1);
    ok("invalid accept rejected", wr == TRANSPORT_ERR);
    close_pair(sv, h);

    h = NULL;
    ok("start ws ping", start_ws(sv, &h, req, sizeof req) == 0);
    ok("complete ws ping", complete_ws(sv[1], h, req) == 0);
    const uint8_t ping_payload[] = { 'p', 'i', 'n', 'g' };
    ok("write ping", write_ping(sv[1], ping_payload, sizeof ping_payload) == 0);
    uint8_t tmp[8];
    int rr = transport_ws_tcp.read(h, tmp, sizeof tmp);
    ok("ping not delivered", rr == TRANSPORT_WANT_READ);
    ok("pong emitted", read_masked_pong(sv[1], ping_payload, sizeof ping_payload) == 0);
    close_pair(sv, h);

    h = NULL;
    ok("start ws masked", start_ws(sv, &h, req, sizeof req) == 0);
    ok("complete ws masked", complete_ws(sv[1], h, req) == 0);
    ok("write masked server frame", write_masked_binary(sv[1]) == 0);
    rr = transport_ws_tcp.read(h, tmp, sizeof tmp);
    ok("masked server frame rejected", rr == TRANSPORT_ERR);
    close_pair(sv, h);

    h = NULL;
    ok("start ws oversize ping", start_ws(sv, &h, req, sizeof req) == 0);
    ok("complete ws oversize ping", complete_ws(sv[1], h, req) == 0);
    ok("write oversize ping", write_oversized_ping_header(sv[1]) == 0);
    rr = transport_ws_tcp.read(h, tmp, sizeof tmp);
    ok("oversize ping rejected", rr == TRANSPORT_ERR);
    close_pair(sv, h);

    h = NULL;
    ok("start ws bad u64", start_ws(sv, &h, req, sizeof req) == 0);
    ok("complete ws bad u64", complete_ws(sv[1], h, req) == 0);
    ok("write bad u64 length", write_bad_u64_length(sv[1]) == 0);
    rr = transport_ws_tcp.read(h, tmp, sizeof tmp);
    ok("bad u64 length rejected", rr == TRANSPORT_ERR);
    close_pair(sv, h);

    h = NULL;
    ok("start ws big write", start_ws(sv, &h, req, sizeof req) == 0);
    ok("complete ws big write", complete_ws(sv[1], h, req) == 0);
    {
        static uint8_t big[70000];
        uint8_t hdr[4];
        memset(big, 'u', sizeof big);
        int bw = transport_ws_tcp.write(h, big, sizeof big);
        ok("a write bigger than a frame sends one frame", bw > 0 && bw <= 0xffff);
        ok("frame header", read(sv[1], hdr, sizeof hdr) == (ssize_t)sizeof hdr);
        ok("frame length is what the write took",
           hdr[0] == 0x82 && (hdr[1] & 0x7f) == 126 && ((hdr[2] << 8) | hdr[3]) == bw);
    }
    close_pair(sv, h);

    h = NULL;
    ok("start ws slow socket", start_ws(sv, &h, req, sizeof req) == 0);
    ok("complete ws slow socket", complete_ws(sv[1], h, req) == 0);
    ok("slow socket: every byte reaches the peer once", slow_socket_once(sv, h) == 0);
    close_pair(sv, h);

    h = NULL;
    ok("start ws big frame", start_ws(sv, &h, req, sizeof req) == 0);
    ok("complete ws big frame", complete_ws(sv[1], h, req) == 0);
    ok("big frame survives partial reads", big_frame_roundtrip(sv[1], h) == 0);
    close_pair(sv, h);

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all transport_ws checks passed\n");
    return 0;
}
