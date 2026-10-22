#define _DEFAULT_SOURCE

#include "session.h"
#include "socks5_client.h"
#include "transport.h"

#include <fcntl.h>
#include <signal.h>
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

static size_t drain(int fd, uint8_t *buf, size_t cap) {
    ssize_t n = read(fd, buf, cap);
    return n > 0 ? (size_t)n : 0;
}

/* a client that answers socks at once sends its first bytes before the
   upstream proxy has replied; they must reach the proxy only after its
   connect reply, never as the next handshake message */
static void test_socks5_upstream_holds_client_bytes(void) {
    int sv[2];
    uint8_t got[4096];
    size_t n, consumed = 0;
    session_t *s = calloc(1, sizeof *s);
    static const uint8_t request[] = { 0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p',
                                       'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb };
    static const uint8_t hello[] = { 0x16, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
    uint8_t first[sizeof request + sizeof hello];

    ok("alloc", s != NULL);
    ok("pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    nonblock(sv[1]);
    void *th = transport_tcp.open(sv[0], NULL);
    ok("session", session_init_after_greet(s, &transport_tcp, th, VL_PROTO_SOCKS5,
                                           NULL, NULL, NULL, NULL) == SESS_OK);

    memcpy(first, request, sizeof request);
    memcpy(first + sizeof request, hello, sizeof hello);
    ok("feed request and hello", session_feed_client(s, first, sizeof first, &consumed) == SESS_OK);
    ok("all taken", consumed == sizeof first);
    n = drain(sv[1], got, sizeof got);
    ok("only the greeting went out", n == 3 && got[0] == 0x05 && got[1] == 0x01 && got[2] == 0x00);

    /* more client bytes while the proxy is still silent stay held too */
    ok("feed more", session_feed_client(s, (const uint8_t *)"more", 4, &consumed) == SESS_OK &&
                    consumed == 4);
    ok("nothing more went out", drain(sv[1], got, sizeof got) == 0);
    ok("held bytes are not pending", session_remote_pending(s) == 0);

    ok("method reply", write(sv[1], "\x05\x00", 2) == 2);
    ok("pump", session_pump_remote(s) == SESS_OK);
    n = drain(sv[1], got, sizeof got);
    if (n != sizeof request || memcmp(got, request, sizeof request)) { fprintf(stderr, "n=%zu:", n); for (size_t i = 0; i < n; ++i) fprintf(stderr, " %02x", got[i]); fprintf(stderr, "\n"); }
    ok("then the connect request alone", n == sizeof request &&
                                         memcmp(got, request, sizeof request) == 0);

    ok("connect reply", write(sv[1], "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10) == 10);
    ok("pump relay", session_pump_remote(s) == SESS_OK);
    ok("relay", s->state == SESS_RELAY);
    n = drain(sv[1], got, sizeof got);
    ok("then the client bytes, in order", n == sizeof hello + 4 &&
                                          memcmp(got, hello, sizeof hello) == 0 &&
                                          memcmp(got + sizeof hello, "more", 4) == 0);

    ok("feed after relay", session_feed_client(s, (const uint8_t *)"live", 4, &consumed) == SESS_OK);
    n = drain(sv[1], got, sizeof got);
    ok("relay bytes go straight out", n == 4 && memcmp(got, "live", 4) == 0);

    transport_tcp.close(th);
    close(sv[0]);
    close(sv[1]);
    free(s);
}

/* the same for an http connect upstream */
static void test_http_upstream_holds_client_bytes(void) {
    int sv[2];
    uint8_t got[4096];
    size_t n, consumed = 0;
    session_t *s = calloc(1, sizeof *s);
    static const uint8_t request[] = { 0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x01, 0xbb };
    uint8_t first[sizeof request + 5];

    ok("alloc http", s != NULL);
    ok("pair http", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    nonblock(sv[1]);
    void *th = transport_tcp.open(sv[0], NULL);
    ok("session http", session_init_after_greet(s, &transport_tcp, th, VL_PROTO_HTTP,
                                                NULL, NULL, NULL, NULL) == SESS_OK);
    memcpy(first, request, sizeof request);
    memcpy(first + sizeof request, "hello", 5);
    ok("feed http", session_feed_client(s, first, sizeof first, &consumed) == SESS_OK &&
                    consumed == sizeof first);
    n = drain(sv[1], got, sizeof got);
    got[n < sizeof got ? n : sizeof got - 1] = 0;
    ok("only the connect request went out",
       n > 0 && strncmp((char *)got, "CONNECT 192.0.2.1:443", 21) == 0 &&
       strstr((char *)got, "hello") == NULL);

    static const char reply[] = "HTTP/1.1 200 Connection established\r\n\r\n";
    ok("http reply", write(sv[1], reply, sizeof reply - 1) == (ssize_t)(sizeof reply - 1));
    ok("pump http", session_pump_remote(s) == SESS_OK && s->state == SESS_RELAY);
    n = drain(sv[1], got, sizeof got);
    ok("then the client bytes", n == 5 && memcmp(got, "hello", 5) == 0);

    transport_tcp.close(th);
    close(sv[0]);
    close(sv[1]);
    free(s);
}

/* the engine closes a socks stream without a reply when its own connection
   upstream fails; the session says the request may go out again, and on a
   new connection it sends the handshake once more and only then the bytes
   the client sent meanwhile */
static void test_socks5_upstream_refused_restart(void) {
    int sv[2], sv2[2];
    uint8_t got[4096];
    size_t n, consumed = 0;
    session_t *s = calloc(1, sizeof *s);
    static const uint8_t request[] = { 0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p',
                                       'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb };
    uint8_t first[sizeof request + 5];

    ok("alloc refused", s != NULL);
    ok("pair refused", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    nonblock(sv[1]);
    void *th = transport_tcp.open(sv[0], NULL);
    ok("session refused", session_init_after_greet(s, &transport_tcp, th, VL_PROTO_SOCKS5,
                                                   NULL, NULL, NULL, NULL) == SESS_OK);
    memcpy(first, request, sizeof request);
    memcpy(first + sizeof request, "hello", 5);
    ok("feed refused", session_feed_client(s, first, sizeof first, &consumed) == SESS_OK &&
                       consumed == sizeof first);
    n = drain(sv[1], got, sizeof got);
    ok("greeting out", n == 3);
    ok("method reply refused", write(sv[1], "\x05\x00", 2) == 2);
    ok("pump to request", session_pump_remote(s) == SESS_OK);
    n = drain(sv[1], got, sizeof got);
    ok("request out", n == sizeof request);
    ok("not refused while waiting", !session_upstream_refused(s));

    close(sv[1]); /* the engine gives up without a reply */
    session_pump_remote(s);
    ok("refused", session_upstream_refused(s));
    ok("restart needs a handle", session_restart_upstream(s, NULL) == SESS_ERR_ARG);

    ok("pair again", socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
    nonblock(sv2[0]);
    nonblock(sv2[1]);
    void *th2 = transport_tcp.open(sv2[0], NULL);
    ok("restart", session_restart_upstream(s, th2) == SESS_OK);
    ok("waiting again", s->state == SESS_VLESS_RESP && !session_upstream_refused(s));
    n = drain(sv2[1], got, sizeof got);
    ok("greeting again, alone", n == 3 && got[0] == 0x05);
    ok("more while waiting", session_feed_client(s, (const uint8_t *)"more", 4, &consumed) ==
                             SESS_OK && consumed == 4);
    ok("method reply again", write(sv2[1], "\x05\x00", 2) == 2);
    ok("pump again", session_pump_remote(s) == SESS_OK);
    n = drain(sv2[1], got, sizeof got);
    ok("request again, alone", n == sizeof request && memcmp(got, request, n) == 0);
    ok("connect reply again", write(sv2[1], "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10) == 10);
    ok("pump relay again", session_pump_remote(s) == SESS_OK && s->state == SESS_RELAY);
    n = drain(sv2[1], got, sizeof got);
    ok("the held bytes, once and in order", n == 9 && memcmp(got, "hellomore", 9) == 0);

    /* an eof once the relay runs is the site's answer, not a refusal */
    close(sv2[1]);
    session_pump_remote(s);
    ok("eof in relay is not a refusal", !session_upstream_refused(s) && s->state == SESS_CLOSED);
    ok("no restart after relay", session_restart_upstream(s, th2) == SESS_ERR_ARG);

    transport_tcp.close(th);
    transport_tcp.close(th2);
    close(sv[0]);
    close(sv2[0]);
    free(s);
}

/* the same for an http connect upstream that hangs up before its status line */
static void test_http_upstream_refused_restart(void) {
    int sv[2], sv2[2];
    uint8_t got[4096];
    size_t n, consumed = 0;
    session_t *s = calloc(1, sizeof *s);
    static const uint8_t request[] = { 0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x01, 0xbb };
    uint8_t first[sizeof request + 5];

    ok("alloc http refused", s != NULL);
    ok("pair http refused", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    nonblock(sv[1]);
    void *th = transport_tcp.open(sv[0], NULL);
    ok("session http refused", session_init_after_greet(s, &transport_tcp, th, VL_PROTO_HTTP,
                                                        NULL, NULL, NULL, NULL) == SESS_OK);
    memcpy(first, request, sizeof request);
    memcpy(first + sizeof request, "hello", 5);
    ok("feed http refused", session_feed_client(s, first, sizeof first, &consumed) == SESS_OK);
    (void)drain(sv[1], got, sizeof got);
    ok("half a status line", write(sv[1], "HTTP/1.1 2", 10) == 10);
    session_pump_remote(s);
    close(sv[1]);
    session_pump_remote(s);
    ok("http refused", session_upstream_refused(s));

    ok("pair http again", socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
    nonblock(sv2[0]);
    nonblock(sv2[1]);
    void *th2 = transport_tcp.open(sv2[0], NULL);
    ok("http restart", session_restart_upstream(s, th2) == SESS_OK);
    n = drain(sv2[1], got, sizeof got);
    got[n < sizeof got ? n : sizeof got - 1] = 0;
    ok("connect again, without the client bytes",
       n > 0 && strncmp((char *)got, "CONNECT 192.0.2.1:443", 21) == 0 &&
       strstr((char *)got, "hello") == NULL);
    static const char reply[] = "HTTP/1.1 200 Connection established\r\n\r\n";
    ok("http reply again", write(sv2[1], reply, sizeof reply - 1) == (ssize_t)(sizeof reply - 1));
    ok("pump http again", session_pump_remote(s) == SESS_OK && s->state == SESS_RELAY);
    n = drain(sv2[1], got, sizeof got);
    ok("then the client bytes after a restart", n == 5 && memcmp(got, "hello", 5) == 0);

    transport_tcp.close(th);
    transport_tcp.close(th2);
    close(sv[0]);
    close(sv2[0]);
    close(sv2[1]);
    free(s);
}

/* a session whose remote queue is full says so, so the loop stops reading */
static void test_client_room(void) {
    session_t *s = calloc(1, sizeof *s);
    ok("room alloc", s != NULL);
    ok("empty queue has room", session_client_room(s) == 8192);
    s->to_remote_len = sizeof s->to_remote - 4096;
    ok("nearly full queue has none", session_client_room(s) == 0);
    s->to_remote_hold = 100;
    ok("held bytes are not pending", session_remote_pending(s) == sizeof s->to_remote - 4096 - 100);
    free(s);
}

/* socks numbers ipv6 as 4, vless as 3 (which is a domain in socks) */
static void test_socks5_ipv6_address_type(void) {
    socks5_client_t c;
    vless_dest_t dest;
    uint8_t out[64];
    size_t out_len = 0, consumed = 0;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_IPV6;
    dest.host_addr[0] = 0x20;
    dest.host_addr[1] = 0x01;
    dest.port = 443;
    s5c_init(&c, NULL, NULL, &dest);
    ok("v6 greeting", s5c_make_request(&c, out, sizeof out, &out_len) == S5C_OK);
    ok("v6 method reply", s5c_feed(&c, (const uint8_t *)"\x05\x00", 2, &consumed, out,
                                   sizeof out, &out_len) == S5C_OK);
    ok("v6 connect", out_len == 22 && out[3] == 0x04 && out[4] == 0x20 && out[5] == 0x01 &&
                     out[20] == 0x01 && out[21] == 0xbb);
}

/* a redirected connection never spoke socks: the start goes straight to the
   upstream's handshake, and the app gets only the destination's bytes */
static void test_transparent_socks5_upstream(void) {
    int sv[2];
    uint8_t got[4096];
    size_t n, consumed = 0, used = 99;
    session_t *s = calloc(1, sizeof *s);
    vless_dest_t dest;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_IPV4;
    dest.host_addr[0] = 192; dest.host_addr[1] = 0; dest.host_addr[2] = 2; dest.host_addr[3] = 7;
    dest.port = 443;

    ok("tp alloc", s != NULL);
    ok("tp pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    nonblock(sv[1]);
    void *th = transport_tcp.open(sv[0], NULL);
    ok("tp init", session_init(s, &transport_tcp, th, VL_PROTO_SOCKS5, NULL, NULL, NULL, NULL) == SESS_OK);
    ok("tp start", session_start_from_transparent_dest(s, &dest, (const uint8_t *)"hello", 5, &used) ==
                   SESS_OK);
    ok("tp payload left to the caller", used == 0);
    ok("tp payload fed", session_feed_client(s, (const uint8_t *)"hello", 5, &consumed) == SESS_OK &&
                         consumed == 5);
    n = drain(sv[1], got, sizeof got);
    ok("tp greeting only", n == 3 && got[0] == 0x05);

/* the replies come in pieces */
    ok("tp method 1", write(sv[1], "\x05", 1) == 1);
    ok("tp pump 1", session_pump_remote(s) == SESS_OK);
    ok("tp method 2", write(sv[1], "\x00", 1) == 1);
    ok("tp pump 2", session_pump_remote(s) == SESS_OK);
    n = drain(sv[1], got, sizeof got);
    ok("tp connect request after a split method reply", n == 10 && got[0] == 0x05 && got[1] == 0x01 &&
                                                        got[3] == 0x01 && got[4] == 192 && got[7] == 7);
    ok("tp reply 1", write(sv[1], "\x05\x00\x00\x01", 4) == 4);
    ok("tp pump 3", session_pump_remote(s) == SESS_OK && s->state != SESS_RELAY);
    ok("tp reply 2 and data", write(sv[1], "\x00\x00\x00\x00\x00\x00HTTP", 10) == 10);
    ok("tp pump 4", session_pump_remote(s) == SESS_OK && s->state == SESS_RELAY);
    n = drain(sv[1], got, sizeof got);
    ok("tp payload after the reply", n == 5 && memcmp(got, "hello", 5) == 0);
    n = session_take_client(s, got, sizeof got);
    ok("tp app sees no socks reply, only the destination", n == 4 && memcmp(got, "HTTP", 4) == 0);

    transport_tcp.close(th);
    close(sv[0]);
    close(sv[1]);
    free(s);
}

/* trojan carries the first bytes in its request, again without a reply */
static void test_transparent_trojan(void) {
    int sv[2];
    uint8_t got[4096];
    size_t used = 0;
    session_t *s = calloc(1, sizeof *s);
    vless_dest_t dest;
    memset(&dest, 0, sizeof dest);
    dest.atyp = VLESS_ADDR_IPV4;
    dest.host_addr[0] = 198; dest.host_addr[1] = 51; dest.host_addr[2] = 100; dest.host_addr[3] = 1;
    dest.port = 80;
    ok("tt alloc", s != NULL);
    ok("tt pair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    nonblock(sv[0]);
    nonblock(sv[1]);
    void *th = transport_tcp.open(sv[0], NULL);
    ok("tt init", session_init(s, &transport_tcp, th, VL_PROTO_TROJAN, NULL, NULL, NULL, "pw") == SESS_OK);
    ok("tt start", session_start_from_transparent_dest(s, &dest, (const uint8_t *)"GET /", 5, &used) ==
                   SESS_OK && used == 5 && s->state == SESS_RELAY);
    size_t n = drain(sv[1], got, sizeof got);
    ok("tt request carries the payload", n > 5 && memcmp(got + n - 5, "GET /", 5) == 0);
    ok("tt no socks reply", session_take_client(s, got, sizeof got) == 0);
    transport_tcp.close(th);
    close(sv[0]);
    close(sv[1]);
    free(s);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN); /* the daemon ignores it too */
    test_socks5_ipv6_address_type();
    test_socks5_upstream_holds_client_bytes();
    test_http_upstream_holds_client_bytes();
    test_socks5_upstream_refused_restart();
    test_http_upstream_refused_restart();
    test_client_room();
    test_transparent_socks5_upstream();
    test_transparent_trojan();
    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    puts("all session upstream checks passed");
    return 0;
}
