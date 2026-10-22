#include "../daemon/loop.c"
#include <assert.h>
#include <stdlib.h>
#include <signal.h>

/* the engine: a socks5 server that hangs up on the first g_refuse requests
   after reading them, the way it does when its own connection upstream fails,
   and answers the rest with "echo:" and what the client sent */
static int g_engine_fd = -1;
static uint16_t g_engine_port;
static volatile int g_refuse;
static volatile int g_accepted;
static volatile int g_stop;
static volatile int g_dials;

static int read_full(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static void *engine_main(void *arg) {
    (void)arg;
    while (!g_stop) {
        struct pollfd p = { g_engine_fd, POLLIN, 0 };
        if (poll(&p, 1, 50) <= 0) continue;
        int fd = accept(g_engine_fd, NULL, NULL);
        if (fd < 0) continue;
        int k = __sync_fetch_and_add(&g_accepted, 1);
        uint8_t b[64];
        /* greeting, then the connect request for 127.0.0.1 */
        if (read_full(fd, b, 3) != 0 || write(fd, "\x05\x00", 2) != 2 ||
            read_full(fd, b, 10) != 0) {
            close(fd);
            continue;
        }
        if (k < g_refuse) {
            close(fd);
            continue;
        }
        assert(write(fd, "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10) == 10);
        ssize_t n = read(fd, b, sizeof b);
        if (n > 0) {
            assert(write(fd, "echo:", 5) == 5);
            assert(write(fd, b, (size_t)n) == n);
        }
        close(fd);
    }
    return NULL;
}

static int engine_dial(void *ctx) {
    (void)ctx;
    __sync_fetch_and_add(&g_dials, 1);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(g_engine_port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    return fd;
}

typedef struct {
    uint16_t proxy_port;
    char got[256];
    size_t got_len;
    volatile int done;
} client_t;

static void *client_main(void *arg) {
    client_t *cl = (client_t *)arg;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(cl->proxy_port);
    assert(connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0);
    uint8_t r[16];
    assert(write(fd, "\x05\x01\x00", 3) == 3);
    assert(read_full(fd, r, 2) == 0 && r[0] == 5 && r[1] == 0);
    assert(write(fd, "\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb", 10) == 10);
    /* the reply comes early from the loop, or from the engine through the
       session; a refused request may also end without one */
    if (read_full(fd, r, 10) == 0 && r[1] == 0 && write(fd, "ping", 4) == 4) {
        for (;;) {
            ssize_t n = read(fd, cl->got + cl->got_len, sizeof cl->got - 1 - cl->got_len);
            if (n <= 0) break;
            cl->got_len += (size_t)n;
        }
    }
    cl->got[cl->got_len] = '\0';
    close(fd);
    cl->done = 1;
    return NULL;
}

static void run_client(loop_t *lp, client_t *cl) {
    pthread_t t;
    cl->proxy_port = loop_listen_port(lp);
    assert(pthread_create(&t, NULL, client_main, cl) == 0);
    for (int i = 0; i < 400 && !cl->done; ++i) assert(loop_step(lp, 25) == LOOP_OK);
    assert(cl->done);
    pthread_join(t, NULL);
    /* let the loop see the client's close */
    for (int i = 0; i < 10; ++i) (void)loop_step(lp, 10);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_engine_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(g_engine_fd, (struct sockaddr *)&sa, sizeof sa) == 0);
    assert(listen(g_engine_fd, 8) == 0);
    socklen_t sl = sizeof sa;
    assert(getsockname(g_engine_fd, (struct sockaddr *)&sa, &sl) == 0);
    g_engine_port = ntohs(sa.sin_port);
    pthread_t engine;
    assert(pthread_create(&engine, NULL, engine_main, NULL) == 0);

    loop_t *lp = calloc(1, sizeof *lp);
    assert(loop_init(lp, 0, 0, &transport_tcp, engine_dial, NULL, VL_PROTO_SOCKS5,
                     NULL, NULL, NULL, NULL) == LOOP_OK);

    /* two refusals in a row: the third connection carries the request */
    client_t cl;
    memset(&cl, 0, sizeof cl);
    g_refuse = 2;
    run_client(lp, &cl);
    assert(strcmp(cl.got, "echo:ping") == 0);
    assert(g_dials == 3 && g_accepted == 3);
    assert(lp->nconns == 0 && lp->nopening == 0);

    /* an engine that refuses everything is asked a bounded number of times */
    memset(&cl, 0, sizeof cl);
    g_dials = 0;
    g_accepted = 0;
    g_refuse = 1000;
    run_client(lp, &cl);
    assert(cl.got_len == 0);
    assert(g_dials == 1 + LOOP_REDIALS);
    assert(lp->nconns == 0 && lp->nopening == 0);

    /* a request the engine answers at once costs one dial */
    memset(&cl, 0, sizeof cl);
    g_dials = 0;
    g_accepted = 0;
    g_refuse = 0;
    run_client(lp, &cl);
    assert(strcmp(cl.got, "echo:ping") == 0 && g_dials == 1);

    g_stop = 1;
    pthread_join(engine, NULL);
    loop_close(lp);
    free(lp);
    close(g_engine_fd);
    puts("all loop redial checks passed");
    return 0;
}
