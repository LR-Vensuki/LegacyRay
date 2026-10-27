/* a subscription body that is still arriving at the timeout may run on, up to
   the allowance the caller gives; without one the timeout stays hard */
#include "subfetch.h"
#include "transport.h"

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failed;

static void ok(const char *what, int pass) {
    if (pass) return;
    fprintf(stderr, "FAIL %s\n", what);
    failed++;
}

/* the header and the first piece are in the socket, the rest follows from a
   thread every 60 ms */
static void *trickle_writer(void *arg) {
    int fd = *(int *)arg;
    free(arg);
    for (int i = 0; i < 4; ++i) {
        poll(NULL, 0, 60);
        if (write(fd, "efgh", 4) != 4) break;
    }
    shutdown(fd, SHUT_WR);
    return NULL;
}

static pthread_t g_trickle;
static int g_peer = -1;

static int trickle_dial(void *ctx, const char *host, uint16_t port) {
    (void)ctx; (void)host; (void)port;
    static const char head[] = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nabcd";
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    if (write(sv[1], head, sizeof head - 1) != (ssize_t)(sizeof head - 1) ||
        fcntl(sv[0], F_SETFL, O_NONBLOCK) != 0) {
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    int *writer_fd = malloc(sizeof *writer_fd);
    if (!writer_fd) { close(sv[0]); close(sv[1]); return -1; }
    *writer_fd = sv[1];
    if (pthread_create(&g_trickle, NULL, trickle_writer, writer_fd) != 0) {
        free(writer_fd);
        close(sv[0]);
        close(sv[1]);
        return -1;
    }
    g_peer = sv[1];
    return sv[0];
}

int main(void) {
    subfetch_cfg_t cfg;
    subfetch_info_t info;
    uint8_t body[64];
    size_t blen = 0;
    subfetch_status_t r;

    signal(SIGPIPE, SIG_IGN); /* the writer outlives a fetch that gave up */
    memset(&cfg, 0, sizeof cfg);
    cfg.dial = trickle_dial;
    cfg.tcp = &transport_tcp;
    cfg.max_redirects = 1;

    r = subfetch_get_info(&cfg, "http://93.184.216.34/feed", body, sizeof body,
                          &blen, 100, &info);
    pthread_join(g_trickle, NULL);
    close(g_peer);
    ok("a flowing body past the timeout stalls without an allowance",
       r == SUBFETCH_ERR_TRANSPORT);

    cfg.progress_extend_ms = 2000;
    r = subfetch_get_info(&cfg, "http://93.184.216.34/feed", body, sizeof body,
                          &blen, 100, &info);
    pthread_join(g_trickle, NULL);
    close(g_peer);
    ok("a flowing body past the timeout finishes with an allowance",
       r == SUBFETCH_OK && blen == 20 && memcmp(body, "abcdefghefghefghefgh", 20) == 0);

    if (failed) return 1;
    puts("all subfetch budget checks passed");
    return 0;
}
