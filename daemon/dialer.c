#define _DEFAULT_SOURCE

#include "dialer.h"

#include "core/net_safe.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

/* the loop dials from its own thread, so a lookup that never answers would
   freeze every connection along with it */
#define DIALER_RESOLVE_MS 3000

void dialer_set_target(dialer_ctx_t *d, const char *host, int port) {
    if (!d || !host) return;
    size_t hl = strlen(host);
    if (hl >= sizeof d->host) hl = sizeof d->host - 1;
    memcpy(d->host, host, hl);
    d->host[hl] = '\0';
    snprintf(d->port, sizeof d->port, "%d", port);
    d->pinned_n = 0;
}

void dialer_pin_ipv4(dialer_ctx_t *d, const char *ip_list) {
    if (!d) return;
    d->pinned_n = 0;
    const char *p = ip_list;
    while (p && *p && d->pinned_n < DIALER_MAX_PINNED) {
        while (*p == ' ' || *p == ',') ++p;
        size_t len = strcspn(p, ", ");
        if (len > 0 && len < sizeof d->pinned[0]) {
            char ip[sizeof d->pinned[0]];
            struct in_addr a;
            memcpy(ip, p, len);
            ip[len] = '\0';
            if (inet_pton(AF_INET, ip, &a) == 1)
                memcpy(d->pinned[d->pinned_n++], ip, len + 1);
        }
        p += len;
    }
}

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* a socket whose connect is under way, or -1 when the kernel refused at once */
static int dial_address(const struct sockaddr *addr, socklen_t addr_len) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_nonblock(fd);
    int r = connect(fd, addr, addr_len);
    if (r == 0 || errno == EINPROGRESS) {
/* low-latency for many short tls streams (safari) */
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        return fd;
    }
    close(fd);
    return -1;
}

int dialer_connect(void *ctx) {
    dialer_ctx_t *d = (dialer_ctx_t *)ctx;
    if (!d || !d->host[0]) return -1;

    if (d->pinned_n > 0) {
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons((uint16_t)atoi(d->port));
        for (size_t i = 0; i < d->pinned_n; ++i) {
            if (inet_pton(AF_INET, d->pinned[i], &sin.sin_addr) != 1) continue;
            int fd = dial_address((const struct sockaddr *)&sin, sizeof sin);
            if (fd >= 0) return fd;
        }
        return -1;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
/* routing bypass is ipv4-only */
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (net_getaddrinfo_timed(d->host, d->port, &hints, &res, DIALER_RESOLVE_MS) != 0 ||
        !res) {
        errno = EHOSTUNREACH;
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET) continue;
        fd = dial_address(ai->ai_addr, ai->ai_addrlen);
        if (fd >= 0) break;
    }

    freeaddrinfo(res);
    return fd;
}
