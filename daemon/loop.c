#define _DEFAULT_SOURCE
#include "loop.h"
#include "pf_natlook.h"
#include "senko_trace.h"
#include "socks5.h"
#include "sniff.h"
#include "net_safe.h"
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define LOOP_OPEN_STACK_SZ (512 * 1024)

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void wake_loop(loop_t *lp) {
    if (!lp || lp->wake_wr < 0) return;
    char b = 'x';
    ssize_t n = write(lp->wake_wr, &b, 1);
    (void)n; /* a full pipe is already awake */
}

static void drain_wake(loop_t *lp) {
    if (!lp || lp->wake_rd < 0) return;
    char buf[64];
    for (;;) {
        ssize_t n = read(lp->wake_rd, buf, sizeof buf);
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        break;
    }
}

static long loop_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + (long)(tv.tv_usec / 1000);
}

/* how long a connection waits for the client to say which site it wants.
   tls and http clients speak first and at once; a server-first protocol just
   pays this once and is routed by its address */
#define LOOP_SNIFF_MS 300
/* a relay nothing moved through for this long belongs to a peer that went
   away without a word, usually on the other side of a wifi/cellular move */
#define LOOP_IDLE_MS (20L * 60L * 1000L)
#define LOOP_DIRECT_CONNECT_MS 10000
/* how long an opener waits on a transport's own handshake (tls and the
   websocket upgrade) before it gives up on that connection and dials again */
#define LOOP_OPEN_HANDSHAKE_MS 7000
/* how many times a request the upstream proxy hung up on before answering
   goes out again. the engine is such an upstream: when a cdn in front of the
   server fails a websocket upgrade with 502 it closes the socks stream
   without a reply, and a cdn does that to a share of upgrades */
#define LOOP_REDIALS 3
#define LOOP_REDIAL_WAIT_MS 150

/* dead peers are found by the kernel instead of holding a slot forever */
static void set_keepalive(int fd) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
#ifdef TCP_KEEPALIVE
    int idle = 60;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idle, sizeof idle);
#endif
}

/* connect to the destination itself. the router already said this address
   goes around the tunnel; the bypass hook keeps the firewall from handing the
   connection straight back to the daemon */
static int direct_dial(loop_t *lp, const vless_dest_t *dest) {
    struct sockaddr_storage ss;
    socklen_t ss_len = 0;
    memset(&ss, 0, sizeof ss);
    char ip[INET6_ADDRSTRLEN];
    if (dest->atyp == VLESS_ADDR_IPV4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, dest->host_addr, 4);
        sin->sin_port = htons(dest->port);
        ss_len = sizeof *sin;
    } else if (dest->atyp == VLESS_ADDR_IPV6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, dest->host_addr, 16);
        sin6->sin6_port = htons(dest->port);
        ss_len = sizeof *sin6;
    } else {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        char port[8];
        snprintf(port, sizeof port, "%u", (unsigned)dest->port);
        if (net_getaddrinfo_timed(dest->domain, port, &hints, &res, 3000) != 0 || !res)
            return -1;
        memcpy(&ss, res->ai_addr, res->ai_addrlen);
        ss_len = res->ai_addrlen;
        freeaddrinfo(res);
    }
    if (ss.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&ss;
        if (!inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip)) return -1;
        if (lp->bypass && lp->bypass(lp->route_ctx, ip) != 0) return -1;
    } else if (lp->bypass) {
        /* the firewall bypass is ipv4 only */
        if (lp->bypass(lp->route_ctx, NULL) != 0) return -1;
    }

    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_nonblock(fd);
    int r = connect(fd, (struct sockaddr *)&ss, ss_len);
    if (r != 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (r != 0) {
        struct pollfd w;
        w.fd = fd; w.events = POLLOUT; w.revents = 0;
        int pr;
        do { pr = poll(&w, 1, LOOP_DIRECT_CONNECT_MS); } while (pr < 0 && errno == EINTR);
        int err = 0;
        socklen_t el = sizeof err;
        if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    set_keepalive(fd);
    return fd;
}

static void *direct_worker_main(void *arg) {
    loop_conn_t *c = (loop_conn_t *)arg;
    loop_t *lp = c->owner;
    int fd = direct_dial(lp, &c->tproxy_dest);
    pthread_mutex_lock(&lp->open_lock);
    c->remote_fd = fd;
    /* any non-null handle means the open worked */
    c->open_th = fd >= 0 ? (void *)c : NULL;
    c->open_done = 1;
    pthread_mutex_unlock(&lp->open_lock);
    wake_loop(lp);
    return NULL;
}

static void *open_worker_main(void *arg) {
    loop_conn_t *c = (loop_conn_t *)arg;
    loop_t *lp = c->owner;
    void *th = NULL;

/* the upstream just refused this request: give it a moment */
    if (c->redialing)
        usleep((useconds_t)(LOOP_REDIAL_WAIT_MS * 1000 * c->redials));

/* keep retries short */
    for (int attempt = 0; attempt < 3; ++attempt) {
        pthread_mutex_lock(&lp->open_lock);
        int cancelled = c->open_cancelled;
        pthread_mutex_unlock(&lp->open_lock);
        if (cancelled) break;
        if (attempt > 0) {
            usleep((useconds_t)(30000 * attempt));
            pthread_mutex_lock(&lp->open_lock);
            cancelled = c->open_cancelled;
            pthread_mutex_unlock(&lp->open_lock);
            if (cancelled) break;
        }
        if (c->remote_fd < 0) {
            int rfd = lp->dial(lp->dial_ctx);
            if (rfd < 0) continue;
            set_nonblock(rfd);
            set_keepalive(rfd);
/* publish the fd under the lock, so a cancel that came during the dial is
   seen here and a later one can shut the fd down to end the handshake */
            pthread_mutex_lock(&lp->open_lock);
            c->remote_fd = rfd;
            cancelled = c->open_cancelled;
            pthread_mutex_unlock(&lp->open_lock);
            if (cancelled) break;
        }
        th = c->open_vt->open(c->remote_fd, &c->open_tls_cfg);
        if (th) break;
        pthread_mutex_lock(&lp->open_lock);
        close(c->remote_fd);
        c->remote_fd = -1;
        pthread_mutex_unlock(&lp->open_lock);
    }

    pthread_mutex_lock(&lp->open_lock);
    c->open_th = th;
    c->open_done = 1;
    pthread_mutex_unlock(&lp->open_lock);

    wake_loop(lp);
    return NULL;
}

loop_status_t loop_init(loop_t *lp, uint16_t listen_port, int bind_public,
                        const transport_vt_t *vt,
                        loop_dialer_fn dial, void *dial_ctx,
                        vl_proto_t proto,
                        const uint8_t uuid[VLESS_UUID_LEN], const char *flow,
                        const char *user, const char *pass) {
    if (!lp || !vt || !dial) return LOOP_ERR_ARG;
    if (cfg_proto_uses_uuid(proto) && !uuid) return LOOP_ERR_ARG;
    memset(lp, 0, sizeof *lp);
    lp->listen_fd = -1;
    lp->tproxy_fd = -1;
    lp->wake_rd = -1;
    lp->wake_wr = -1;
    lp->vt = vt;
    lp->dial = dial;
    lp->dial_ctx = dial_ctx;
    lp->proto = proto;
    if (uuid) memcpy(lp->uuid, uuid, VLESS_UUID_LEN);
    if (flow && flow[0]) {
        size_t fl = strlen(flow);
        if (fl >= sizeof lp->flow) fl = sizeof lp->flow - 1;
        memcpy(lp->flow, flow, fl);
        lp->flow[fl] = '\0';
    }
    if (user) {
        size_t ul = strlen(user);
        if (ul >= sizeof lp->user) ul = sizeof lp->user - 1;
        memcpy(lp->user, user, ul);
        lp->user[ul] = '\0';
    }
    if (pass) {
        size_t pl = strlen(pass);
        if (pl >= sizeof lp->pass) pl = sizeof lp->pass - 1;
        memcpy(lp->pass, pass, pl);
        lp->pass[pl] = '\0';
    }

    /* point transport fields at buffers owned by the loop */
    lp->tls_cfg.sni         = lp->sni;
    lp->tls_cfg.fingerprint = lp->fingerprint;
    lp->tls_cfg.reality_pbk = lp->reality_pbk;
    lp->tls_cfg.reality_sid = lp->reality_sid;
    lp->tls_cfg.path        = lp->path;
    lp->tls_cfg.ws_host     = lp->ws_host;
    lp->tls_cfg.xhttp_mode  = lp->xhttp_mode;
    lp->tls_cfg.peer_host   = lp->peer_host;

    /* command-line mode starts active; managed mode selects a server later */
    lp->active = 1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return LOOP_ERR_BIND;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    uint16_t ports[22];
    size_t nports = 0;
    if (listen_port == 0) {
        ports[nports++] = 0;
    } else {
        for (int off = 0; off < 20 && nports < 22; ++off)
            ports[nports++] = (uint16_t)(listen_port + off);
        ports[nports++] = 0;
    }

    uint32_t bind_addr = bind_public ? INADDR_ANY : htonl(INADDR_LOOPBACK);
    int bound = 0;
    for (size_t pi = 0; pi < nports; ++pi) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = bind_addr;
        addr.sin_port = htons(ports[pi]);
        if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0)
            continue;
        if (listen(fd, 32) != 0) {
            close(fd);
            fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) return LOOP_ERR_BIND;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
            continue;
        }
        bound = 1;
        break;
    }
    if (!bound) {
        close(fd);
        return LOOP_ERR_BIND;
    }
    set_nonblock(fd);
    lp->listen_fd = fd;

    int pfd[2];
    if (pipe(pfd) != 0) {
        close(fd);
        lp->listen_fd = -1;
        return LOOP_ERR_BIND;
    }
    set_nonblock(pfd[0]);
    set_nonblock(pfd[1]);
    lp->wake_rd = pfd[0];
    lp->wake_wr = pfd[1];
    if (pthread_mutex_init(&lp->open_lock, NULL) != 0) {
        close(lp->wake_rd);
        close(lp->wake_wr);
        close(fd);
        lp->listen_fd = lp->wake_rd = lp->wake_wr = -1;
        return LOOP_ERR_BIND;
    }
    lp->open_lock_ready = 1;
    return LOOP_OK;
}

uint16_t loop_listen_port(const loop_t *lp) {
    if (!lp) return 0;
    struct sockaddr_in addr;
    socklen_t len = sizeof addr;
    if (getsockname(lp->listen_fd, (struct sockaddr *)&addr, &len) != 0) return 0;
    return ntohs(addr.sin_port);
}

static void copy_field(char *dst, size_t cap, const char *src) {
    if (!src) { dst[0] = '\0'; return; }
    size_t l = strlen(src);
    if (l >= cap) l = cap - 1;
    memcpy(dst, src, l);
    dst[l] = '\0';
}

void loop_set_tls(loop_t *lp, const char *sni, const char *fingerprint,
                  const char *reality_pbk, const char *reality_sid,
                  const char *path, const char *ws_host,
                  const char *xhttp_mode, const char *peer_host, int insecure) {
    if (!lp) return;
    copy_field(lp->sni,          sizeof lp->sni,          sni);
    copy_field(lp->fingerprint,  sizeof lp->fingerprint,  fingerprint);
    copy_field(lp->reality_pbk,  sizeof lp->reality_pbk,  reality_pbk);
    copy_field(lp->reality_sid,  sizeof lp->reality_sid,  reality_sid);
    copy_field(lp->path,         sizeof lp->path,         path);
    copy_field(lp->ws_host,      sizeof lp->ws_host,      ws_host);
    copy_field(lp->xhttp_mode,   sizeof lp->xhttp_mode,   xhttp_mode);
    copy_field(lp->peer_host,    sizeof lp->peer_host,    peer_host);
    lp->insecure = insecure;
    lp->tls_cfg.sni = lp->sni;
    lp->tls_cfg.fingerprint = lp->fingerprint;
    lp->tls_cfg.reality_pbk = lp->reality_pbk;
    lp->tls_cfg.reality_sid = lp->reality_sid;
    lp->tls_cfg.path = lp->path;
    lp->tls_cfg.ws_host = lp->ws_host;
    lp->tls_cfg.xhttp_mode = lp->xhttp_mode;
    lp->tls_cfg.peer_host = lp->peer_host;
    lp->tls_cfg.insecure = lp->insecure;
}

void loop_set_xhttp(loop_t *lp, const transport_xhttp_opts_t *xh) {
    if (!lp) return;
    if (xh) lp->tls_cfg.xh = *xh;
    else memset(&lp->tls_cfg.xh, 0, sizeof lp->tls_cfg.xh);
}

/* a connection's buffers run to a couple of hundred kilobytes, so a slot is
   only allocated while it is in use. a fixed array of them kept tens of
   megabytes resident in a daemon on a phone with 256 MB in all */
static loop_conn_t *alloc_conn(loop_t *lp) {
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (c && c->used) continue;
        if (!c) {
            c = (loop_conn_t *)malloc(sizeof *c);
            if (!c) return NULL;
            lp->conns[i] = c;
        }
        memset(c, 0, sizeof *c);
        c->owner = lp;
        c->local_fd = -1;
        c->remote_fd = -1;
        c->last_io_ms = loop_now_ms();
        return c;
    }
    return NULL;
}

/* slots are released outside dispatch, so no pointer taken during one poll
   round can outlive its memory */
static void free_unused_slots(loop_t *lp) {
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (c && !c->used) {
            free(c);
            lp->conns[i] = NULL;
        }
    }
}

static int flush_pend_local(loop_conn_t *c);
static int flush_to_local(loop_conn_t *c);
static void cancel_opening_conn(loop_t *lp, loop_conn_t *c);

static void clear_conn_slot(loop_conn_t *c) {
    loop_t *owner = c->owner;
    memset(c, 0, sizeof *c);
    c->owner = owner;
    c->local_fd = c->remote_fd = -1;
}

static int pend_append(loop_conn_t *c, const uint8_t *buf, size_t len) {
    if (!c || !buf || len == 0) return 0;
    if (c->pend_len + len > sizeof c->pend) return -1;
    memcpy(c->pend + c->pend_len, buf, len);
    c->pend_len += len;
    return 0;
}

static int read_local_into_prebuf(loop_conn_t *c) {
    uint8_t buf[256];
    for (;;) {
        size_t room = sizeof c->prebuf - c->prebuf_len;
        if (room == 0) return 0;
        size_t want = room < sizeof buf ? room : sizeof buf;
        ssize_t n = read(c->local_fd, buf, want);
        if (n > 0) {
            c->owner->bytes_up += (uint64_t)n;
            memcpy(c->prebuf + c->prebuf_len, buf, (size_t)n);
            c->prebuf_len += (size_t)n;
            continue;
        }
        if (n == 0) return -1;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) continue;
        return -1;
    }
}

/* the socks greeting and request are answered locally, before the remote
   transport is open. the request bytes stay in prebuf for the session (or
   are dropped for a direct relay); the session's own reply is skipped later.
   -1 means the client spoke something that is not socks */
static int socks_early(loop_conn_t *c) {
    if (c->transparent) return 0;
    if (!c->socks_greet_done && c->prebuf_len > 0) {
        size_t used = 0;
        s5_status_t gr = socks5_parse_greeting(c->prebuf, c->prebuf_len, &used);
        if (gr == S5_NEED_MORE) return 0;
        if (gr != S5_OK) return -1;
        uint8_t reply[2];
        size_t rn = 0;
        if (socks5_build_method_reply(reply, sizeof reply, &rn) != S5_OK ||
            pend_append(c, reply, rn) != 0 || flush_pend_local(c) != 0)
            return -1;
        c->socks_greet_done = 1;
        memmove(c->prebuf, c->prebuf + used, c->prebuf_len - used);
        c->prebuf_len -= used;
    }
    if (c->socks_greet_done && !c->socks_req_done && c->prebuf_len > 0) {
        vless_dest_t dest;
        size_t used = 0;
        s5_status_t rr = socks5_parse_request(c->prebuf, c->prebuf_len, &dest, &used);
        if (rr == S5_NEED_MORE) return 0;
        /* anything odd is left for the session, which answers it properly */
        if (rr != S5_OK) { c->socks_req_done = 1; return 0; }
        uint8_t rep[10];
        size_t rn = 0;
        if (socks5_build_reply(SOCKS5_REP_OK, rep, sizeof rep, &rn) != S5_OK ||
            pend_append(c, rep, rn) != 0 || flush_pend_local(c) != 0)
            return -1;
        c->socks_req_done = 1;
        c->socks_req_len = used;
        c->socks_reply_skip = rn;
        c->tproxy_dest = dest;
    }
    return 0;
}

/* answer SOCKS while the worker opens the remote transport */
static void service_opening_local(loop_t *lp, loop_conn_t *c, short local_re) {
    if (local_re & (POLLHUP | POLLERR)) {
        cancel_opening_conn(lp, c);
        return;
    }
    if (local_re & POLLOUT) {
        if (flush_pend_local(c) != 0)
            cancel_opening_conn(lp, c);
    }
    if (local_re & POLLIN) {
        if (read_local_into_prebuf(c) != 0) {
            cancel_opening_conn(lp, c);
            return;
        }
    }
    /* a direct relay has no session to read the socks request later */
    if (!c->direct && socks_early(c) != 0) cancel_opening_conn(lp, c);
}

static void cancel_opening_conn(loop_t *lp, loop_conn_t *c) {
    if (!c->used || !c->opening) return;
    pthread_mutex_lock(&lp->open_lock);
    c->open_cancelled = 1;
    /* wake the worker without reusing its remote fd */
    if (c->remote_fd >= 0)
        shutdown(c->remote_fd, SHUT_RDWR);
    pthread_mutex_unlock(&lp->open_lock);
    if (c->local_fd >= 0) {
        close(c->local_fd);
        c->local_fd = -1;
    }
}

static void discard_conn(loop_conn_t *c);

static void drop_conn(loop_t *lp, loop_conn_t *c) {
    if (!c->used) return;
    if (c->opening) {
        cancel_opening_conn(lp, c);
        return;
    }
    if (c->sniffing) {
        discard_conn(c);
        return;
    }
    if (!c->direct) {
        if (c->relay_clean && c->th && c->open_vt && c->open_vt->shutdown)
            c->open_vt->shutdown(c->th);
        /* client bytes the session never took say where a stall sat */
        char why[48];
        snprintf(why, sizeof why, "drop held=%zu", c->prebuf_len);
        session_trace_close(&c->sess, why);
        if (c->sess.state == SESS_ERROR)
            fprintf(stderr, "legacyrayd: dropping errored session\n");
        if (c->th && c->open_vt) c->open_vt->close(c->th);
    }
    if (c->remote_fd >= 0) close(c->remote_fd);
    if (c->local_fd >= 0)  close(c->local_fd);
    clear_conn_slot(c);
    if (lp->nconns > 0) lp->nconns--;
}

/* drop connections when switching servers; keep the listener open */
static void drop_all_conns(loop_t *lp) {
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (!c || !c->used) continue;
        if (c->opening) cancel_opening_conn(lp, c);
        else drop_conn(lp, c);
    }
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (!c || !c->used || !c->opening) continue;
        pthread_join(c->open_thread, NULL);
        c->opening = 0;
        c->open_done = 0;
        c->open_th = NULL;
        if (lp->nopening > 0) lp->nopening--;
        if (c->remote_fd >= 0) close(c->remote_fd);
        if (c->local_fd >= 0) close(c->local_fd);
        clear_conn_slot(c);
    }
}

static void reap_opening_conns(loop_t *lp) {
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (!c || !c->used || !c->opening) continue;

        pthread_mutex_lock(&lp->open_lock);
        int done = c->open_done;
        int cancelled = c->open_cancelled;
        void *th = c->open_th;
        pthread_mutex_unlock(&lp->open_lock);
        if (!done) continue;

        pthread_join(c->open_thread, NULL);
        c->opening = 0;
        c->open_done = 0;
        c->open_th = NULL;
        if (lp->nopening > 0) lp->nopening--;

        if (cancelled || !th) {
            if (!cancelled && !th)
                fprintf(stderr, "legacyrayd: %s open failed (tproxy=%d)\n",
                        c->direct ? "direct" : "transport", c->transparent);
            if (c->local_fd >= 0) close(c->local_fd);
            if (th && c->open_vt && !c->direct) c->open_vt->close(th);
            if (c->remote_fd >= 0) close(c->remote_fd);
            clear_conn_slot(c);
            continue;
        }

        if (c->direct) {
            /* raw relay: the socks request was for the daemon, not the site */
            if (!c->transparent && c->socks_req_len) {
                size_t drop = c->socks_req_len < c->prebuf_len ? c->socks_req_len
                                                               : c->prebuf_len;
                memmove(c->prebuf, c->prebuf + drop, c->prebuf_len - drop);
                c->prebuf_len -= drop;
                c->socks_req_len = 0;
            }
            c->last_io_ms = loop_now_ms();
            lp->nconns++;
            continue;
        }

        c->th = th;
        sess_status_t ir;
        if (c->redialing) {
            c->redialing = 0;
            ir = session_restart_upstream(&c->sess, th);
        } else if (c->transparent) {
            ir = session_init(&c->sess, c->open_vt, th, c->open_proto,
                              cfg_proto_uses_uuid(c->open_proto) ? c->open_uuid : NULL,
                              c->open_flow[0] ? c->open_flow : NULL,
                              c->open_user[0] ? c->open_user : NULL,
                              c->open_pass[0] ? c->open_pass : NULL);
            if (ir == SESS_OK) {
                size_t pu = 0;
                ir = session_start_from_transparent_dest(&c->sess, &c->tproxy_dest,
                                                         c->prebuf, c->prebuf_len, &pu);
                if (ir == SESS_OK && pu > 0) {
                    memmove(c->prebuf, c->prebuf + pu, c->prebuf_len - pu);
                    c->prebuf_len -= pu;
                }
            }
        } else if (c->socks_greet_done) {
            ir = session_init_after_greet(&c->sess, c->open_vt, th, c->open_proto,
                                          cfg_proto_uses_uuid(c->open_proto) ? c->open_uuid : NULL,
                                          c->open_flow[0] ? c->open_flow : NULL,
                                          c->open_user[0] ? c->open_user : NULL,
                                          c->open_pass[0] ? c->open_pass : NULL);
        } else {
            ir = session_init(&c->sess, c->open_vt, th, c->open_proto,
                              cfg_proto_uses_uuid(c->open_proto) ? c->open_uuid : NULL,
                              c->open_flow[0] ? c->open_flow : NULL,
                              c->open_user[0] ? c->open_user : NULL,
                              c->open_pass[0] ? c->open_pass : NULL);
        }
        if (ir != SESS_OK) {
            fprintf(stderr, "legacyrayd: session start failed (%s, proto %d)\n",
                    c->transparent ? "redirected" : "socks", (int)c->open_proto);
            if (c->open_vt) c->open_vt->close(th);
            if (c->remote_fd >= 0) close(c->remote_fd);
            if (c->local_fd >= 0) close(c->local_fd);
            clear_conn_slot(c);
            continue;
        }

        if (c->prebuf_len > 0) {
            size_t off = 0;
            while (off < c->prebuf_len) {
                size_t consumed = 0;
                if (session_feed_client(&c->sess, c->prebuf + off,
                                        c->prebuf_len - off, &consumed) != SESS_OK)
                    break;
                if (consumed == 0) break;
                off += consumed;
            }
            if (off > 0) {
                memmove(c->prebuf, c->prebuf + off, c->prebuf_len - off);
                c->prebuf_len -= off;
            }
            if (flush_to_local(c) != 0) {
                drop_conn(lp, c);
                continue;
            }
        }
        lp->nconns++;
    }
}

loop_status_t loop_set_server(loop_t *lp, const transport_vt_t *vt,
                              loop_dialer_fn dial, void *dial_ctx,
                              vl_proto_t proto,
                              const uint8_t uuid[VLESS_UUID_LEN], const char *flow,
                              const char *user, const char *pass,
                              const char *sni, const char *fingerprint,
                              const char *reality_pbk, const char *reality_sid,
                              const char *path, const char *ws_host,
                              const char *xhttp_mode, const char *peer_host,
                              int insecure) {
    if (!lp || !vt || !dial) return LOOP_ERR_ARG;
    if (cfg_proto_uses_uuid(proto) && !uuid) return LOOP_ERR_ARG;

    /* drop connections before switching servers */
    drop_all_conns(lp);
    lp->bytes_up = lp->bytes_down = 0;

    lp->vt = vt;
    lp->dial = dial;
    lp->dial_ctx = dial_ctx;
    lp->proto = proto;
    if (uuid) {
        memcpy(lp->uuid, uuid, VLESS_UUID_LEN);
    } else {
        memset(lp->uuid, 0, sizeof lp->uuid);
    }
    copy_field(lp->flow, sizeof lp->flow, (flow && flow[0]) ? flow : NULL);
    copy_field(lp->user, sizeof lp->user, (user && user[0]) ? user : NULL);
    copy_field(lp->pass, sizeof lp->pass, (pass && pass[0]) ? pass : NULL);

    loop_set_tls(lp, sni, fingerprint, reality_pbk, reality_sid, path, ws_host,
                 xhttp_mode, peer_host, insecure);
    loop_set_xhttp(lp, NULL); /* the caller sets the new server's, if any */

    lp->active = 1; /* accept clients again */
    return LOOP_OK;
}

void loop_stop(loop_t *lp) {
    if (!lp) return;
    drop_all_conns(lp);
    lp->bytes_up = lp->bytes_down = 0;
    lp->active = 0; /* refuse new clients until a server is selected again */
}

static loop_status_t loop_enable_tproxy_mode(loop_t *lp, uint16_t port,
                                             int sockname_dest) {
    if (!lp || port == 0) return LOOP_ERR_ARG;
    loop_disable_tproxy(lp);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return LOOP_ERR_BIND;

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = sockname_dest ? htonl(INADDR_ANY)
                                          : htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(fd, 32) != 0) {
        close(fd);
        return LOOP_ERR_BIND;
    }
    set_nonblock(fd);
    lp->tproxy_fd = fd;
    lp->tproxy_port = port;
    lp->tproxy_sockname = sockname_dest;
    return LOOP_OK;
}

loop_status_t loop_enable_tproxy(loop_t *lp, uint16_t port) {
    return loop_enable_tproxy_mode(lp, port, 0);
}

loop_status_t loop_enable_tproxy_sockname(loop_t *lp, uint16_t port) {
    return loop_enable_tproxy_mode(lp, port, 1);
}

void loop_disable_tproxy(loop_t *lp) {
    if (!lp) return;
    if (lp->tproxy_fd >= 0) {
        close(lp->tproxy_fd);
        lp->tproxy_fd = -1;
        lp->tproxy_port = 0;
        lp->tproxy_sockname = 0;
    }
    pf_natlook_close();
}

static void fill_open_fields(loop_t *lp, loop_conn_t *c) {
    c->open_vt = lp->vt;
    c->open_proto = lp->proto;
    memcpy(c->open_uuid, lp->uuid, sizeof c->open_uuid);
    copy_field(c->open_flow, sizeof c->open_flow, lp->flow[0] ? lp->flow : NULL);
    copy_field(c->open_user, sizeof c->open_user, lp->user[0] ? lp->user : NULL);
    copy_field(c->open_pass, sizeof c->open_pass, lp->pass[0] ? lp->pass : NULL);
    copy_field(c->open_sni, sizeof c->open_sni, lp->sni);
    copy_field(c->open_fingerprint, sizeof c->open_fingerprint, lp->fingerprint);
    copy_field(c->open_reality_pbk, sizeof c->open_reality_pbk, lp->reality_pbk);
    copy_field(c->open_reality_sid, sizeof c->open_reality_sid, lp->reality_sid);
    copy_field(c->open_path, sizeof c->open_path, lp->path);
    copy_field(c->open_ws_host, sizeof c->open_ws_host, lp->ws_host);
    copy_field(c->open_xhttp_mode, sizeof c->open_xhttp_mode, lp->xhttp_mode);
    copy_field(c->open_peer_host, sizeof c->open_peer_host, lp->peer_host);
    c->open_insecure = lp->insecure;
    c->open_tls_cfg.sni = c->open_sni;
    c->open_tls_cfg.fingerprint = c->open_fingerprint;
    c->open_tls_cfg.reality_pbk = c->open_reality_pbk;
    c->open_tls_cfg.reality_sid = c->open_reality_sid;
    c->open_tls_cfg.path = c->open_path;
    c->open_tls_cfg.ws_host = c->open_ws_host;
    c->open_tls_cfg.xhttp_mode = c->open_xhttp_mode;
    c->open_tls_cfg.peer_host = c->open_peer_host;
    c->open_tls_cfg.insecure = c->open_insecure;
    c->open_tls_cfg.xh = lp->tls_cfg.xh;
    c->open_tls_cfg.handshake_ms = LOOP_OPEN_HANDSHAKE_MS;
}

/* hand a connection whose client socket is set to a worker that dials and
   opens the tunnel transport */
static int begin_open(loop_t *lp, loop_conn_t *c) {
    if (lp->nopening >= LOOP_MAX_OPENING) {
        fprintf(stderr, "legacyrayd: drop: opening cap %zu\n", lp->nopening);
        return -1;
    }
    /* the worker dials: a name lookup for the server must never stall the
       loop that carries every other connection */
    c->remote_fd = -1;
    if (!c->direct) fill_open_fields(lp, c);
    c->sniffing = 0;
    c->opening = 1;
    lp->nopening++;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, LOOP_OPEN_STACK_SZ);
    int cr = pthread_create(&c->open_thread, &attr,
                            c->direct ? direct_worker_main : open_worker_main, c);
    pthread_attr_destroy(&attr);
    if (cr != 0) {
        lp->nopening--;
        c->opening = 0;
        if (c->remote_fd >= 0) close(c->remote_fd);
        c->remote_fd = -1;
        return -1;
    }
    return 0;
}

static void discard_conn(loop_conn_t *c) {
    if (c->local_fd >= 0) close(c->local_fd);
    if (c->remote_fd >= 0) close(c->remote_fd);
    clear_conn_slot(c);
}

/* the upstream proxy hung up before it answered, so nothing reached the
   site yet: the session keeps the request and the client's bytes, and a
   worker opens a new connection for them. -1 leaves the conn as it was */
static int redial_conn(loop_t *lp, loop_conn_t *c) {
    if (!session_upstream_refused(&c->sess) || c->redials >= LOOP_REDIALS)
        return -1;
    if (c->th && c->open_vt) c->open_vt->close(c->th);
    c->th = NULL;
    c->sess.th = NULL;
    if (c->remote_fd >= 0) close(c->remote_fd);
    c->remote_fd = -1;
    c->redials++;
    c->redialing = 1;
/* the client's socks exchange is over whoever answered it; what it sends
   while the worker opens is payload, not a request to parse */
    c->socks_greet_done = 1;
    c->socks_req_done = 1;
    if (lp->nconns > 0) lp->nconns--;
    fprintf(stderr, "legacyrayd: upstream closed before its reply, dialing again (%d)\n",
            c->redials);
    if (begin_open(lp, c) != 0) {
        session_trace_close(&c->sess, "redial");
        discard_conn(c);
    }
    return 0;
}

static void route_log(const loop_conn_t *c, const char *host, loop_route_t r) {
    char addr[INET6_ADDRSTRLEN] = "?";
    const vless_dest_t *d = &c->tproxy_dest;
    if (d->atyp == VLESS_ADDR_IPV4) inet_ntop(AF_INET, d->host_addr, addr, sizeof addr);
    else if (d->atyp == VLESS_ADDR_IPV6) inet_ntop(AF_INET6, d->host_addr, addr, sizeof addr);
    else snprintf(addr, sizeof addr, "%.40s", d->domain);
    if (r == LOOP_ROUTE_PROXY) return; /* the common case stays out of the log */
    fprintf(stderr, "legacyrayd: route %s:%u%s%s -> %s\n", addr, (unsigned)d->port,
            host && host[0] ? " " : "", host ? host : "",
            r == LOOP_ROUTE_DIRECT ? "direct" : "block");
}

/* the router's answer for a connection whose destination is known */
static void apply_route(loop_t *lp, loop_conn_t *c, loop_route_t r, const char *host) {
    route_log(c, host, r);
    if (r == LOOP_ROUTE_BLOCK) {
        discard_conn(c);
        return;
    }
    c->direct = (r == LOOP_ROUTE_DIRECT);
    if (begin_open(lp, c) != 0) discard_conn(c);
}

/* the destination is known (transparent redirect, or a socks request read
   early): ask the router, and either decide or start waiting for the name */
static void route_known(loop_t *lp, loop_conn_t *c) {
    loop_route_t r = lp->route ? lp->route(lp->route_ctx, &c->tproxy_dest, NULL)
                               : LOOP_ROUTE_PROXY;
    if (r != LOOP_ROUTE_SNIFF) {
        apply_route(lp, c, r, NULL);
        return;
    }
    c->sniffing = 2; /* destination known, waiting for the site name */
    c->sniff_deadline_ms = loop_now_ms() + LOOP_SNIFF_MS;
}

/* look at what the client sent so far. force decides with whatever is there */
static void try_sniff(loop_t *lp, loop_conn_t *c, int force) {
    size_t off = c->transparent ? 0 : c->socks_req_len;
    char host[256];
    sniff_status_t st = c->prebuf_len > off
        ? sniff_host(c->prebuf + off, c->prebuf_len - off, sizeof c->prebuf - off,
                     host, sizeof host)
        : SNIFF_NEED_MORE;
    if (st == SNIFF_NEED_MORE && !force) return;
    if (st != SNIFF_FOUND) host[0] = '\0';
    loop_route_t r = lp->route ? lp->route(lp->route_ctx, &c->tproxy_dest, host)
                               : LOOP_ROUTE_PROXY;
    if (r == LOOP_ROUTE_SNIFF) r = LOOP_ROUTE_PROXY;
    apply_route(lp, c, r, host);
}

/* a connection that has not been handed to a worker yet: socks handshake,
   then the first client bytes for the router */
static void service_sniffing(loop_t *lp, loop_conn_t *c, short local_re) {
    if (local_re & POLLOUT) {
        if (flush_pend_local(c) != 0) { discard_conn(c); return; }
    }
    if (local_re & POLLIN) {
        if (read_local_into_prebuf(c) != 0) {
            /* a client that closed before saying anything has nothing to route */
            discard_conn(c);
            return;
        }
    } else if (local_re & (POLLHUP | POLLERR)) {
        discard_conn(c);
        return;
    }
    if (c->sniffing == 1) {
        if (socks_early(c) != 0) { discard_conn(c); return; }
        if (!c->socks_req_done) return;
        if (!c->socks_reply_skip) {
            /* a request the early parser did not take: the tunnel session
               answers it */
            apply_route(lp, c, LOOP_ROUTE_PROXY, NULL);
            return;
        }
        route_known(lp, c);
        if (c->used && c->sniffing == 2) try_sniff(lp, c, 0);
        return;
    }
    try_sniff(lp, c, c->prebuf_len >= sizeof c->prebuf);
}

static void sniff_deadlines(loop_t *lp) {
    long now = 0;
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (!c || !c->used || !c->sniffing) continue;
        if (!now) now = loop_now_ms();
        if (now < c->sniff_deadline_ms) continue;
        if (c->sniffing == 2) try_sniff(lp, c, 1);
        else discard_conn(c); /* a socks client that never finished its request */
    }
}

static loop_conn_t *new_client(loop_t *lp, int cfd, const char *what) {
    loop_conn_t *c = alloc_conn(lp);
    if (!c) {
        fprintf(stderr, "legacyrayd: drop %s: conn cap\n", what);
        return NULL;
    }
    set_nonblock(cfd);
    c->local_fd = cfd;
    c->used = 1;
    return c;
}

static void accept_one(loop_t *lp) {
    int cfd = accept(lp->listen_fd, NULL, NULL);
    if (cfd < 0) return;

    /* refuse clients until a server is selected */
    if (!lp->active || !lp->vt || !lp->dial) { close(cfd); return; }

    loop_conn_t *c = new_client(lp, cfd, "accept");
    if (!c) { close(cfd); return; }
    if (lp->route) {
        /* the socks request comes first, the router needs its address */
        c->sniffing = 1;
        c->sniff_deadline_ms = loop_now_ms() + 5000;
        return;
    }
    if (begin_open(lp, c) != 0) discard_conn(c);
}

static void accept_tproxy_one(loop_t *lp) {
    struct sockaddr_in clientaddr;
    socklen_t addrlen = sizeof clientaddr;
    int cfd = accept(lp->tproxy_fd, (struct sockaddr *)&clientaddr, &addrlen);
    if (cfd < 0) return;

    if (!lp->active || !lp->vt || !lp->dial) { close(cfd); return; }

    char host[INET_ADDRSTRLEN];
    uint16_t dport = 0;
    if (lp->tproxy_sockname) {
        struct sockaddr_in dest;
        socklen_t destlen = sizeof dest;
        if (getsockname(cfd, (struct sockaddr *)&dest, &destlen) != 0 ||
            dest.sin_family != AF_INET ||
            !inet_ntop(AF_INET, &dest.sin_addr, host, sizeof host)) {
            close(cfd);
            return;
        }
        dport = ntohs(dest.sin_port);
        /* the wildcard bind that ipfw fwd needs is reachable from the network,
           and a direct connection to it carries no original destination, so it
           would either relay to this listener forever or hand a stranger an
           open proxy */
        if (dport == lp->tproxy_port) {
            close(cfd);
            return;
        }
    } else if (pf_natlook_dest(cfd, &clientaddr, lp->tproxy_port,
                               host, sizeof host, &dport) != 0) {
        close(cfd);
        return;
    }

    lp->tproxy_accept_generation++;
    snprintf(lp->tproxy_last_host, sizeof lp->tproxy_last_host, "%s", host);
    lp->tproxy_last_port = dport;

    loop_conn_t *c = new_client(lp, cfd, "tproxy");
    if (!c) { close(cfd); return; }

    memset(&c->tproxy_dest, 0, sizeof c->tproxy_dest);
    c->tproxy_dest.port = dport;
    struct in_addr ia;
    if (inet_pton(AF_INET, host, &ia) == 1) {
        c->tproxy_dest.atyp = VLESS_ADDR_IPV4;
        memcpy(c->tproxy_dest.host_addr, &ia, sizeof ia);
    } else {
        c->tproxy_dest.atyp = VLESS_ADDR_DOMAIN;
        snprintf(c->tproxy_dest.domain, sizeof c->tproxy_dest.domain, "%s", host);
    }
    c->transparent = 1;
    route_known(lp, c);
}

/* flush queued bytes without blocking */
static int flush_pend_local(loop_conn_t *c) {
    while (c->pend_off < c->pend_len) {
        ssize_t w = write(c->local_fd, c->pend + c->pend_off,
                          c->pend_len - c->pend_off);
        if (w > 0) {
            c->owner->bytes_down += (uint64_t)w;
            c->pend_off += (size_t)w;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) continue;
        return -1;
    }
    c->pend_off = c->pend_len = 0;
    return 0;
}

static int flush_to_local(loop_conn_t *c) {
    while (c->pend_off < c->pend_len) {
        ssize_t w = write(c->local_fd, c->pend + c->pend_off,
                          c->pend_len - c->pend_off);
        if (w > 0) {
            c->owner->bytes_down += (uint64_t)w;
            c->pend_off += (size_t)w;
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; /* try later */
        if (errno == EINTR) continue;
        return -1;
    }
    c->pend_off = c->pend_len = 0; /* fully drained, reset */

    for (;;) {
        size_t n = session_take_client(&c->sess, c->pend, sizeof c->pend);
        if (n == 0) return 0; /* session has nothing more */
        c->pend_len = n;
        c->pend_off = 0;
        if (c->socks_reply_skip) {
            /* the client already has its socks reply */
            size_t skip = c->socks_reply_skip < n ? c->socks_reply_skip : n;
            c->socks_reply_skip -= skip;
            c->pend_off = skip;
        }
        while (c->pend_off < c->pend_len) {
            ssize_t w = write(c->local_fd, c->pend + c->pend_off,
                              c->pend_len - c->pend_off);
            if (w > 0) {
                c->owner->bytes_down += (uint64_t)w;
                c->pend_off += (size_t)w;
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; /* keep pend */
            if (errno == EINTR) continue;
            return -1;
        }
        c->pend_off = c->pend_len = 0;
    }
}

/* move what the client sent (kept in prebuf) to the destination */
static int direct_flush_up(loop_conn_t *c) {
    while (c->prebuf_len > 0) {
        ssize_t w = write(c->remote_fd, c->prebuf, c->prebuf_len);
        if (w > 0) {
            memmove(c->prebuf, c->prebuf + w, c->prebuf_len - (size_t)w);
            c->prebuf_len -= (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (w < 0 && errno == EINTR) continue;
        return -1;
    }
    if (c->local_eof) shutdown(c->remote_fd, SHUT_WR);
    return 0;
}

/* a relay around the tunnel: prebuf carries client bytes up, pend carries
   the site's bytes down, each side half closes when the other is done */
static void service_direct(loop_t *lp, loop_conn_t *c, short local_re, short remote_re) {
    int moved = 0;
    if ((local_re & POLLIN) && !c->local_eof && c->prebuf_len < sizeof c->prebuf) {
        size_t before = c->prebuf_len;
        /* -1 is the client's eof or a reset: either way it sends no more */
        if (read_local_into_prebuf(c) != 0) c->local_eof = 1;
        if (c->prebuf_len != before) moved = 1;
    }
    if (c->prebuf_len > 0 || (remote_re & POLLOUT) || c->local_eof) {
        if (direct_flush_up(c) != 0) { drop_conn(lp, c); return; }
    }
    if ((remote_re & (POLLIN | POLLHUP | POLLERR)) && !c->remote_eof &&
        c->pend_off >= c->pend_len) {
        ssize_t n = read(c->remote_fd, c->pend, sizeof c->pend);
        if (n > 0) {
            c->pend_len = (size_t)n;
            c->pend_off = 0;
            moved = 1;
        } else if (n == 0) {
            c->remote_eof = 1;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            drop_conn(lp, c);
            return;
        }
    }
    if (flush_pend_local(c) != 0) { drop_conn(lp, c); return; }
    if (c->remote_eof && c->pend_off >= c->pend_len) shutdown(c->local_fd, SHUT_WR);
    if (moved) c->last_io_ms = loop_now_ms();
    if ((c->local_eof && c->remote_eof && c->prebuf_len == 0 && c->pend_off >= c->pend_len) ||
        ((local_re & (POLLHUP | POLLERR)) && !(local_re & POLLIN) && c->remote_eof)) {
        drop_conn(lp, c);
    }
}

/* client bytes the session refused wait in prebuf, ahead of any new read */
static int feed_backlog(loop_conn_t *c) {
    size_t off = 0;
    while (off < c->prebuf_len) {
        size_t consumed = 0;
        sess_status_t fr = session_feed_client(&c->sess, c->prebuf + off,
                                               c->prebuf_len - off, &consumed);
        if (fr != SESS_OK) {
            if (c->sess.state == SESS_ERROR) return -1;
            break;
        }
        if (consumed == 0) break;
        off += consumed;
    }
    if (off > 0) {
        memmove(c->prebuf, c->prebuf + off, c->prebuf_len - off);
        c->prebuf_len -= off;
    }
    return 0;
}

static void service_conn(loop_t *lp, loop_conn_t *c,
                         short local_re, short remote_re) {
    if (c->direct) {
        service_direct(lp, c, local_re, remote_re);
        return;
    }
    c->last_io_ms = loop_now_ms();
/* pump remote output when it is ready */
    if (remote_re & (POLLIN | POLLOUT | POLLHUP | POLLERR)) {
        session_pump_remote(&c->sess);
        if (redial_conn(lp, c) == 0) return;
    }
    if (c->prebuf_len > 0 && feed_backlog(c) != 0) {
        drop_conn(lp, c);
        return;
    }

/* read only what the session can take: a refused tail used to be lost */
    size_t room = c->prebuf_len == 0 ? session_client_room(&c->sess) : 0;
    if ((local_re & POLLIN) && room > 0) {
        uint8_t buf[8192];
        ssize_t n = read(c->local_fd, buf, room < sizeof buf ? room : sizeof buf);
        if (n > 0) {
            lp->bytes_up += (uint64_t)n;
            size_t off = 0;
            while (off < (size_t)n) {
                size_t consumed = 0;
                sess_status_t fr = session_feed_client(&c->sess, buf + off,
                                                       (size_t)n - off, &consumed);
                if (fr != SESS_OK) {
                    if (c->sess.state == SESS_ERROR) {
                        drop_conn(lp, c);
                        return;
                    }
                }
                if (fr != SESS_OK || consumed == 0) { /* session backpressured */
                    memcpy(c->prebuf, buf + off, (size_t)n - off);
                    c->prebuf_len = (size_t)n - off;
                    session_pump_remote(&c->sess);
                    break;
                }
                off += consumed;
            }
        } else if (n == 0) {
            c->sess.state = (c->sess.state == SESS_RELAY) ? SESS_CLOSED : c->sess.state;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            drop_conn(lp, c);
            return;
        }
    }
    /* flush before handling hangup */
    int was_full = session_remote_room(&c->sess) == 0;
    if (flush_to_local(c) != 0) { drop_conn(lp, c); return; }
    /* a pump that stopped on a full client queue can leave bytes inside the
       transport (a websocket frame, a tls record) that no poll event will
       announce: pump again while the flush keeps making room */
    for (int i = 0; was_full && i < 8 && session_remote_room(&c->sess) > 0 &&
                    c->sess.state != SESS_ERROR; ++i) {
        size_t before = c->sess.to_client_len;
        session_pump_remote(&c->sess);
        if (c->sess.to_client_len == before) break;
        if (flush_to_local(c) != 0) { drop_conn(lp, c); return; }
    }

    if (local_re & (POLLHUP | POLLERR)) {
        drop_conn(lp, c);
        return;
    }
    if (redial_conn(lp, c) == 0) return;

    /* close only after the session and pending output are done */
    if (session_is_done(&c->sess) && c->pend_off >= c->pend_len) {
        c->relay_clean = 1;
        drop_conn(lp, c);
    }
}

static void drop_idle_conns(loop_t *lp) {
    long now = 0;
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (!c || !c->used || c->opening || c->sniffing) continue;
        if (!now) now = loop_now_ms();
        if (now - c->last_io_ms < LOOP_IDLE_MS) continue;
        fprintf(stderr, "legacyrayd: dropping a connection idle for %ld s\n",
                (now - c->last_io_ms) / 1000);
        drop_conn(lp, c);
    }
}

void loop_set_router(loop_t *lp, loop_route_fn route, loop_bypass_fn bypass,
                     void *ctx) {
    if (!lp) return;
    lp->route = route;
    lp->bypass = bypass;
    lp->route_ctx = ctx;
}

size_t loop_prepare(loop_t *lp, struct pollfd *pfd, size_t cap) {
    if (!lp || !pfd || cap < 3) return 0;
    reap_opening_conns(lp);
    sniff_deadlines(lp);
    drop_idle_conns(lp);
    free_unused_slots(lp);

    loop_conn_t **map = lp->poll_map;
    uint8_t *is_remote = lp->poll_remote;
    if (cap > LOOP_POLLFD_MAX) cap = LOOP_POLLFD_MAX;

    size_t nf = 0;
    pfd[nf].fd = lp->listen_fd;
    pfd[nf].events = POLLIN;
    pfd[nf].revents = 0;
    map[nf] = NULL; is_remote[nf] = 0;
    nf++;

    lp->poll_tproxy_idx = -1;
    if (lp->tproxy_fd >= 0) {
        lp->poll_tproxy_idx = (int)nf;
        pfd[nf].fd = lp->tproxy_fd;
        pfd[nf].events = POLLIN;
        pfd[nf].revents = 0;
        map[nf] = NULL; is_remote[nf] = 0;
        nf++;
    }

    lp->poll_wake_idx = nf;
    pfd[nf].fd = lp->wake_rd;
    pfd[nf].events = POLLIN;
    pfd[nf].revents = 0;
    map[nf] = NULL; is_remote[nf] = 0;
    nf++;

    lp->poll_conn_base = nf;

    for (size_t i = 0; i < LOOP_MAX_CONNS && nf + 2 <= cap; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (!c || !c->used) continue;

        if (c->sniffing) {
            short lev = POLLIN;
            if (c->pend_off < c->pend_len) lev |= POLLOUT;
            pfd[nf].fd = c->local_fd;
            pfd[nf].events = lev;
            pfd[nf].revents = 0;
            map[nf] = c; is_remote[nf] = 0;
            nf++;
            continue;
        }

        if (c->direct && !c->opening) {
            short lev = 0;
            if (!c->local_eof && c->prebuf_len < sizeof c->prebuf) lev |= POLLIN;
            if (c->pend_off < c->pend_len) lev |= POLLOUT;
            pfd[nf].fd = c->local_fd;
            pfd[nf].events = lev;
            pfd[nf].revents = 0;
            map[nf] = c; is_remote[nf] = 0;
            nf++;
            short rev = 0;
            if (!c->remote_eof && c->pend_off >= c->pend_len) rev |= POLLIN;
            if (c->prebuf_len > 0) rev |= POLLOUT;
            pfd[nf].fd = c->remote_fd;
            pfd[nf].events = rev;
            pfd[nf].revents = 0;
            map[nf] = c; is_remote[nf] = 1;
            nf++;
            continue;
        }

        if (c->opening) {
        /* wake the loop after cancellation */
            if (c->local_fd < 0) continue;
            /* a full prebuf would only spin the loop until the worker is done */
            short lev = c->prebuf_len < sizeof c->prebuf ? POLLIN : 0;
            if (c->pend_off < c->pend_len) lev |= POLLOUT;
            pfd[nf].fd = c->local_fd;
            pfd[nf].events = lev;
            pfd[nf].revents = 0;
            map[nf] = c; is_remote[nf] = 0;
            nf++;
            continue;
        }

        if (c->sess.state == SESS_VISION_FIRST)
            session_pump_remote(&c->sess);

/* poll the local socket and pending output; a session with no room for
   another read, or a backlog of refused bytes, waits for its remote */
        short lev = 0;
        if (c->prebuf_len == 0 && session_client_room(&c->sess) > 0) lev |= POLLIN;
        if (c->pend_off < c->pend_len) lev |= POLLOUT;
        pfd[nf].fd = c->local_fd;
        pfd[nf].events = lev;
        pfd[nf].revents = 0;
        map[nf] = c; is_remote[nf] = 0;
        nf++;

        /* poll remote writes only when needed, and reads only while the
           client queue has room: a full one would spin the loop */
        short ev = session_remote_room(&c->sess) > 0 ? POLLIN : 0;
        if (session_remote_pending(&c->sess) > 0 && !session_remote_blocked(&c->sess))
            ev |= POLLOUT;
        else if (c->sess.vt && c->sess.vt->want_write && c->sess.th &&
                 c->sess.vt->want_write(c->sess.th))
            ev |= POLLOUT;
        pfd[nf].fd = c->remote_fd;
        pfd[nf].events = ev;
        pfd[nf].revents = 0;
        map[nf] = c; is_remote[nf] = 1;
        nf++;
    }
    return nf;
}

void loop_dispatch(loop_t *lp, const struct pollfd *pfd, size_t nf) {
    if (!lp || !pfd || nf < 1 || nf <= lp->poll_wake_idx) return;
    loop_conn_t **map = lp->poll_map;
    const uint8_t *is_remote = lp->poll_remote;

    int any = 0;
    for (size_t i = 0; i < nf; ++i)
        if (pfd[i].revents) { any = 1; break; }
    if (!any) return; /* a timeout: prepare already pumped what was due */

    if (pfd[0].revents & POLLIN) accept_one(lp);
    if (lp->poll_tproxy_idx >= 0 && (pfd[lp->poll_tproxy_idx].revents & POLLIN))
        accept_tproxy_one(lp);
    if (pfd[lp->poll_wake_idx].revents & POLLIN) {
        drain_wake(lp);
        reap_opening_conns(lp);
    }

    /* process connections after accepting new clients */
    size_t conn_base = lp->poll_conn_base;
    for (size_t i = conn_base; i < nf; ++i) {
        loop_conn_t *c = map[i];
        if (!c || !c->used) continue;

        if (c->opening) {
            service_opening_local(lp, c, pfd[i].revents);
            continue;
        }
        if (c->sniffing) {
            service_sniffing(lp, c, pfd[i].revents);
            map[i] = NULL;
            continue;
        }

        short local_re = 0, remote_re = 0;
        if (is_remote[i]) remote_re = pfd[i].revents;
        else              local_re  = pfd[i].revents;
        for (size_t j = conn_base; j < nf; ++j) {
            if (j == i || map[j] != c) continue;
            if (is_remote[j]) remote_re |= pfd[j].revents;
            else              local_re  |= pfd[j].revents;
        }

        service_conn(lp, c, local_re, remote_re);

        for (size_t j = conn_base; j < nf; ++j) {
            if (map[j] == c) map[j] = NULL;
        }
    }
    reap_opening_conns(lp);
}

int loop_timeout_ms(const loop_t *lp) {
    if (!lp) return -1;
    long best = -1, now = 0;
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        const loop_conn_t *c = lp->conns[i];
        if (!c || !c->used || c->opening) continue;
        long deadline;
        if (c->sniffing) deadline = c->sniff_deadline_ms;
        else if (!c->direct && c->sess.state == SESS_VISION_FIRST)
            deadline = c->sess.vision_first_deadline_ms;
        else if (!c->sniffing)
            deadline = c->last_io_ms + LOOP_IDLE_MS;
        else continue;
        if (!now) now = loop_now_ms();
        long left = deadline - now;
        if (left < 0) left = 0;
        if (best < 0 || left < best) best = left;
    }
    return best < 0 ? -1 : (int)(best + 1);
}

loop_status_t loop_step(loop_t *lp, int timeout_ms) {
    if (!lp) return LOOP_ERR_ARG;
    struct pollfd pfd[LOOP_POLLFD_MAX];
    size_t nf = loop_prepare(lp, pfd, LOOP_POLLFD_MAX);
    int due = loop_timeout_ms(lp);
    if (due >= 0 && (timeout_ms < 0 || due < timeout_ms)) timeout_ms = due;

    int r = poll(pfd, (nfds_t)nf, timeout_ms);
    if (r < 0) {
        if (errno == EINTR) return LOOP_OK;
        return LOOP_ERR;
    }
    if (r == 0) return LOOP_OK; /* timeout, nothing to do */
    loop_dispatch(lp, pfd, nf);
    return LOOP_OK;
}

size_t loop_conn_count(const loop_t *lp) {
    return lp ? lp->nconns : 0;
}

uint64_t loop_tproxy_generation(const loop_t *lp) {
    return lp ? lp->tproxy_accept_generation : 0;
}

int loop_tproxy_seen(const loop_t *lp, uint64_t after_generation,
                     const char *host, uint16_t port) {
    if (!lp || !host || lp->tproxy_accept_generation == after_generation)
        return 0;
    return lp->tproxy_last_port == port &&
           strcmp(lp->tproxy_last_host, host) == 0;
}

void loop_close(loop_t *lp) {
    if (!lp) return;
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        if (lp->conns[i] && lp->conns[i]->used) drop_conn(lp, lp->conns[i]);
    }
    for (size_t i = 0; i < LOOP_MAX_CONNS; ++i) {
        loop_conn_t *c = lp->conns[i];
        if (!c || !c->used || !c->opening) continue;
        pthread_join(c->open_thread, NULL);
        if (c->open_th && c->open_vt && !c->direct) c->open_vt->close(c->open_th);
        if (c->remote_fd >= 0) close(c->remote_fd);
        if (c->local_fd >= 0) close(c->local_fd);
        if (lp->nopening > 0) lp->nopening--;
        clear_conn_slot(c);
    }
    free_unused_slots(lp);
    loop_disable_tproxy(lp);
    if (lp->listen_fd >= 0) close(lp->listen_fd);
    if (lp->wake_rd >= 0) close(lp->wake_rd);
    if (lp->wake_wr >= 0) close(lp->wake_wr);
    if (lp->open_lock_ready) pthread_mutex_destroy(&lp->open_lock);
    lp->listen_fd = -1;
    lp->wake_rd = lp->wake_wr = -1;
    lp->open_lock_ready = 0;
}
