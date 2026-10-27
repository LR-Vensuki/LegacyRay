#ifndef LOOP_H
#define LOOP_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#include "session.h"
#include "transport.h"
#include "vless.h"

#ifdef __cplusplus
extern "C" {
#endif

/* a slot is only allocated while its connection lives, so the cap costs
   nothing until a page actually opens that many */
#define LOOP_MAX_CONNS 192
/* allow safari bursts so connection drops do not force page reloads */
#define LOOP_MAX_OPENING 64
#define LOOP_PREBUF_CAP (16 * 1024)
/* listener, transparent listener, wake pipe, then two sockets per conn */
#define LOOP_POLLFD_MAX (3 + 2 * LOOP_MAX_CONNS)

typedef int (*loop_dialer_fn)(void *ctx);

/* where a connection goes. the router is asked first with no name: it answers
   from the address alone, or with LOOP_ROUTE_SNIFF when only the site name
   the client is about to send can decide. it is then asked again with the
   name ("" when none could be read) and must not answer SNIFF a second time */
typedef enum {
    LOOP_ROUTE_PROXY = 0,
    LOOP_ROUTE_DIRECT,
    LOOP_ROUTE_BLOCK,
    LOOP_ROUTE_SNIFF
} loop_route_t;

typedef loop_route_t (*loop_route_fn)(void *ctx, const vless_dest_t *dest,
                                      const char *host);
/* make a direct connection to this ipv4 address safe to dial, ie keep the
   firewall redirect from sending it straight back to the daemon. runs on a
   worker thread; 0 when the address may be dialled */
typedef int (*loop_bypass_fn)(void *ctx, const char *ipv4);

typedef struct {
    struct loop *owner;
    int        local_fd; /* preserve the client socket */
    int        remote_fd; /* preserve the remote socket */
    session_t  sess;
    void      *th; /* retain transport state for remote_fd */
    int        used;
    int        opening; /* prevent loop work during worker open */
    int        open_done;
    int        open_cancelled;
    pthread_t  open_thread;

/* snapshot configuration so server switches cannot race a handshake */
    const transport_vt_t *open_vt;
    vl_proto_t open_proto;
    uint8_t    open_uuid[VLESS_UUID_LEN];
    char       open_flow[32];
    char       open_user[64];
    char       open_pass[64];
    char       open_sni[256];
    char       open_fingerprint[32];
    char       open_reality_pbk[128];
    char       open_reality_sid[32];
    char       open_path[256];
    char       open_ws_host[256];
    char       open_xhttp_mode[16];
    char       open_peer_host[256];
    int        open_insecure;
    transport_tls_cfg_t open_tls_cfg;
    net_fail_t open_fail; /* what the transport saw of the server */
    void      *open_th;

/* preserve the destination captured before the transparent handshake */
    int        transparent;
    vless_dest_t tproxy_dest;

/* the router wants the site name: wait for the client's first bytes */
    int        sniffing;
    long       sniff_deadline_ms;
/* relay raw bytes to the destination itself, around the tunnel */
    int        direct;
    int        local_eof;
    int        remote_eof;
    long       last_io_ms;

/* the socks request is answered as soon as it is read, so the hooked
   connect() in an app returns at once instead of after the whole tunnel
   handshake; the reply the session produces later is dropped */
    int        socks_req_done;
    size_t     socks_req_len;
    size_t     socks_reply_skip;

/* retain early client bytes until the remote transport is ready */
    int        socks_greet_done;
    uint8_t    prebuf[LOOP_PREBUF_CAP];
    size_t     prebuf_len;

/* the relay ended without error, so a transport may half close politely */
    int        relay_clean;

/* times the upstream hung up before it answered and the request went out
   again; redialing is set while a worker opens the new connection */
    int        redials;
    int        redialing;

/* retain local output so large package transfers survive backpressure */
    uint8_t    pend[64 * 1024];
    size_t     pend_len;
    size_t     pend_off;
} loop_conn_t;

typedef struct loop {
    int                   listen_fd; /* local socks listener */
    int                   tproxy_fd; /* transparent listener, -1 means off */
    uint16_t              tproxy_port; /* redirect port used by natlook */
    int                   tproxy_sockname; /* ipfw retains original destination */
    uint64_t              tproxy_accept_generation;
    char                  tproxy_last_host[64];
    uint16_t              tproxy_last_port;
    const transport_vt_t *vt; /* active remote transport */
    loop_dialer_fn        dial;
    void                 *dial_ctx;

    uint8_t  uuid[VLESS_UUID_LEN];
    char     flow[32]; /* own the active flow string */
    vl_proto_t proto;
    char     user[64];
    char     pass[64];

/* own tls strings so worker opens never observe dead pointers */
    char     sni[256];
    char     fingerprint[32];
    char     reality_pbk[128];
    char     reality_sid[32];
    char     path[256];
    char     ws_host[256];
    char     xhttp_mode[16];
    char     peer_host[256]; /* dial target, authority fallback for http/2 */
    int      insecure; /* skip tls certificate/hostname verification */
    transport_tls_cfg_t tls_cfg;

/* keep the listener bound while rejecting clients without a server */
    int      active;
    uint64_t bytes_up;
    uint64_t bytes_down;

    loop_conn_t *conns[LOOP_MAX_CONNS];

    loop_route_fn  route;
    loop_bypass_fn bypass;
    void          *route_ctx;
    size_t      nconns;
    size_t      nopening;

    int         wake_rd;
    int         wake_wr;
    pthread_mutex_t open_lock;
    int         open_lock_ready;

/* what loop_prepare put where, for loop_dispatch to read the answers back */
    loop_conn_t *poll_map[LOOP_POLLFD_MAX];
    uint8_t      poll_remote[LOOP_POLLFD_MAX];
    int          poll_tproxy_idx;
    size_t       poll_wake_idx;
    size_t       poll_conn_base;

/* the first failure any connection saw since loop_failure_reset, for a check
   to explain itself */
    net_fail_t   last_fail;
    sess_fail_t  last_answer;
} loop_t;

typedef enum {
    LOOP_OK       =  0,
    LOOP_ERR_ARG  = -1,
    LOOP_ERR_BIND = -2, /* reject a listener that cannot bind */
    LOOP_ERR      = -3
} loop_status_t;

loop_status_t loop_init(loop_t *lp, uint16_t listen_port, int bind_public,
                        const transport_vt_t *vt,
                        loop_dialer_fn dial, void *dial_ctx,
                        vl_proto_t proto,
                        const uint8_t uuid[VLESS_UUID_LEN], const char *flow,
                        const char *user, const char *pass);

uint16_t loop_listen_port(const loop_t *lp);

/* copy transport parameters so worker opens can use stable pointers */
void loop_set_tls(loop_t *lp, const char *sni, const char *fingerprint,
                  const char *reality_pbk, const char *reality_sid,
                  const char *path, const char *ws_host,
                  const char *xhttp_mode, const char *peer_host, int insecure);

/* the server's xhttp knobs; NULL restores xray's defaults. loop_set_server
   clears them, so set them after it */
void loop_set_xhttp(loop_t *lp, const transport_xhttp_opts_t *xh);

/* forget, and read back, why the connections since the reset failed: the
   transport's view of the server and the session's view of its answer */
void loop_failure_reset(loop_t *lp);
void loop_failure_get(const loop_t *lp, net_fail_t *transport, sess_fail_t *answer);

/* replace the active path and drop connections tied to the old server */
loop_status_t loop_set_server(loop_t *lp, const transport_vt_t *vt,
                              loop_dialer_fn dial, void *dial_ctx,
                              vl_proto_t proto,
                              const uint8_t uuid[VLESS_UUID_LEN], const char *flow,
                              const char *user, const char *pass,
                              const char *sni, const char *fingerprint,
                              const char *reality_pbk, const char *reality_sid,
                              const char *path, const char *ws_host,
                              const char *xhttp_mode, const char *peer_host,
                              int insecure);

/* split routing: NULL route sends everything through the tunnel */
void loop_set_router(loop_t *lp, loop_route_fn route, loop_bypass_fn bypass,
                     void *ctx);

/* stop traffic while keeping the listener ready for the next selection */
void loop_stop(loop_t *lp);

/* enable the listener used by full-device transparent routing. pf rewrites
   the destination, so that mode asks pf for it; every ipfw fwd mode keeps the
   destination on the accepted socket and reads it with getsockname */
loop_status_t loop_enable_tproxy(loop_t *lp, uint16_t port);
loop_status_t loop_enable_tproxy_sockname(loop_t *lp, uint16_t port);
void loop_disable_tproxy(loop_t *lp);

loop_status_t loop_step(loop_t *lp, int timeout_ms);

/* loop_step in two halves, so the daemon can sleep on the loop, the control
   socket and the network watch in one poll instead of taking turns with short
   timeouts. prepare fills at most cap entries and returns how many; dispatch
   takes the same entries back after poll has filled revents */
struct pollfd;
size_t loop_prepare(loop_t *lp, struct pollfd *pfd, size_t cap);
void loop_dispatch(loop_t *lp, const struct pollfd *pfd, size_t n);

/* milliseconds until a connection needs the loop without any socket event,
   -1 when nothing is waiting on the clock */
int loop_timeout_ms(const loop_t *lp);

size_t loop_conn_count(const loop_t *lp);

uint64_t loop_tproxy_generation(const loop_t *lp);
int loop_tproxy_seen(const loop_t *lp, uint64_t after_generation,
                     const char *host, uint16_t port);

void loop_close(loop_t *lp);

#ifdef __cplusplus
}
#endif

#endif /* loop_h */
