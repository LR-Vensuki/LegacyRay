#ifndef SESSION_H
#define SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "transport.h"
#include "config.h"
#include "vless.h"
#include "vless_conn.h"
#include "vision.h"
#include "socks5_client.h"
#include "http_client.h"
#include "trojan_client.h"
#include "shadowsocks_client.h"
#include "vmess_client.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SESS_GREETING = 0, /* wait for socks greeting before opening remote work */
    SESS_REQUEST, /* need destination before sending vless */
    SESS_VISION_FIRST, /* delay the first write for vision bootstrap safety */
    SESS_VLESS_RESP, /* wait for the remote response header */
    SESS_RELAY, /* relay application bytes in both directions */
    SESS_CLOSED, /* drain client output after remote eof */
    SESS_ERROR /* close both sides after a protocol failure */
} sess_state_t;

typedef enum {
    SESS_OK      =  0,
    SESS_ERR_ARG = -1,
    SESS_ERR     = -2 /* move the session to the terminal error state */
} sess_status_t;

/* keep enough client output queued to avoid truncating package downloads */
#define SESS_BUF  (64 * 1024)

typedef struct {
    sess_state_t state;

    const transport_vt_t *vt; /* borrow transport operations from the loop */
    void                 *th; /* borrow the loop-owned transport handle */

    vl_proto_t            proto;
    union {
        vless_conn_t         vc;
        socks5_client_t      s5c;
        http_client_t        hc;
        trojan_client_t      tc;
        shadowsocks_client_t sc;
        vmess_client_t       mc;
    } u;

    uint8_t client_stage[512];
    size_t  client_stage_len;

/* queue local output because socket writes can apply backpressure */
    uint8_t to_client[SESS_BUF];
    size_t  to_client_len;

/* queue remote output when transport_write reports backpressure */
    uint8_t to_remote[SESS_BUF];
    size_t  to_remote_len;
    int     to_remote_raw;
/* the tail of to_remote that waits until a socks5 or http upstream accepted
   the connection: client bytes sent before its reply would be read as the
   next handshake message */
    size_t  to_remote_hold;

/* track vision framing so direct mode can splice raw bytes safely */
    int            vision_on;
    int            vision_upstream_direct;
    int            vision_upstream_direct_pending;
    int            vision_upstream_direct_mark_transport;
    int            vision_downstream_direct;
    int            vision_downstream_framing_done;
    long           vision_first_deadline_ms;
    vision_traffic_t vision_traffic;
    vision_wrap_t  vwrap;
    vision_unpad_t vunpad;

/* delay socks success until the remote response proves the tunnel exists */
    int            pending_socks_ok;
/* a redirected connection never spoke socks, so it gets no socks replies */
    int            no_socks_reply;
/* a socks5 upstream's reply can arrive in pieces; the start waits here */
    uint8_t        up_stage[300];
    size_t         up_stage_len;
/* the socks5 or http upstream hung up before it answered */
    int            upstream_refused;

/* the destination label, the close latch and the byte counts exist in every
   build: an event line with no destination in it names nothing, and a close
   that does not say whether the request ever left or an answer ever came back
   cannot tell a dead server from a stuck session. everything below is what a
   release build cuts, because the replay and upload buffers are 64 kb each */
    char     trace_host[280];
    int      trace_closed;
    uint64_t trace_app_tx;
    uint64_t trace_app_rx;
    uint64_t trace_wire_tx;
    uint64_t trace_wire_rx;

#ifndef SENKO_RELEASE
    uint8_t  replay_buf[64 * 1024];
    size_t   replay_len;
    uint16_t replay_chunks;
    uint8_t  replay_uuid[16];
    int      replay_uuid_set;

    uint8_t  upload_in_buf[64 * 1024];
    size_t   upload_in_len;
    uint32_t upload_in_chunks;
    uint8_t  upload_wire_buf[64 * 1024];
    size_t   upload_wire_len;
    uint32_t upload_wire_chunks;
    uint8_t  upload_uuid[16];
    int      upload_uuid_set;
    int      upload_started;
#endif
} session_t;

/* initialize a session over an already-open transport handle */
sess_status_t session_init(session_t *s,
                           const transport_vt_t *vt, void *th,
                           vl_proto_t proto,
                           const uint8_t uuid[VLESS_UUID_LEN],
                           const char *flow,
                           const char *user,
                           const char *pass);

/* greeting reply already went out while the transport was still opening */
sess_status_t session_init_after_greet(session_t *s,
                                       const transport_vt_t *vt, void *th,
                                       vl_proto_t proto,
                                       const uint8_t uuid[VLESS_UUID_LEN],
                                       const char *flow,
                                       const char *user,
                                       const char *pass);

/* attach destination after transport open so early payload stays ordered */
sess_status_t session_start_from_socks_dest(session_t *s,
                                            const vless_dest_t *dest,
                                            const uint8_t *payload,
                                            size_t payload_len);

/* pf-transparent clients: no socks5 reply on the local socket */
sess_status_t session_start_from_transparent_dest(session_t *s,
                                                  const vless_dest_t *dest,
                                                  const uint8_t *payload,
                                                  size_t payload_len,
                                                  size_t *payload_used_out);

/* feed local bytes and report consumed input under backpressure */
sess_status_t session_feed_client(session_t *s,
                                  const uint8_t *in, size_t len,
                                  size_t *consumed);

/* pump remote bytes and queue client output without blocking */
sess_status_t session_pump_remote(session_t *s);

/* drain queued client output without exposing the internal buffer */
size_t session_take_client(session_t *s, uint8_t *out, size_t cap);

/* how many bytes may be read from the remote now without the client queue
   overflowing; 0 while the client has not taken what is already queued */
size_t session_remote_room(const session_t *s);

/* bytes queued for the remote that can be written now */
size_t session_remote_pending(const session_t *s);

/* 1 while the transport takes nothing until the remote sends something */
int session_remote_blocked(const session_t *s);

/* how many client bytes the session can take in one feed without refusing
   any: none while its remote queue is too full for one more read */
size_t session_client_room(const session_t *s);

/* close only after errors or a drained remote eof */
int session_is_done(const session_t *s);

/* 1 when a socks5 or http upstream hung up before it answered. nothing has
   gone to the destination then, so the request may be sent again */
int session_upstream_refused(const session_t *s);

/* send the request again over a new transport handle; the client bytes that
   wait for the upstream's answer are kept */
sess_status_t session_restart_upstream(session_t *s, void *th);

#ifdef __cplusplus
}
#endif

#endif /* session_h */
