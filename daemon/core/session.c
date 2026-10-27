#include "session.h"
#include "senko_trace.h"
#include "senko_replay.h"
#include "senko_upload.h"
#include "socks5.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define VISION_FIRST_WAIT_MS 500

static size_t q_append(uint8_t *q, size_t *qlen, size_t cap,
                       const uint8_t *src, size_t len) {
    size_t room = cap - *qlen;
    size_t take = len < room ? len : room;
    memcpy(q + *qlen, src, take);
    *qlen += take;
    return take;
}

/* stage new remote bytes behind queued data so transport order stays intact */
static int transport_write_mode(session_t *s, const uint8_t *buf, size_t len, int raw) {
    int w;
    if (!raw)
        w = s->vt->write(s->th, buf, len);
    else if (!s->vt->raw_write)
        w = TRANSPORT_ERR;
    else
        w = s->vt->raw_write(s->th, buf, len);
    if (w > 0)
        senko_upload_wire_feed(s, buf, (size_t)w);
    return w;
}

static void activate_pending_direct_if_drained(session_t *s) {
    if (s->vision_upstream_direct_pending && s->to_remote_len == 0) {
        s->vision_upstream_direct_pending = 0;
        if (s->vision_upstream_direct_mark_transport && s->vt->raw_write) {
            (void)s->vt->raw_write(s->th, NULL, 0);
            s->vision_upstream_direct_mark_transport = 0;
        }
        s->vision_upstream_direct = 1;
        fprintf(stderr, "legacyrayd: vision upstream direct active\n");
        senko_trace_sess(s, "upstream_direct_active", "pending drained");
    }
}

static void request_upstream_direct(session_t *s, const char *why, int mark_transport) {
    if (s->vision_upstream_direct) return;
    if (s->to_remote_len == 0) {
        if (mark_transport && s->vt->raw_write)
            (void)s->vt->raw_write(s->th, NULL, 0);
        s->vision_upstream_direct = 1;
        fprintf(stderr, "legacyrayd: vision upstream direct active: %s\n",
                why ? why : "direct");
        senko_trace_sess(s, "upstream_direct_active", why);
    } else {
        if (mark_transport)
            s->vision_upstream_direct_mark_transport = 1;
        s->vision_upstream_direct_pending = 1;
        fprintf(stderr, "legacyrayd: vision upstream direct pending: %s\n",
                why ? why : "direct");
        senko_trace_sess(s, "upstream_direct_pending", why);
    }
}

static void flush_remote(session_t *s);

/* a socks5 or http upstream is still answering its handshake */
static int upstream_handshake_pending(const session_t *s) {
    return s->state == SESS_VLESS_RESP &&
           (s->proto == VL_PROTO_SOCKS5 || s->proto == VL_PROTO_HTTP ||
            s->proto == VL_PROTO_HTTPS);
}

/* handshake bytes go ahead of the held client bytes, whole or not at all */
static size_t push_before_hold(session_t *s, const uint8_t *buf, size_t len) {
    size_t at = s->to_remote_len - s->to_remote_hold;
    if (len > sizeof s->to_remote - s->to_remote_len) {
        s->state = SESS_ERROR;
        return 0;
    }
    memmove(s->to_remote + at + len, s->to_remote + at, s->to_remote_hold);
    memcpy(s->to_remote + at, buf, len);
    s->to_remote_len += len;
    flush_remote(s);
    return len;
}

static size_t push_remote_mode(session_t *s, const uint8_t *buf, size_t len, int raw) {
    if (s->to_remote_hold > 0 && !raw) return push_before_hold(s, buf, len);
    if (s->to_remote_len > 0) {
        if (s->to_remote_raw != raw) return 0;
        return q_append(s->to_remote, &s->to_remote_len, sizeof s->to_remote, buf, len);
    }

    size_t off = 0;
    while (off < len) {
        int w = transport_write_mode(s, buf + off, len - off, raw);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w == TRANSPORT_WANT_WRITE || w == TRANSPORT_WANT_READ) {
            s->to_remote_raw = raw;
            off += q_append(s->to_remote, &s->to_remote_len, sizeof s->to_remote,
                            buf + off, len - off);
            break;
        }
        senko_trace_sess(s, "SESS_ERROR", raw ? "push_remote_raw" : "push_remote");
        fprintf(stderr, "legacyrayd: session remote write failed (%s)\n",
                raw ? "raw" : "framed");
        s->state = SESS_ERROR;
        break;
    }
    s->trace_wire_tx += (uint64_t)off;
    return off;
}

static size_t push_remote(session_t *s, const uint8_t *buf, size_t len) {
    return push_remote_mode(s, buf, len, 0);
}

static size_t push_remote_raw(session_t *s, const uint8_t *buf, size_t len) {
    return push_remote_mode(s, buf, len, 1);
}

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + (long)(tv.tv_usec / 1000);
}

static void flush_remote(session_t *s) {
    size_t off = 0;
    size_t ready = s->to_remote_len - s->to_remote_hold;
    while (off < ready) {
        int w = transport_write_mode(s, s->to_remote + off,
                                     ready - off,
                                     s->to_remote_raw);
        if (w > 0) { off += (size_t)w; continue; }
        if (w == TRANSPORT_WANT_WRITE || w == TRANSPORT_WANT_READ) break;
        senko_trace_sess(s, "SESS_ERROR", "flush_remote");
        fprintf(stderr, "legacyrayd: session remote write failed (queued, %s)\n",
                w == TRANSPORT_EOF ? "peer closed" : "error");
        s->state = SESS_ERROR;
        return;
    }
    if (off > 0) {
        memmove(s->to_remote, s->to_remote + off, s->to_remote_len - off);
        s->to_remote_len -= off;
    }
    if (s->to_remote_len == 0) s->to_remote_raw = 0;
    activate_pending_direct_if_drained(s);
}

#define VISION_MAX_OVERHEAD (16 + 5 + 1400)

static sess_status_t send_vision_first(session_t *s,
                                       const uint8_t *payload, size_t payload_len,
                                       size_t *taken) {
    uint8_t req[VLESS_UUID_LEN + 512];
    size_t reqlen = 0;
    size_t content = payload_len;
    if (content > 8192) content = 8192;
    if (content > 0xffff) content = 0xffff;

    uint8_t blk[8192 + VISION_MAX_OVERHEAD];
    size_t blk_len = 0;
    int sent_direct = 0;
    if (content > 0) {
        senko_upload_in_feed(s, payload, content);
        int was_direct = s->vwrap.direct_sent;
        if (vision_wrap(&s->vwrap, payload, content,
                        blk, sizeof blk, &blk_len) != 0) {
            s->state = SESS_ERROR;
            return SESS_ERR;
        }
        sent_direct = !was_direct && s->vwrap.direct_sent;
    } else {
        if (vision_wrap_bootstrap(&s->vwrap, blk, sizeof blk, &blk_len) != 0) {
            s->state = SESS_ERROR;
            return SESS_ERR;
        }
    }

    vc_status_t vs = vless_conn_make_request(&s->u.vc, NULL, 0,
                                             req, sizeof req, &reqlen);
    if (vs != VC_OK) {
        s->state = SESS_ERROR;
        return SESS_ERR;
    }

    uint8_t first[VLESS_UUID_LEN + 512 + 8192 + VISION_MAX_OVERHEAD];
    if (reqlen + blk_len > sizeof first) {
        s->state = SESS_ERROR;
        return SESS_ERR;
    }
    memcpy(first, req, reqlen);
    memcpy(first + reqlen, blk, blk_len);
    push_remote(s, first, reqlen + blk_len);
    if (s->state == SESS_ERROR) return SESS_ERR;
    s->trace_app_tx += (uint64_t)content;

    s->state = SESS_VLESS_RESP;
/* only DIRECT (inner tls 1.3) leaves the outer tls. END (tls 1.2, plain
   http) just drops the framing: xray keeps reading those bytes through the
   outer tls, and bare ones make it answer with a protocol_version alert */
    if (sent_direct)
        request_upstream_direct(s, "vision first DIRECT", 1);
    if (taken) *taken = content;
    senko_trace_sess(s, content ? "vision_first_payload" : "vision_first_bootstrap",
                     content ? "header+payload" : "header+bootstrap");
    return SESS_OK;
}

/* wrap client bytes atomically so backpressure cannot split a vision block */
static size_t push_app(session_t *s, const uint8_t *buf, size_t len) {
    if (upstream_handshake_pending(s)) {
        size_t took = q_append(s->to_remote, &s->to_remote_len, sizeof s->to_remote,
                               buf, len);
        s->to_remote_hold += took;
        return took;
    }
    if (s->proto == VL_PROTO_VMESS) {
        enum { overhead = 2 + 16 + 63 };
        if (len == 0) return 0;
        size_t free_rm = sizeof s->to_remote - s->to_remote_len;
        if (free_rm <= overhead) return 0;
        size_t content = free_rm - overhead;
        if (content > VMESS_CHUNK_PAYLOAD_MAX) content = VMESS_CHUNK_PAYLOAD_MAX;
        if (content > len) content = len;
        uint8_t enc[VMESS_CHUNK_PAYLOAD_MAX + overhead];
        size_t enc_len = 0;
        if (vmess_client_encrypt_chunk(&s->u.mc, buf, content, enc, sizeof enc,
                                       &enc_len) != VMESS_OK) {
            s->state = SESS_ERROR;
            return 0;
        }
        if (push_remote(s, enc, enc_len) == 0) return 0;
        s->trace_app_tx += (uint64_t)content;
        return content;
    }
    if (s->proto == VL_PROTO_SHADOWSOCKS) {
        if (len == 0) return 0;
        size_t free_rm = sizeof s->to_remote - s->to_remote_len;
        if (free_rm <= 34) return 0;
        size_t maxc = free_rm - 34;
        if (maxc > 8192) maxc = 8192;
        size_t content = len < maxc ? len : maxc;
        uint8_t enc[8192 + 34];
        size_t enc_len = 0;
        if (ss_client_encrypt_chunk(&s->u.sc, buf, content, enc, sizeof enc, &enc_len) != SS_OK)
            return 0;
        size_t p = push_remote(s, enc, enc_len);
        if (p == 0) return 0;
        s->trace_app_tx += (uint64_t)content;
        return content;
    }

    if (!s->vision_on) {
        size_t n = push_remote(s, buf, len);
        s->trace_app_tx += (uint64_t)n;
        return n;
    }
    if (len == 0) return 0;

    activate_pending_direct_if_drained(s);
    if (s->vision_upstream_direct) return push_remote_raw(s, buf, len);
    if (s->vision_upstream_direct_pending) return 0;

    size_t free_rm = sizeof s->to_remote - s->to_remote_len;
    if (free_rm <= VISION_MAX_OVERHEAD) return 0;

    size_t maxc = free_rm - VISION_MAX_OVERHEAD;
    if (maxc > 8192)  maxc = 8192; /* keep the temp block small */
    if (maxc > 0xffff) maxc = 0xffff;
    size_t content = len < maxc ? len : maxc;

    senko_upload_in_feed(s, buf, content);

    uint8_t blk[8192 + VISION_MAX_OVERHEAD];
    size_t bn = 0;
    int was_direct = s->vwrap.direct_sent;
    if (vision_wrap(&s->vwrap, buf, content, blk, sizeof blk, &bn) != 0) return 0;
    int sent_direct = !was_direct && s->vwrap.direct_sent;

    push_remote(s, blk, bn);
    if (s->state == SESS_ERROR) return 0;
    if (sent_direct)
        request_upstream_direct(s, "local DIRECT", 1);
    s->trace_app_tx += (uint64_t)content;
    return content;
}

static void deliver_client(session_t *s, const uint8_t *buf, size_t len) {
/* reject overflow so package downloads cannot become partial archives */
    if (!s->vision_on || s->vision_downstream_direct ||
        s->vision_downstream_framing_done) {
        if (s->vision_on) vision_filter_tls(&s->vision_traffic, buf, len);
        size_t took = q_append(s->to_client, &s->to_client_len,
                               sizeof s->to_client, buf, len);
        if (took < len) {
            fprintf(stderr, "legacyrayd: to_client overflow, dropped %zu bytes "
                    "(would corrupt downloads)\n", len - took);
            s->state = SESS_ERROR;
            return;
        }
        s->trace_app_rx += (uint64_t)len;
        return;
    }
    senko_replay_feed(s, buf, len);
    uint8_t app[SESS_BUF]; size_t an = 0; int dir = 0;
    if (vision_unpad(&s->vunpad, buf, len, app, sizeof app, &an, &dir) != 0) {
        char detail[128];
        snprintf(detail, sizeof detail,
                 "in=%zu stash=%zu rem_cmd=%d rem_cnt=%d rem_pad=%d direct=%d",
                 len, s->vunpad.stash_len, s->vunpad.remaining_command,
                 (int)s->vunpad.remaining_content, (int)s->vunpad.remaining_padding,
                 s->vunpad.direct);
        senko_trace_sess(s, "vision_unpad_err", detail);
        senko_trace_sess(s, "SESS_ERROR", "vision_unpad");
        s->state = SESS_ERROR;
        return;
    }
    if (s->vunpad.framing_done)
        s->vision_downstream_framing_done = 1;
    if (an > 0) vision_filter_tls(&s->vision_traffic, app, an);
    if (dir) {
        s->vision_downstream_direct = 1;
        fprintf(stderr, "legacyrayd: vision downstream direct\n");
        senko_trace_sess(s, "downstream_direct", "vision CMD_DIRECT");
    }
    size_t took = q_append(s->to_client, &s->to_client_len,
                           sizeof s->to_client, app, an);
    if (took < an) {
        fprintf(stderr, "legacyrayd: to_client overflow after vision, dropped %zu\n",
                an - took);
        s->state = SESS_ERROR;
        return;
    }
    s->trace_app_rx += (uint64_t)an;
}

static void push_staged_client(session_t *s) {
    if ((s->state != SESS_VLESS_RESP && s->state != SESS_RELAY) ||
        s->client_stage_len == 0)
        return;

    size_t pushed = push_app(s, s->client_stage, s->client_stage_len);
    memmove(s->client_stage, s->client_stage + pushed,
            s->client_stage_len - pushed);
    s->client_stage_len -= pushed;
}

sess_status_t session_init(session_t *s,
                           const transport_vt_t *vt, void *th,
                           vl_proto_t proto,
                           const uint8_t uuid[VLESS_UUID_LEN],
                           const char *flow,
                           const char *user,
                           const char *pass) {
    if (!s || !vt) return SESS_ERR_ARG;
    memset(s, 0, sizeof *s);
    s->vt = vt;
    s->th = th;
    s->proto = proto;
    s->state = SESS_GREETING;

    if (proto == VL_PROTO_VLESS) {
        if (uuid) memcpy(s->u.vc.uuid, uuid, VLESS_UUID_LEN);
        s->u.vc.flow = (flow && flow[0]) ? flow : NULL;
/* enable vision only for its explicit flow so both directions agree */
        if (flow && strcmp(flow, "xtls-rprx-vision") == 0 && uuid) {
            s->vision_on = 1;
            vision_traffic_init(&s->vision_traffic);
            vision_wrap_init(&s->vwrap, uuid);
            vision_unpad_init(&s->vunpad, uuid);
            vision_wrap_bind_traffic(&s->vwrap, &s->vision_traffic);
            vision_unpad_bind_traffic(&s->vunpad, &s->vision_traffic);
            senko_trace_sess(s, "sess_init", "vision");
        }
    } else if (proto == VL_PROTO_SOCKS5) {
        s5c_init(&s->u.s5c, user, pass, &(vless_dest_t){0});
    } else if (proto == VL_PROTO_HTTP || proto == VL_PROTO_HTTPS) {
        hc_init(&s->u.hc, user, pass, &(vless_dest_t){0});
    } else if (proto == VL_PROTO_TROJAN) {
        trojan_client_init(&s->u.tc, pass, &(vless_dest_t){0});
    } else if (proto == VL_PROTO_SHADOWSOCKS) {
        ss_client_init(&s->u.sc, user, pass, &(vless_dest_t){0});
    } else if (proto == VL_PROTO_VMESS) {
/* user carries the body cipher, as it carries the shadowsocks method */
        if (!uuid || vmess_client_init(&s->u.mc, uuid, user, &(vless_dest_t){0},
                                       NULL) != VMESS_OK)
            return SESS_ERR_ARG;
    }
    return SESS_OK;
}

sess_status_t session_init_after_greet(session_t *s,
                                       const transport_vt_t *vt, void *th,
                                       vl_proto_t proto,
                                       const uint8_t uuid[VLESS_UUID_LEN],
                                       const char *flow,
                                       const char *user,
                                       const char *pass) {
    sess_status_t r = session_init(s, vt, th, proto, uuid, flow, user, pass);
    if (r != SESS_OK) return r;
    s->state = SESS_REQUEST;
    return SESS_OK;
}

static void queue_socks_reply(session_t *s, uint8_t code) {
    if (s->no_socks_reply) return;
    uint8_t rep[10];
    size_t rn = 0;
    socks5_build_reply(code, rep, sizeof rep, &rn);
    q_append(s->to_client, &s->to_client_len, sizeof s->to_client, rep, rn);
}

static void flush_pending_socks_ok(session_t *s) {
    if (!s->pending_socks_ok) return;
    s->pending_socks_ok = 0;
    queue_socks_reply(s, SOCKS5_REP_OK);
}

static void fail_pending_socks(session_t *s) {
    if (!s->pending_socks_ok) return;
    s->pending_socks_ok = 0;
    queue_socks_reply(s, SOCKS5_REP_GENERAL_FAIL);
}

static sess_status_t begin_vless_dest(session_t *s, const vless_dest_t *dest,
                                     const uint8_t *payload, size_t payload_len,
                                     size_t *payload_used_out, int send_socks_ok) {
    session_set_trace_host(s, dest);
    s->u.vc.dest = *dest;
    s->u.vc.state = VC_ST_INIT;

/* acknowledge socks early because vision peers may reset an empty bootstrap */
    if (send_socks_ok)
        queue_socks_reply(s, SOCKS5_REP_OK);
    s->pending_socks_ok = 0;

    size_t payload_used = 0;
    if (s->vision_on) {
        if (payload_len) {
            size_t took = 0;
            if (send_vision_first(s, payload, payload_len, &took) != SESS_OK)
                return SESS_ERR;
            payload_used = took;
        } else {
/* wait for client bytes before sending an empty vision bootstrap */
            s->state = SESS_VISION_FIRST;
            s->vision_first_deadline_ms = now_ms() + VISION_FIRST_WAIT_MS;
            senko_trace_sess(s, "vision_first_wait",
                             send_socks_ok ? "await client after socks ok"
                                           : "empty tproxy payload");
        }
    } else {
        uint8_t req[VLESS_UUID_LEN + 512];
        size_t cap = sizeof req;
        size_t first = payload_len;
        size_t header_budget = 64;
        if (first + header_budget > cap) first = cap - header_budget;

        size_t reqlen = 0;
        vc_status_t vs = vless_conn_make_request(&s->u.vc, payload, first,
                                                 req, cap, &reqlen);
        if (vs != VC_OK) { s->state = SESS_ERROR; return SESS_ERR; }
        push_remote(s, req, reqlen);
        if (s->state == SESS_ERROR) return SESS_ERR;
        payload_used = first;
        s->trace_app_tx += (uint64_t)first;
    }

    if (payload_used_out) *payload_used_out = payload_used;
    if (s->state != SESS_VISION_FIRST)
        s->state = SESS_VLESS_RESP;
    return SESS_OK;
}

/* the start for the upstreams that are not vless. socks5 and http send their
   handshake and leave the payload to the caller, which feeds it once they
   answer; trojan and shadowsocks carry the first payload bytes in their
   request and the session relays at once */
static sess_status_t begin_upstream_dest(session_t *s, const vless_dest_t *dest,
                                         const uint8_t *payload, size_t payload_len,
                                         size_t *payload_used_out) {
    size_t payload_used = 0;
    if (payload_len > sizeof s->client_stage) payload_len = sizeof s->client_stage;
    if (s->proto == VL_PROTO_SOCKS5) {
        session_set_trace_host(s, dest);
        s->u.s5c.dest = *dest;
        s->u.s5c.state = S5C_ST_INIT;

        uint8_t req[512];
        size_t reqlen = 0;
        int rs = s5c_make_request(&s->u.s5c, req, sizeof req, &reqlen);
        if (rs != S5C_OK) { s->state = SESS_ERROR; return SESS_ERR; }

        push_remote(s, req, reqlen);
        if (s->state == SESS_ERROR) return SESS_ERR;
        s->state = SESS_VLESS_RESP;
    } else if (s->proto == VL_PROTO_HTTP || s->proto == VL_PROTO_HTTPS) {
        s->u.hc.dest = *dest;
        s->u.hc.state = HC_ST_INIT;

        uint8_t req[1024];
        size_t reqlen = 0;
        int rs = hc_make_request(&s->u.hc, req, sizeof req, &reqlen);
        if (rs != HC_OK) { s->state = SESS_ERROR; return SESS_ERR; }

        push_remote(s, req, reqlen);
        if (s->state == SESS_ERROR) return SESS_ERR;
        s->state = SESS_VLESS_RESP;
    } else if (s->proto == VL_PROTO_TROJAN) {
        session_set_trace_host(s, dest);
        s->u.tc.dest = *dest;

        uint8_t req[1024];
        size_t reqlen = 0;
        int rs = trojan_client_build_request(&s->u.tc, payload, payload_len, req, sizeof req, &reqlen);
        if (rs != TR_OK) { s->state = SESS_ERROR; return SESS_ERR; }

        push_remote(s, req, reqlen);
        if (s->state == SESS_ERROR) return SESS_ERR;
        payload_used = payload_len;
        s->state = SESS_RELAY;
/* trojan has no distinct response header, so ack the local socks client now */
        queue_socks_reply(s, SOCKS5_REP_OK);
    } else if (s->proto == VL_PROTO_SHADOWSOCKS) {
        session_set_trace_host(s, dest);
        s->u.sc.dest = *dest;

        uint8_t req[16384];
        size_t reqlen = 0;
        int rs = ss_client_build_request(&s->u.sc, payload, payload_len, req, sizeof req, &reqlen);
        if (rs != SS_OK) { s->state = SESS_ERROR; return SESS_ERR; }

        push_remote(s, req, reqlen);
        if (s->state == SESS_ERROR) return SESS_ERR;
        payload_used = payload_len;
        s->state = SESS_RELAY;
/* shadowsocks has no distinct response header, so ack the local socks client now */
        queue_socks_reply(s, SOCKS5_REP_OK);
    } else if (s->proto == VL_PROTO_VMESS) {
        session_set_trace_host(s, dest);
        s->u.mc.dest = *dest;

        uint8_t req[VMESS_REQUEST_MAX + sizeof s->client_stage + 2 + 16 + 63];
        size_t reqlen = 0;
        if (vmess_client_build_request(&s->u.mc, payload, payload_len, req, sizeof req,
                                       &reqlen) != VMESS_OK) {
            s->state = SESS_ERROR;
            return SESS_ERR;
        }

        push_remote(s, req, reqlen);
        if (s->state == SESS_ERROR) return SESS_ERR;
        payload_used = payload_len;
        s->state = SESS_RELAY;
/* the vmess response header rides with the first reply bytes, which never come
   for a client that waits to be spoken to, so ack the local socks client now */
        queue_socks_reply(s, SOCKS5_REP_OK);
    } else {
        s->state = SESS_ERROR;
        return SESS_ERR;
    }
    s->trace_app_tx += (uint64_t)payload_used;
    if (payload_used_out) *payload_used_out = payload_used;
    return SESS_OK;
}

sess_status_t session_start_from_socks_dest(session_t *s,
                                            const vless_dest_t *dest,
                                            const uint8_t *payload,
                                            size_t payload_len) {
    if (!s || !dest) return SESS_ERR_ARG;
    if (s->proto != VL_PROTO_VLESS) return SESS_ERR_ARG;
    return begin_vless_dest(s, dest, payload, payload_len, NULL, 1);
}

sess_status_t session_start_from_transparent_dest(session_t *s,
                                                  const vless_dest_t *dest,
                                                  const uint8_t *payload,
                                                  size_t payload_len,
                                                  size_t *payload_used_out) {
    if (!s || !dest) return SESS_ERR_ARG;
    s->no_socks_reply = 1;
    if (s->proto == VL_PROTO_VLESS)
        return begin_vless_dest(s, dest, payload, payload_len, payload_used_out, 0);
    return begin_upstream_dest(s, dest, payload, payload_len, payload_used_out);
}

static sess_status_t do_greeting(session_t *s, size_t *consumed) {
    size_t used = 0;
    s5_status_t r = socks5_parse_greeting(s->client_stage, s->client_stage_len, &used);
    if (r == S5_NEED_MORE) { *consumed = 0; return SESS_OK; }
    if (r != S5_OK) { s->state = SESS_ERROR; return SESS_ERR; }

    uint8_t reply[2]; size_t rn = 0;
    socks5_build_method_reply(reply, sizeof reply, &rn);
    q_append(s->to_client, &s->to_client_len, sizeof s->to_client, reply, rn);

    memmove(s->client_stage, s->client_stage + used, s->client_stage_len - used);
    s->client_stage_len -= used;
    s->state = SESS_REQUEST;
    *consumed = 0; /* staged greeting bytes were already consumed */
    return SESS_OK;
}

static sess_status_t do_request(session_t *s) {
    vless_dest_t dest;
    size_t used = 0;
    s5_status_t r = socks5_parse_request(s->client_stage, s->client_stage_len,
                                         &dest, &used);
    if (r == S5_NEED_MORE) return SESS_OK;
    if (r != S5_OK) {
        uint8_t rep[10]; size_t rn = 0;
        uint8_t code = (r == S5_ERR_CMD) ? SOCKS5_REP_CMD_NOT_SUP
                                         : SOCKS5_REP_GENERAL_FAIL;
        socks5_build_reply(code, rep, sizeof rep, &rn);
        q_append(s->to_client, &s->to_client_len, sizeof s->to_client, rep, rn);
        s->state = SESS_ERROR;
        return SESS_ERR;
    }

    const uint8_t *payload = s->client_stage + used;
    size_t payload_len = s->client_stage_len - used;
    size_t payload_used = 0;
    sess_status_t br = s->proto == VL_PROTO_VLESS
        ? begin_vless_dest(s, &dest, payload, payload_len, &payload_used, 1)
        : begin_upstream_dest(s, &dest, payload, payload_len, &payload_used);
    if (br != SESS_OK) return SESS_ERR;
    size_t eaten = used + payload_used;
    memmove(s->client_stage, s->client_stage + eaten, s->client_stage_len - eaten);
    s->client_stage_len -= eaten;
    return SESS_OK;
}

sess_status_t session_feed_client(session_t *s,
                                  const uint8_t *in, size_t len,
                                  size_t *consumed) {
    if (!s || (!in && len) || !consumed) return SESS_ERR_ARG;
    *consumed = 0;
    if (s->state == SESS_ERROR || s->state == SESS_CLOSED) return SESS_ERR;

    if (s->state == SESS_GREETING || s->state == SESS_REQUEST) {
        size_t took = q_append(s->client_stage, &s->client_stage_len,
                               sizeof s->client_stage, in, len);
        *consumed = took;

        for (;;) {
            sess_state_t before = s->state;
            if (s->state == SESS_GREETING) {
                size_t c;
                if (do_greeting(s, &c) != SESS_OK) return SESS_ERR;
            } else if (s->state == SESS_REQUEST) {
                if (do_request(s) != SESS_OK) return SESS_ERR;
            } else {
                break;
            }
            if (s->state == before) break; /* wait when this pass made no progress */
        }

/* flush staged bytes after the request so early client data is not stranded */
        if ((s->state == SESS_VLESS_RESP || s->state == SESS_RELAY) &&
            s->client_stage_len > 0) {
            push_staged_client(s);
            if (s->state == SESS_ERROR) return SESS_ERR;
        }
        return SESS_OK;
    }

    if (s->state == SESS_VISION_FIRST) {
        size_t took = 0;
        if (send_vision_first(s, in, len, &took) != SESS_OK) return SESS_ERR;
        *consumed = took;
        return SESS_OK;
    }

/* relay client data while the remote side parses its response header */
    *consumed = push_app(s, in, len);
    if (s->state == SESS_ERROR) return SESS_ERR;
    return SESS_OK;
}

sess_status_t session_pump_remote(session_t *s) {
    if (!s) return SESS_ERR_ARG;
    if (s->state == SESS_ERROR) return SESS_ERR;

    if (s->state == SESS_VISION_FIRST) {
        if (now_ms() < s->vision_first_deadline_ms) return SESS_OK;
        fprintf(stderr, "legacyrayd: vision first bootstrap timeout fired\n");
        if (send_vision_first(s, NULL, 0, NULL) != SESS_OK) return SESS_ERR;
    }

    flush_remote(s);
    if (s->state == SESS_ERROR) return SESS_ERR;
/* nudge reality so accepted plaintext can flush pending ciphertext */
    if (s->to_remote_len == 0 && s->vt && s->vt->write && s->th &&
        (s->state == SESS_RELAY || s->state == SESS_VLESS_RESP)) {
        int nw = s->vt->write(s->th, (const uint8_t *)"", 0);
        (void)nw; /* empty writes only trigger the internal flush */
    }
    push_staged_client(s);
    if (s->state == SESS_ERROR) return SESS_ERR;

/* drain all readable records in one pump (avoid empty/truncated body) */
    for (;;) {
        size_t room = session_remote_room(s);
        if (room == 0) return SESS_OK;

        uint8_t tmp[SESS_BUF];
        size_t want = room < sizeof tmp ? room : sizeof tmp;
        int n = s->vt->read(s->th, tmp, want);

        if (n == TRANSPORT_WANT_READ || n == TRANSPORT_WANT_WRITE) return SESS_OK;
        if (n == TRANSPORT_EOF) {
            fprintf(stderr, "legacyrayd: transport eof in session state=%d queued=%zu\n",
                    (int)s->state, s->to_client_len);
            if (upstream_handshake_pending(s)) s->upstream_refused = 1;
            fail_pending_socks(s);
            s->state = SESS_CLOSED;
            return SESS_OK;
        }
        if (n < 0) {
            fprintf(stderr, "legacyrayd: transport read error in session state=%d rc=%d\n",
                    (int)s->state, n);
            if (upstream_handshake_pending(s)) s->upstream_refused = 1;
            fail_pending_socks(s);
            s->state = SESS_ERROR;
            return SESS_ERR;
        }
        if (n == 0) return SESS_OK;

        s->trace_wire_rx += (uint64_t)n;

        if (s->state == SESS_VLESS_RESP) {
            if (s->proto == VL_PROTO_VLESS) {
                size_t app_off = 0;
                vc_status_t vs = vless_conn_feed_response(&s->u.vc, tmp, (size_t)n, &app_off);
                if (vs == VC_NEED_MORE) return SESS_OK; /* retain a partial header */
                if (vs != VC_OK) {
                    s->fail = n >= 5 && memcmp(tmp, "HTTP/", 5) == 0
                        ? SESS_FAIL_WEBSITE : SESS_FAIL_PROTOCOL;
                    fprintf(stderr, "legacyrayd: vless response parse failed rc=%d bytes=%d\n",
                            (int)vs, n);
                    fail_pending_socks(s);
                    s->state = SESS_ERROR;
                    return SESS_ERR;
                }
/* deliver the response tail as application data after the header */
                s->state = SESS_RELAY;
                flush_pending_socks_ok(s);
                fprintf(stderr, "legacyrayd: vless response ok app_tail=%zu\n",
                        (size_t)n - app_off);
                senko_trace_sess(s, "relay_established", "vless");
                deliver_client(s, tmp + app_off, (size_t)n - app_off);
                if (s->state == SESS_ERROR) return SESS_ERR;
            } else if (s->proto == VL_PROTO_SOCKS5) {
/* gather the proxy's replies until a whole one is in: a reply cut across
   reads used to be dropped, which stalled or failed the connection */
                size_t take = (size_t)n;
                if (take > sizeof s->up_stage - s->up_stage_len)
                    take = sizeof s->up_stage - s->up_stage_len;
                memcpy(s->up_stage + s->up_stage_len, tmp, take);
                s->up_stage_len += take;
                while (s->u.s5c.state != S5C_ST_OPEN) {
                    size_t consumed = 0;
                    uint8_t out[1024];
                    size_t out_len = 0;
                    int rs = s5c_feed(&s->u.s5c, s->up_stage, s->up_stage_len, &consumed,
                                      out, sizeof out, &out_len);
                    if (rs == S5C_NEED_MORE) {
                        if (s->up_stage_len == sizeof s->up_stage) rs = S5C_ERR_PROTO;
                        else break;
                    }
                    if (rs != S5C_OK) {
                        if (rs == S5C_ERR_AUTH) s->fail = SESS_FAIL_LOGIN;
                        queue_socks_reply(s, SOCKS5_REP_GENERAL_FAIL);
                        s->state = SESS_ERROR;
                        return SESS_ERR;
                    }
                    memmove(s->up_stage, s->up_stage + consumed, s->up_stage_len - consumed);
                    s->up_stage_len -= consumed;
                    if (out_len > 0) {
                        push_remote(s, out, out_len);
                        if (s->state == SESS_ERROR) return SESS_ERR;
                    }
                }

                if (s->u.s5c.state == S5C_ST_OPEN) {
                    queue_socks_reply(s, SOCKS5_REP_OK);
                    s->state = SESS_RELAY;
/* whatever followed the reply is the destination talking already */
                    if (s->up_stage_len > 0)
                        q_append(s->to_client, &s->to_client_len, sizeof s->to_client,
                                 s->up_stage, s->up_stage_len);
                    if (take < (size_t)n)
                        q_append(s->to_client, &s->to_client_len, sizeof s->to_client,
                                 tmp + take, (size_t)n - take);
                    s->up_stage_len = 0;
                }
            } else if (s->proto == VL_PROTO_HTTP || s->proto == VL_PROTO_HTTPS) {
                size_t consumed = 0;
                int rs = hc_feed(&s->u.hc, tmp, (size_t)n, &consumed);
                if (rs == HC_NEED_MORE) return SESS_OK;
                if (rs != HC_OK) {
                    if (rs == HC_ERR_AUTH) s->fail = SESS_FAIL_LOGIN;
                    queue_socks_reply(s, SOCKS5_REP_GENERAL_FAIL);
                    s->state = SESS_ERROR;
                    return SESS_ERR;
                }

                if (s->u.hc.state == HC_ST_OPEN) {
                    queue_socks_reply(s, SOCKS5_REP_OK);
                    s->state = SESS_RELAY;

                    if (consumed < (size_t)n) {
                        q_append(s->to_client, &s->to_client_len, sizeof s->to_client,
                                 tmp + consumed, (size_t)n - consumed);
                    }
                }
            }

/* the upstream took the connection: what the client sent meanwhile goes out */
            if (s->state == SESS_RELAY && s->to_remote_hold > 0) {
                s->to_remote_hold = 0;
                flush_remote(s);
                if (s->state == SESS_ERROR) return SESS_ERR;
            }
/* flush bytes parked during response parsing when relay mode starts */
            if (s->state == SESS_RELAY && s->client_stage_len > 0) {
                push_staged_client(s);
                if (s->state == SESS_ERROR) return SESS_ERR;
            }
            continue;
        }

        if (s->proto == VL_PROTO_SHADOWSOCKS) {
            const uint8_t *feed = tmp;
            size_t feed_len = (size_t)n;
/* one wire read can hold more full chunks than the plain buffer takes at
   once, so keep draining the staged ciphertext until nothing more is ready */
            for (;;) {
                uint8_t plain[16384];
                size_t plain_len = 0;
                int fr = ss_client_feed_downstream(&s->u.sc, feed, feed_len, plain, sizeof plain, &plain_len);
                feed = NULL;
                feed_len = 0;
                if (fr == SS_ERR_BAD_TAG || fr == SS_ERR_CRYPTO) {
                    s->fail = SESS_FAIL_DECRYPT;
                    fprintf(stderr, "legacyrayd: shadowsocks decrypt failed rc=%d\n", fr);
                    fail_pending_socks(s);
                    s->state = SESS_ERROR;
                    return SESS_ERR;
                }
                if (plain_len > 0) {
                    deliver_client(s, plain, plain_len);
                    if (s->state == SESS_ERROR) return SESS_ERR;
                }
                if (plain_len == 0) break;
            }
            continue;
        }

        if (s->proto == VL_PROTO_VMESS) {
            const uint8_t *feed = tmp;
            size_t feed_len = (size_t)n;
/* session_remote_room keeps every whole chunk staged here openable into the
   client queue, as for shadowsocks */
            for (;;) {
                uint8_t plain[16384];
                size_t room_c = sizeof s->to_client - s->to_client_len;
                size_t plain_len = 0;
                int fr = vmess_client_feed_downstream(&s->u.mc, feed, feed_len, plain,
                                                      room_c < sizeof plain ? room_c : sizeof plain,
                                                      &plain_len);
                feed = NULL;
                feed_len = 0;
                if (plain_len > 0) {
                    deliver_client(s, plain, plain_len);
                    if (s->state == SESS_ERROR) return SESS_ERR;
                }
/* the server's end chunk is its eof */
                if (fr == VMESS_EOF) {
                    s->state = SESS_CLOSED;
                    return SESS_OK;
                }
                if (fr != VMESS_OK && fr != VMESS_NEED_MORE) {
                    s->fail = fr == VMESS_ERR_BAD_TAG ? SESS_FAIL_DECRYPT : SESS_FAIL_PROTOCOL;
                    fprintf(stderr, "legacyrayd: vmess response failed rc=%d\n", fr);
                    fail_pending_socks(s);
                    s->state = SESS_ERROR;
                    return SESS_ERR;
                }
                if (plain_len == 0) break;
            }
            continue;
        }

        deliver_client(s, tmp, (size_t)n);
        if (s->state == SESS_ERROR) return SESS_ERR;
    }
}

size_t session_take_client(session_t *s, uint8_t *out, size_t cap) {
    if (!s || !out) return 0;
    size_t take = s->to_client_len < cap ? s->to_client_len : cap;
    memcpy(out, s->to_client, take);
    if (take < s->to_client_len) {
        memmove(s->to_client, s->to_client + take, s->to_client_len - take);
    }
    s->to_client_len -= take;
    return take;
}

size_t session_remote_room(const session_t *s) {
    size_t room;
    if (!s) return 0;
    room = sizeof s->to_client - s->to_client_len;
/* shadowsocks decrypts every whole chunk it holds at once, and plaintext is
   never longer than its ciphertext: what is staged plus the next read must
   fit the client queue, or the tail of a download is dropped */
    if (s->proto == VL_PROTO_SHADOWSOCKS)
        room = s->u.sc.dec_stage_len < room ? room - s->u.sc.dec_stage_len : 0;
/* the same for vmess, whose stage also must take the whole read */
    if (s->proto == VL_PROTO_VMESS) {
        size_t staged = s->u.mc.dec_stage_len;
        size_t stage_room = sizeof s->u.mc.dec_stage - staged;
        room = staged < room ? room - staged : 0;
        if (room > stage_room) room = stage_room;
    }
    return room;
}

size_t session_remote_pending(const session_t *s) {
    return s ? s->to_remote_len - s->to_remote_hold : 0;
}

int session_remote_blocked(const session_t *s) {
    return s && s->vt && s->vt->blocked && s->th && s->vt->blocked(s->th);
}

/* one read of up to 8 kb, plus the most framing a block of it can gain
   (vision padding is the largest) */
size_t session_client_room(const session_t *s) {
    size_t free_rm;
    if (!s) return 0;
    free_rm = sizeof s->to_remote - s->to_remote_len;
    return free_rm >= 8192 + VISION_MAX_OVERHEAD + 64 ? 8192 : 0;
}

int session_is_done(const session_t *s) {
    if (!s) return 1;
    if (s->state == SESS_ERROR) return 1;
    if (s->state == SESS_CLOSED && s->to_client_len == 0) return 1;
    return 0;
}

int session_upstream_refused(const session_t *s) {
    return s && s->upstream_refused;
}

sess_status_t session_restart_upstream(session_t *s, void *th) {
    if (!s || !th || !s->upstream_refused) return SESS_ERR_ARG;
/* the handshake bytes still queued were meant for the connection that is
   gone; only the held client bytes carry over */
    size_t hold = s->to_remote_hold;
    memmove(s->to_remote, s->to_remote + s->to_remote_len - hold, hold);
    s->to_remote_len = hold;
    s->up_stage_len = 0;
    s->upstream_refused = 0;
    s->th = th;
    s->state = SESS_VLESS_RESP;

    uint8_t req[1024];
    size_t reqlen = 0;
    int made;
    if (s->proto == VL_PROTO_SOCKS5) {
        s->u.s5c.state = S5C_ST_INIT;
        made = s5c_make_request(&s->u.s5c, req, sizeof req, &reqlen) == S5C_OK;
    } else if (s->proto == VL_PROTO_HTTP || s->proto == VL_PROTO_HTTPS) {
        s->u.hc.state = HC_ST_INIT;
        s->u.hc.rbuf_len = 0;
        made = hc_make_request(&s->u.hc, req, sizeof req, &reqlen) == HC_OK;
    } else {
        made = 0;
    }
    if (!made) { s->state = SESS_ERROR; return SESS_ERR; }
    push_remote(s, req, reqlen);
    return s->state == SESS_ERROR ? SESS_ERR : SESS_OK;
}
