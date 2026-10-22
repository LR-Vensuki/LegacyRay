#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TRANSPORT_WANT_READ   (-1) /* wait for socket input before retrying */
#define TRANSPORT_WANT_WRITE  (-2) /* wait for socket output before retrying */
#define TRANSPORT_EOF         (-3) /* close after the peer ends the stream */
#define TRANSPORT_ERR         (-4) /* close after an unrecoverable failure */

/* the xhttp knobs a server may set (xray's xhttpSettings / "extra"); zero
   keeps xray's defaults */
typedef struct {
    uint32_t pad_min, pad_max; /* x_padding length range, default 100-1000 */
    uint32_t post_max;         /* largest packet-up body the server takes */
    int      no_grpc;          /* no grpc content type on streamed requests */
} transport_xhttp_opts_t;

/* borrow config strings so transport opens can outlive the caller stack */
typedef struct {
    const char *sni; /* preserve the tls server name */
    const char *fingerprint;/* preserve the browser fingerprint choice */
    const char *reality_pbk;/* enable reality only when a key is present */
    const char *reality_sid;/* preserve the optional reality short id */
    const char *path; /* preserve the transport request path */
    const char *ws_host; /* preserve the websocket host header */
    const char *xhttp_mode; /* preserve the xhttp stream mode */
    const char *peer_host; /* dial target host, last authority fallback */
    int insecure; /* skip certificate and hostname verification (allowInsecure) */
/* when positive, open finishes the transport's own handshake within this many
   ms before it returns, so a server that refuses it fails the open and the
   caller can dial again. zero leaves the handshake to the first read/write.
   only the websocket transports use it */
    int handshake_ms;
/* the carrier speaks http/2 over this tls (xhttp, grpc): offer only h2, as
   xray and grpc do. a server that picked http/1.1 would read the h2 preface
   as a broken request, and grpc servers refuse a handshake without h2 */
    int alpn_h2;
    transport_xhttp_opts_t xh;
} transport_tls_cfg_t;

typedef struct transport_vt {
/* open from a connected fd without blocking the shared loop */
    void *(*open)(int fd, const transport_tls_cfg_t *cfg);

/* move application bytes and expose backpressure through the result */
    int (*read)(void *h, uint8_t *buf, size_t len);
    int (*write)(void *h, const uint8_t *buf, size_t len);

/* splice plaintext only after the transport has entered direct mode */
    int (*raw_write)(void *h, const uint8_t *buf, size_t len);

/* release transport state while the daemon retains fd ownership */
    void (*close)(void *h);

/* report pending ciphertext so the loop continues polling for output */
    int (*want_write)(void *h);

/* half close after the relay drained cleanly; optional (http/2 end stream) */
    void (*shutdown)(void *h);

/* 1 while the transport takes no bytes until the peer sends something (an
   http/2 window or stream slot), so the loop waits for input instead of
   spinning on a writable socket; optional */
    int (*blocked)(void *h);
} transport_vt_t;

extern const transport_vt_t transport_tcp; /* plain tcp transport */
extern const transport_vt_t transport_tls; /* tls and reality transport */
extern const transport_vt_t transport_ws_tcp;/* websocket over plain tcp */
extern const transport_vt_t transport_ws_tls;/* websocket over tls */
extern const transport_vt_t transport_ws_reality; /* websocket over reality */
extern const transport_vt_t transport_xhttp_tcp;
extern const transport_vt_t transport_xhttp_tls;
extern const transport_vt_t transport_xhttp_reality;

#ifdef __cplusplus
}
#endif

#endif /* transport_h */
