#include "transport.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include "tls_clienthello.h"
#include "frag.h"
#include <openssl/err.h>
#include "../../common/senko_paths.h"

#if defined(LR_MACOS)
#include <limits.h>
#include <mach-o/dyld.h>
#endif

#if defined(LR_MACOS)
/* the installed roots, else the copy beside the running binary (the app's
   Helpers folder while the daemon runs from the bundle) */
static void load_ca_bundle(SSL_CTX *ctx) {
    if (access(SENKO_CA_BUNDLE, R_OK) == 0) {
        SSL_CTX_load_verify_locations(ctx, SENKO_CA_BUNDLE, NULL);
        return;
    }
    char self[PATH_MAX], real[PATH_MAX], path[PATH_MAX];
    uint32_t n = sizeof self;
    if (_NSGetExecutablePath(self, &n) != 0 || !realpath(self, real)) return;
    char *slash = strrchr(real, '/');
    if (!slash) return;
    *slash = '\0';
    if (snprintf(path, sizeof path, "%s/cacert.pem", real) >= (int)sizeof path) return;
    if (access(path, R_OK) == 0) SSL_CTX_load_verify_locations(ctx, path, NULL);
}
#else
static void load_ca_bundle(SSL_CTX *ctx) {
    if (access(SENKO_CA_BUNDLE, R_OK) == 0)
        SSL_CTX_load_verify_locations(ctx, SENKO_CA_BUNDLE, NULL);
}
#endif

typedef struct {
    SSL_CTX *ctx;
    SSL     *ssl;
    int      fd;
    int      raw_rx;
    int      raw_tx;
} tls_handle_t;

/* a filter in front of the socket bio that sends the first write, the
   client hello, through frag_write_all; everything after passes straight on */
static int frag_bio_write(BIO *b, const char *data, int len) {
    BIO *next = BIO_next(b);
    if (!next || len < 0) return -1;
    BIO_clear_retry_flags(b);
    if (!BIO_get_data(b) || len == 0) {
        int r = BIO_write(next, data, len);
        BIO_copy_next_retry(b);
        return r;
    }
    BIO_set_data(b, NULL);
    int fd = -1;
    if (BIO_get_fd(next, &fd) <= 0 || fd < 0) return -1;
    return frag_write_all(fd, (const uint8_t *)data, (size_t)len, 5000) == 0 ? len : -1;
}

static int frag_bio_read(BIO *b, char *out, int len) {
    BIO *next = BIO_next(b);
    if (!next) return -1;
    BIO_clear_retry_flags(b);
    int r = BIO_read(next, out, len);
    BIO_copy_next_retry(b);
    return r;
}

static long frag_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    BIO *next = BIO_next(b);
    return next ? BIO_ctrl(next, cmd, num, ptr) : 0;
}

static int frag_bio_create(BIO *b) {
    BIO_set_data(b, (void *)1); /* the hello is still to come */
    BIO_set_init(b, 1);
    return 1;
}

static BIO_METHOD *g_frag_method;

static void frag_bio_method_init(void) {
    BIO_METHOD *m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER, "legacyray frag");
    if (!m) return;
    BIO_meth_set_write(m, frag_bio_write);
    BIO_meth_set_read(m, frag_bio_read);
    BIO_meth_set_ctrl(m, frag_bio_ctrl);
    BIO_meth_set_create(m, frag_bio_create);
    g_frag_method = m;
}

/* opens run on worker threads, so the method is built exactly once */
static BIO_METHOD *frag_bio_method(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, frag_bio_method_init);
    return g_frag_method;
}

/* keep ctx per conn so lifetime stays simple while the stack settles */
static void *tls_open(int fd, const transport_tls_cfg_t *cfg) {
    if (fd < 0) return NULL;

    tls_handle_t *h = (tls_handle_t *)OPENSSL_zalloc(sizeof *h);
    if (!h) return NULL;

    h->ctx = SSL_CTX_new(TLS_client_method());
    if (!h->ctx) { OPENSSL_free(h); return NULL; }

/* pin the tls range so old devices stay inside support */
    SSL_CTX_set_min_proto_version(h->ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(h->ctx, TLS1_3_VERSION);

/* a bare ClientHello with no alpn and openssl's own suite/group order is a
   free dpi fingerprint for "not a browser". offering h2 here is not safe:
   this transport only ever speaks http/1.x (tls_read/tls_write pass bytes
   straight through to subfetch's http.c and to the vless byte stream), so a
   server that honors h2 over an alpn offer leaves both trying to parse a
   binary h2 frame as a plaintext response */
    static const unsigned char alpn[] = "\x08http/1.1";
    static const unsigned char alpn_h2[] = "\x02h2";
    if (cfg && cfg->alpn_h2)
        SSL_CTX_set_alpn_protos(h->ctx, alpn_h2, sizeof alpn_h2 - 1);
    else
        SSL_CTX_set_alpn_protos(h->ctx, alpn, sizeof alpn - 1);
    SSL_CTX_set_ciphersuites(h->ctx, tls_ch_prefer_chacha()
        ? "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
        : "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    if (tls_ch_prefer_chacha())
        SSL_CTX_set_cipher_list(h->ctx,
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384");
    SSL_CTX_set1_groups_list(h->ctx, "X25519:P-256:P-384");

    int reality = (cfg && cfg->reality_pbk && cfg->reality_pbk[0]);
    if (reality || (cfg && cfg->insecure)) {
        SSL_CTX_set_verify(h->ctx, SSL_VERIFY_NONE, NULL);
    } else {
        SSL_CTX_set_verify(h->ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_default_verify_paths(h->ctx);
        load_ca_bundle(h->ctx);
    }

    h->ssl = SSL_new(h->ctx);
    if (!h->ssl) { SSL_CTX_free(h->ctx); OPENSSL_free(h); return NULL; }

    if (frag_enabled()) {
        BIO *sock = BIO_new_socket(fd, BIO_NOCLOSE);
        BIO *frag = BIO_new(frag_bio_method());
        if (!sock || !frag) {
            BIO_free(sock); BIO_free(frag);
            SSL_free(h->ssl); SSL_CTX_free(h->ctx); OPENSSL_free(h);
            return NULL;
        }
        BIO_push(frag, sock);
        SSL_set_bio(h->ssl, frag, frag);
    } else if (SSL_set_fd(h->ssl, fd) != 1) {
        SSL_free(h->ssl); SSL_CTX_free(h->ctx); OPENSSL_free(h);
        return NULL;
    }
    h->fd = fd;

/* use the configured server name so cert checks and fronting stay aligned */
    if (cfg && cfg->sni && cfg->sni[0]) {
        SSL_set_tlsext_host_name(h->ssl, cfg->sni);
        SSL_set1_host(h->ssl, cfg->sni);
    }

    SSL_set_connect_state(h->ssl); /* client mode */
    return h;
}

static int ssl_err_to_transport(SSL *ssl, int ret) {
    int e = SSL_get_error(ssl, ret);
    switch (e) {
        case SSL_ERROR_WANT_READ:  return TRANSPORT_WANT_READ;
        case SSL_ERROR_WANT_WRITE: return TRANSPORT_WANT_WRITE;
        case SSL_ERROR_ZERO_RETURN: return TRANSPORT_EOF; /* peer closed cleanly */
        case SSL_ERROR_SYSCALL:
/* peer reset without close notify, treat it as eof and drain */
            return TRANSPORT_EOF;
        default:
            return TRANSPORT_ERR;
    }
}

static int tls_read(void *handle, uint8_t *buf, size_t len) {
    tls_handle_t *h = (tls_handle_t *)handle;
    if (h->raw_rx) {
        ssize_t n = read(h->fd, buf, len);
        if (n > 0) return (int)n;
        if (n == 0) return TRANSPORT_EOF;
        return TRANSPORT_WANT_READ;
    }
    int n = SSL_read(h->ssl, buf, (int)len);
    if (n > 0) return n;
    return ssl_err_to_transport(h->ssl, n);
}

static int tls_write(void *handle, const uint8_t *buf, size_t len) {
    tls_handle_t *h = (tls_handle_t *)handle;
    if (h->raw_tx) {
        ssize_t n = write(h->fd, buf, len);
        if (n > 0) return (int)n;
        if (n == 0) return TRANSPORT_WANT_WRITE;
        return TRANSPORT_WANT_WRITE;
    }
    int n = SSL_write(h->ssl, buf, (int)len);
    if (n > 0) return n;
    return ssl_err_to_transport(h->ssl, n);
}

static int tls_raw_write(void *handle, const uint8_t *buf, size_t len) {
    tls_handle_t *h = (tls_handle_t *)handle;
    if (len == 0) {
        h->raw_rx = 1;
        h->raw_tx = 1;
        return 0;
    }
    h->raw_tx = 1;
    return tls_write(handle, buf, len);
}

static void tls_close(void *handle) {
    tls_handle_t *h = (tls_handle_t *)handle;
    if (!h) return;
    if (h->ssl) {
        SSL_shutdown(h->ssl);
        SSL_free(h->ssl);
    }
    if (h->ctx) SSL_CTX_free(h->ctx);
    OPENSSL_free(h);
}

const transport_vt_t transport_tls = {
    tls_open, tls_read, tls_write, tls_raw_write, tls_close, NULL, NULL, NULL
};

/* reality uses its own handshake path, not ssl_connect */
