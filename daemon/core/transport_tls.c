#include "transport.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include "tls_clienthello.h"
#include "frag.h"
#include <openssl/err.h>
#include "../../common/senko_paths.h"

#define SENKO_CA_BUNDLE SENKO_USR_LIB "/legacyraytlsfix/cacert.pem"

static int ca_bundle_path(char *out, size_t cap) {
    if (access(SENKO_CA_BUNDLE, R_OK) != 0) return 0;
    return snprintf(out, cap, "%s", SENKO_CA_BUNDLE) < (int)cap;
}

/* the roots are parsed once and every connection's context shares them. each
   handshake used to read and parse the whole bundle again, and
   set_default_verify_paths sent openssl looking under the openssldir baked in
   at build time, a folder in the builder's home that no phone has, a dozen
   lookups per handshake. a bundle that is not there yet is looked for again
   on the next connection */
static pthread_mutex_t g_roots_lock = PTHREAD_MUTEX_INITIALIZER;
static X509_STORE *g_roots;

static X509_STORE *shared_roots(void) {
    pthread_mutex_lock(&g_roots_lock);
    if (!g_roots) {
        char path[1024];
        X509_STORE *st = ca_bundle_path(path, sizeof path) ? X509_STORE_new() : NULL;
        if (st && X509_STORE_load_file(st, path) == 1) g_roots = st;
        else X509_STORE_free(st);
    }
    X509_STORE *roots = g_roots;
    pthread_mutex_unlock(&g_roots_lock);
    return roots;
}

X509_STORE *transport_tls_roots(void) {
    return shared_roots();
}

typedef struct {
    SSL_CTX *ctx;
    SSL     *ssl;
    int      fd;
    int      raw_rx;
    int      raw_tx;
    net_fail_t *fail;
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
        X509_STORE *roots = shared_roots();
        if (roots) SSL_CTX_set1_cert_store(h->ctx, roots);
#if !defined(__APPLE__)
        else SSL_CTX_set_default_verify_paths(h->ctx); /* host builds: the system's roots */
#endif
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
    h->fail = cfg ? cfg->fail : NULL;

/* use the configured server name so cert checks and fronting stay aligned */
    if (cfg && cfg->sni && cfg->sni[0]) {
        SSL_set_tlsext_host_name(h->ssl, cfg->sni);
        SSL_set1_host(h->ssl, cfg->sni);
    }

    SSL_set_connect_state(h->ssl); /* client mode */
    return h;
}

/* what a failed handshake says about the server, for a check's diagnosis */
static void note_tls_failure(const tls_handle_t *h, int ssl_error, int saved_errno) {
    unsigned long code = ERR_peek_error();
    int reason = code && ERR_GET_LIB(code) == ERR_LIB_SSL ? ERR_GET_REASON(code) : 0;
    if (!h->fail || SSL_is_init_finished(h->ssl)) return;
    if (reason == SSL_R_CERTIFICATE_VERIFY_FAILED) {
        switch (SSL_get_verify_result(h->ssl)) {
        case X509_V_ERR_CERT_NOT_YET_VALID:
            net_fail_note(h->fail, NET_FAIL_CERT_NOT_YET_VALID, 0);
            return;
        case X509_V_ERR_CERT_HAS_EXPIRED:
            net_fail_note(h->fail, NET_FAIL_CERT_EXPIRED, 0);
            return;
        case X509_V_ERR_HOSTNAME_MISMATCH:
        case X509_V_ERR_IP_ADDRESS_MISMATCH:
            net_fail_note(h->fail, NET_FAIL_CERT_NAME, 0);
            return;
        default:
            net_fail_note(h->fail, NET_FAIL_CERT_UNTRUSTED, 0);
            return;
        }
    }
/* a plain http or proxy port answers the client hello with text */
    if (reason == SSL_R_WRONG_VERSION_NUMBER || reason == SSL_R_PACKET_LENGTH_TOO_LONG) {
        net_fail_note(h->fail, NET_FAIL_NOT_TLS, 0);
        return;
    }
    if (saved_errno == ECONNRESET) {
        net_fail_note(h->fail, NET_FAIL_RESET, 0);
        return;
    }
    if (saved_errno == ETIMEDOUT) {
        net_fail_note(h->fail, NET_FAIL_TIMEOUT, 0);
        return;
    }
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
    if (reason == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
        net_fail_note(h->fail, NET_FAIL_CLOSED, 0);
        return;
    }
#endif
    if (ssl_error == SSL_ERROR_ZERO_RETURN ||
        (ssl_error == SSL_ERROR_SYSCALL && saved_errno == 0)) {
        net_fail_note(h->fail, NET_FAIL_CLOSED, 0);
        return;
    }
    net_fail_note(h->fail, NET_FAIL_TLS, reason);
}

static int ssl_err_to_transport(const tls_handle_t *h, int ret) {
    int saved_errno = errno;
    int e = SSL_get_error(h->ssl, ret);
    switch (e) {
        case SSL_ERROR_WANT_READ:  return TRANSPORT_WANT_READ;
        case SSL_ERROR_WANT_WRITE: return TRANSPORT_WANT_WRITE;
        case SSL_ERROR_ZERO_RETURN:
            note_tls_failure(h, e, saved_errno);
            return TRANSPORT_EOF; /* peer closed cleanly */
        case SSL_ERROR_SYSCALL:
/* peer reset without close notify, treat it as eof and drain */
            note_tls_failure(h, e, saved_errno);
            return TRANSPORT_EOF;
        default:
            note_tls_failure(h, e, saved_errno);
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
    return ssl_err_to_transport(h, n);
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
    return ssl_err_to_transport(h, n);
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
