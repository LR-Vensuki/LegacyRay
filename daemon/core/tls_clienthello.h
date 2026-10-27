#ifndef TLS_CLIENTHELLO_H
#define TLS_CLIENTHELLO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_CH_RANDOM_LEN     32
#define TLS_CH_SESSIONID_LEN  32
#define TLS_CH_X25519_PUB_LEN 32
#define TLS_CH_MLKEM768_PUB_LEN 1184 /* draft-kwiatkowski-tls-ecdhe-mlkem-03 client share */
#define TLS_CH_SESSIONID_OFF  39 /* keep reality aad offsets deterministic */

typedef enum {
    TLS_CH_OK        =  0,
    TLS_CH_ERR_ARG   = -1,
    TLS_CH_ERR_SPACE = -2, /* reject output beyond fixed storage */
    TLS_CH_ERR_SNI   = -3 /* reject an sni beyond fixed storage */
} tls_ch_status_t;

/* model browser fingerprints while keeping the supported tls suites narrow */
typedef enum {
    TLS_FP_CHROME = 0, /* use chrome when no profile is configured */
    TLS_FP_EDGE,
    TLS_FP_FIREFOX,
    TLS_FP_QQ,
    TLS_FP_RANDOMIZED
} tls_fp_t;

/* carry caller-owned random, session, key-share, sni, and fingerprint inputs */
typedef struct {
    uint8_t     random[TLS_CH_RANDOM_LEN];
    uint8_t     session_id[TLS_CH_SESSIONID_LEN];
    uint8_t     x25519_pub[TLS_CH_X25519_PUB_LEN];
    const char *sni; /* present the configured fronting name */
    tls_fp_t    fp; /* select the browser-shaped hello */
    const uint8_t *p256_pub; /* add the firefox decoy share when available */
    /* real firefox offers this hybrid group first; a fingerprint missing it
       reads as an outdated browser to any server that checks for it, which
       reality servers use as anti-probing signal ahead of the token check */
    const uint8_t *mlkem768_pub; /* TLS_CH_MLKEM768_PUB_LEN bytes, or NULL to omit */
} tls_ch_params_t;

/* legacyray: chrome and edge built on hardware without aes instructions list
   chacha20-poly1305 ahead of aes-gcm (boringssl orders by EVP_has_aes_hardware),
   and a go server, xray and reality included, then answers in chacha20. every
   armv7 iphone is that hardware, where chacha20 costs a fraction of the cycles
   aes-gcm does. off by default here; the daemon turns it on from settings */
void tls_ch_set_prefer_chacha(int on);
int  tls_ch_prefer_chacha(void);

/* serialize the exact hello bytes used by reality aad and tls transcript */
tls_ch_status_t tls_build_clienthello(const tls_ch_params_t *p,
                                      uint8_t *buf, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* tls_clienthello_h */
