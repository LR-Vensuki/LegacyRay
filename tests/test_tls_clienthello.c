/* edge profiles need their own wire shape, not chrome with a different name */
#include "../daemon/core/tls_clienthello.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(const char *name, int pass) {
    if (pass) printf("  ok  %s\n", name);
    else { printf(" FAIL %s\n", name); failures++; }
}

static size_t read_u16(const uint8_t *p) {
    return ((size_t)p[0] << 8) | p[1];
}

static const uint8_t *find_extension(const uint8_t *hello, size_t hello_len,
                                     uint16_t want, size_t *data_len) {
    size_t pos = 4 + 2 + TLS_CH_RANDOM_LEN;
    if (hello_len < pos + 1) return NULL;
    size_t sid_len = hello[pos++];
    if (sid_len > hello_len - pos || hello_len - pos - sid_len < 2) return NULL;
    pos += sid_len;
    size_t cipher_len = read_u16(hello + pos); pos += 2;
    if (cipher_len > hello_len - pos || hello_len - pos - cipher_len < 1) return NULL;
    pos += cipher_len;
    size_t compression_len = hello[pos++];
    if (compression_len > hello_len - pos || hello_len - pos - compression_len < 2) return NULL;
    pos += compression_len;
    size_t exts_len = read_u16(hello + pos); pos += 2;
    if (exts_len > hello_len - pos) return NULL;
    size_t end = pos + exts_len;
    while (pos + 4 <= end) {
        uint16_t type = (uint16_t)read_u16(hello + pos);
        size_t len = read_u16(hello + pos + 2);
        pos += 4;
        if (len > end - pos) return NULL;
        if (type == want) {
            if (data_len) *data_len = len;
            return hello + pos;
        }
        pos += len;
    }
    return NULL;
}

int main(void) {
    tls_ch_params_t p;
    uint8_t hello[2048];
    size_t hello_len = 0, ext_len = 0;
    memset(&p, 0, sizeof p);
    memset(p.random, 0x41, sizeof p.random);
    memset(p.x25519_pub, 0x42, sizeof p.x25519_pub);
    p.sni = "front.example";
    p.fp = TLS_FP_EDGE;

    check("build edge", tls_build_clienthello(&p, hello, sizeof hello, &hello_len) == TLS_CH_OK);
    check("edge offers aes-256-gcm", hello_len > 78 && hello[77] == 0x13 && hello[78] == 0x02);
    const uint8_t *versions = find_extension(hello, hello_len, 0x002b, &ext_len);
    check("edge has supported versions", versions && ext_len == 11);
    check("edge offers tls 1.1 and 1.0", versions && ext_len == 11 &&
          versions[7] == 0x03 && versions[8] == 0x02 &&
          versions[9] == 0x03 && versions[10] == 0x01);
    check("edge omits chrome alps", !find_extension(hello, hello_len, 0x4469, NULL));
    const uint8_t *shares = find_extension(hello, hello_len, 0x0033, &ext_len);
    check("no hybrid share without an ml-kem key", shares && ext_len >= 2 + 4 + 32 &&
          read_u16(shares + 2 + 4 + 1) != 0x11ec);

/* the hybrid share comes first after grease and carries ml-kem key || x25519 */
    static uint8_t mlkem[TLS_CH_MLKEM768_PUB_LEN];
    static uint8_t big[4096];
    static const tls_fp_t hybrid[] = {TLS_FP_CHROME, TLS_FP_EDGE, TLS_FP_FIREFOX};
    memset(mlkem, 0x43, sizeof mlkem);
    p.mlkem768_pub = mlkem;
    for (size_t i = 0; i < sizeof hybrid / sizeof hybrid[0]; i++) {
        p.fp = hybrid[i];
        check("build with the hybrid share",
              tls_build_clienthello(&p, big, sizeof big, &hello_len) == TLS_CH_OK);
        shares = find_extension(big, hello_len, 0x0033, &ext_len);
        size_t at = 2;
        if (shares && p.fp != TLS_FP_FIREFOX) at += 4 + 1; /* grease share */
        check("hybrid share is listed", shares && ext_len >= at + 4 + 1216 &&
              read_u16(shares + at) == 0x11ec && read_u16(shares + at + 2) == 1216);
        check("hybrid share is ml-kem key then x25519", shares && ext_len >= at + 4 + 1216 &&
              memcmp(shares + at + 4, mlkem, sizeof mlkem) == 0 &&
              memcmp(shares + at + 4 + sizeof mlkem, p.x25519_pub, 32) == 0);
        const uint8_t *groups = find_extension(big, hello_len, 0x000a, &ext_len);
        size_t g = (p.fp == TLS_FP_FIREFOX) ? 2 : 4;
        check("hybrid group is offered first", groups && ext_len > g + 1 &&
              read_u16(groups + g) == 0x11ec);
    }
    p.fp = TLS_FP_EDGE;
    check("small buffer is refused, not overrun",
          tls_build_clienthello(&p, hello, 1024, &hello_len) != TLS_CH_OK);

    if (failures) {
        printf("%d tls_clienthello checks failed\n", failures);
        return 1;
    }
    printf("all tls_clienthello checks passed\n");
    return 0;
}
