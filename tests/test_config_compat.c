#include "config.h"

#include <stdio.h>
#include <string.h>

static int g_fail = 0;
static void ok(const char *what, int cond) {
    if (cond) return;
    g_fail++;
    fprintf(stderr, "FAIL %s\n", what);
}

int main(void) {
    vl_server_t s;
    char reason[128];

/* '+' is only a space inside query values, never in the remark fragment */
    ok("parse plus remark",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443?security=tls&type=tcp#C+++Node",
                      &s) == CFG_OK);
    ok("remark keeps plus", strcmp(s.remark, "C+++Node") == 0);

    ok("parse plus path",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443?security=tls&type=ws&path=%2Fws%2Bv2&host=cdn.example#ws",
                      &s) == CFG_OK);
    ok("path keeps encoded plus", strcmp(s.path, "/ws+v2") == 0);

    ok("parse raw reality",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality&type=raw&flow=xtls-rprx-vision&pbk=abc&sid=00#raw",
                      &s) == CFG_OK);
    ok("raw is tcp", s.net == VL_NET_TCP);
    ok("default sni host", strcmp(s.sni, "example.com") == 0);

    ok("parse serverName",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443?security=tls&type=tcp&flow=xtls-rprx-vision&serverName=edge.example#tls",
                      &s) == CFG_OK);
    ok("serverName sni", strcmp(s.sni, "edge.example") == 0);

    ok("parse ws host separate from sni",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443?security=tls&type=ws&sni=tls.example&host=cdn.example&path=%2Fws#ws",
                      &s) == CFG_OK);
    ok("ws keeps tls sni", strcmp(s.sni, "tls.example") == 0);
    ok("ws keeps http host", strcmp(s.ws_host, "cdn.example") == 0);
    ok("ws path decoded", strcmp(s.path, "/ws") == 0);

    ok("decode ws host and sni",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443?security=tls&type=ws&sni=tls%2Eexample&host=cdn%2Eexample%3A443&path=%2Fws#wsenc",
                      &s) == CFG_OK);
    ok("decoded sni", strcmp(s.sni, "tls.example") == 0);
    ok("decoded ws host", strcmp(s.ws_host, "cdn.example:443") == 0);

    reason[0] = '\0';
    ok("ws flow rejected",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443?security=tls&type=ws&sni=tls.example&host=cdn.example&path=%2Fws&flow=xtls-rprx-vision#badws",
                      &s) == CFG_OK &&
       !cfg_validate_server(&s, reason, sizeof reason) &&
       strcmp(reason, "ws flow is unsupported") == 0);

    reason[0] = '\0';
    ok("plain tls valid",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp#tlsplain",
                      &s) == CFG_OK &&
       cfg_validate_server(&s, reason, sizeof reason));

    ok("encryption none valid",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp&encryption=none#tlsnone",
                      &s) == CFG_OK &&
       cfg_validate_server(&s, reason, sizeof reason));

    reason[0] = '\0';
    ok("non none encryption rejected",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp&encryption=mlkem768x25519plus#badenc",
                      &s) == CFG_OK &&
       !cfg_validate_server(&s, reason, sizeof reason) &&
       strcmp(reason, "unsupported encryption") == 0);

    ok("valid reality contract",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality&type=raw&flow=xtls-rprx-vision&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00#ok",
                      &s) == CFG_OK &&
       cfg_validate_server(&s, reason, sizeof reason));

    reason[0] = '\0';
    ok("invalid reality rejected",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality&type=tcp&flow=xtls-rprx-vision#bad",
                      &s) == CFG_OK &&
       !cfg_validate_server(&s, reason, sizeof reason) &&
       strcmp(reason, "reality requires valid pbk") == 0);

    reason[0] = '\0';
    ok("bad tls flow rejected",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=tcp&flow=none#bad",
                      &s) == CFG_OK &&
       !cfg_validate_server(&s, reason, sizeof reason) &&
       strcmp(reason, "unsupported tls flow") == 0);

    {
/* a panel that prefixes every node with the same banner used to hand back a
   list of identically named servers once the name was clipped */
        static const char *const banner =
            "top%20vpn%20%F0%9F%94%9D%20%7C%20%D0%BF%D0%BE%D0%B4%D0%BF%D0%B8%D1%81"
            "%D0%BA%D0%B0%20%D0%B0%D0%BA%D1%82%D0%B8%D0%B2%D0%BD%D0%B0%20%D0%B4%D0"
            "%BE%2008.09.2026%20%7C%20%D0%BE%D1%81%D1%82%D0%B0%D0%BB%D0%BE%D1%81%D1"
            "%8C%20940%20%D0%93%D0%91%20%7C%20";
        char link_a[1024], link_b[1024];
        vl_server_t a, b;
        snprintf(link_a, sizeof link_a,
                 "vless://11111111-1111-4111-8111-111111111111@a.example.com:443"
                 "?security=tls&type=tcp#%s%s", banner, "NL-1");
        snprintf(link_b, sizeof link_b,
                 "vless://11111111-1111-4111-8111-111111111111@b.example.com:443"
                 "?security=tls&type=tcp#%s%s", banner, "DE-2");
        ok("long shared banner keeps names distinct",
           cfg_parse_link(link_a, &a) == CFG_OK &&
           cfg_parse_link(link_b, &b) == CFG_OK &&
           strcmp(a.remark, b.remark) != 0);

        char link_long[2048];
        int off = snprintf(link_long, sizeof link_long,
                           "vless://11111111-1111-4111-8111-111111111111@c.example.com:443"
                           "?security=tls&type=tcp#");
        for (int i = 0; i < 200 && off < (int)sizeof link_long - 8; ++i)
            off += snprintf(link_long + off, sizeof link_long - (size_t)off, "%%D0%%AF");
        ok("an over long name is cut on a codepoint boundary",
           cfg_parse_link(link_long, &a) == CFG_OK &&
           strlen(a.remark) % 2 == 0 &&
           ((unsigned char)a.remark[strlen(a.remark) - 1] & 0xC0) == 0x80);
    }

/* multiMode servers register TunMulti, not Tun */
    ok("parse grpc multi",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443"
                      "?security=tls&type=grpc&serviceName=svc&mode=multi#g", &s) == CFG_OK);
    ok("grpc multi path", strcmp(s.path, "/svc/TunMulti") == 0 && s.grpc_multi);
    ok("parse grpc gun",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443"
                      "?security=tls&type=grpc&serviceName=svc&mode=gun#g", &s) == CFG_OK);
    ok("grpc gun path", strcmp(s.path, "/svc/Tun") == 0 && !s.grpc_multi);
    ok("parse grpc saved multi path",
       cfg_parse_link("vless://11111111-1111-4111-8111-111111111111@1.2.3.4:443"
                      "?security=tls&type=grpc&serviceName=%2Fsvc%2FTunMulti#g", &s) == CFG_OK);
    ok("a path that names the stream is kept", strcmp(s.path, "/svc/TunMulti") == 0);
    {
        static const char xray[] =
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{"
            "\"address\":\"1.2.3.4\",\"port\":443,\"users\":[{\"id\":"
            "\"11111111-1111-4111-8111-111111111111\"}]}]},\"streamSettings\":{"
            "\"network\":\"grpc\",\"security\":\"tls\",\"grpcSettings\":"
            "{\"serviceName\":\"svc\",\"multiMode\":true}}}]}";
        vl_server_t list[2];
        size_t n = 0;
        ok("xray json grpc multi",
           cfg_parse_subscription(xray, strlen(xray), list, 2, &n) == CFG_OK && n == 1 &&
           strcmp(list[0].path, "/svc/TunMulti") == 0);
    }

/* vmess: the v2rayn base64 json body and the xtls share link form */
#define VM_UUID "11111111-1111-4111-8111-111111111111"
    ok("v2rayn ws over tls",
       cfg_parse_link("vmess://eyJ2IjoiMiIsInBzIjoianAgd3MiLCJhZGQiOiJqcC5leGFtcGxlIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMTExMS00MTExLTgxMTEtMTExMTExMTExMTExIiwiYWlkIjoiMCIsInNjeSI6ImNoYWNoYTIwLXBvbHkxMzA1IiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJjZG4uZXhhbXBsZSIsInBhdGgiOiIvdm0iLCJ0bHMiOiJ0bHMiLCJzbmkiOiJzbmkuZXhhbXBsZSIsImZwIjoiY2hyb21lIn0=", &s) == CFG_OK &&
       cfg_validate_server(&s, reason, sizeof reason) && s.proto == VL_PROTO_VMESS &&
       strcmp(s.uuid, VM_UUID) == 0 && strcmp(s.encryption, "chacha20-poly1305") == 0 &&
       strcmp(s.user, "chacha20-poly1305") == 0 && s.net == VL_NET_WS &&
       strcmp(s.path, "/vm") == 0 && strcmp(s.ws_host, "cdn.example") == 0 &&
       s.security == VL_SEC_TLS && strcmp(s.sni, "sni.example") == 0 &&
       strcmp(s.fp, "chrome") == 0 && strcmp(s.remark, "jp ws") == 0);
    ok("v2rayn numeric port, no cipher, no tls",
       cfg_parse_link("vmess://eyJ2IjoiMiIsInBzIjoiIiwiYWRkIjoiMTAuMC4wLjEiLCJwb3J0Ijo4MDgwLCJpZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsImFpZCI6MCwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUiLCJ0bHMiOiIifQ==#named", &s) == CFG_OK &&
       cfg_validate_server(&s, reason, sizeof reason) && s.port == 8080 &&
       s.net == VL_NET_TCP && s.security == VL_SEC_NONE &&
       strcmp(s.encryption, "auto") == 0 && strcmp(s.remark, "named") == 0);
    ok("v2rayn grpc multi",
       cfg_parse_link("vmess://eyJ2IjoiMiIsInBzIjoiZyIsImFkZCI6ImcuZXhhbXBsZSIsInBvcnQiOiI0NDMiLCJpZCI6IjExMTExMTExLTExMTEtNDExMS04MTExLTExMTExMTExMTExMSIsIm5ldCI6ImdycGMiLCJ0eXBlIjoibXVsdGkiLCJwYXRoIjoic3ZjIiwidGxzIjoidGxzIn0=", &s) == CFG_OK &&
       s.net == VL_NET_GRPC && s.grpc_multi && strcmp(s.path, "/svc/TunMulti") == 0);
    ok("v2rayn tcp http header is refused",
       cfg_parse_link("vmess://eyJ2IjoiMiIsInBzIjoiaCIsImFkZCI6ImguZXhhbXBsZSIsInBvcnQiOiI4MCIsImlkIjoiMTExMTExMTEtMTExMS00MTExLTgxMTEtMTExMTExMTExMTExIiwibmV0IjoidGNwIiwidHlwZSI6Imh0dHAifQ==", &s) != CFG_OK);
    ok("v2rayn kcp is refused",
       cfg_parse_link("vmess://eyJ2IjoiMiIsInBzIjoiayIsImFkZCI6ImsuZXhhbXBsZSIsInBvcnQiOiI4MCIsImlkIjoiMTExMTExMTEtMTExMS00MTExLTgxMTEtMTExMTExMTExMTExIiwibmV0Ijoia2NwIn0=", &s) != CFG_OK ||
       !cfg_validate_server(&s, reason, sizeof reason));
    ok("v2rayn body without an id",
       cfg_parse_link("vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6Im4uZXhhbXBsZSIsInBvcnQiOiI4MCJ9", &s) != CFG_OK);
    ok("a body that is not base64", cfg_parse_link("vmess://%%%%not-base64%%%%", &s) != CFG_OK);
    ok("xtls share link form",
       cfg_parse_link("vmess://" VM_UUID "@example.com:443?encryption=aes-128-gcm&security=tls"
                      "&type=tcp#r", &s) == CFG_OK &&
       cfg_validate_server(&s, reason, sizeof reason) &&
       s.proto == VL_PROTO_VMESS && s.security == VL_SEC_TLS &&
       strcmp(s.encryption, "aes-128-gcm") == 0 && strcmp(s.user, "aes-128-gcm") == 0 &&
       strcmp(s.remark, "r") == 0);
    ok("xtls form without encryption runs auto",
       cfg_parse_link("vmess://" VM_UUID "@example.com:80?type=ws&path=%2F#w", &s) == CFG_OK &&
       strcmp(s.encryption, "auto") == 0 && s.net == VL_NET_WS && s.security == VL_SEC_NONE);
    ok("vmess carries no flow",
       cfg_parse_link("vmess://" VM_UUID "@example.com:443?security=tls&flow=xtls-rprx-vision#f",
                      &s) == CFG_OK && !cfg_validate_server(&s, reason, sizeof reason));
    ok("vmess needs an id", cfg_parse_link("vmess://@example.com:443?security=tls#f", &s) != CFG_OK ||
       !cfg_validate_server(&s, reason, sizeof reason));
    {
        static const char xray[] =
            "{\"outbounds\":[{\"protocol\":\"vmess\",\"settings\":{\"vnext\":[{"
            "\"address\":\"a.example\",\"port\":443,\"users\":[{\"id\":\"" VM_UUID "\","
            "\"alterId\":0,\"security\":\"aes-128-gcm\"}]}]},\"streamSettings\":{"
            "\"network\":\"ws\",\"security\":\"tls\",\"wsSettings\":{\"path\":\"/p\"}}}]}";
        static const char singbox[] =
            "{\"outbounds\":[{\"type\":\"vmess\",\"tag\":\"v\",\"server\":\"b.example\","
            "\"server_port\":443,\"uuid\":\"" VM_UUID "\",\"security\":\"chacha20-poly1305\","
            "\"tls\":{\"enabled\":true,\"server_name\":\"b.example\"}}]}";
        vl_server_t list[2];
        size_t n = 0;
        ok("xray vmess vnext",
           cfg_parse_subscription(xray, strlen(xray), list, 2, &n) == CFG_OK && n == 1 &&
           list[0].proto == VL_PROTO_VMESS && strcmp(list[0].encryption, "aes-128-gcm") == 0 &&
           strcmp(list[0].user, "aes-128-gcm") == 0 &&
           list[0].net == VL_NET_WS && list[0].security == VL_SEC_TLS &&
           strcmp(list[0].path, "/p") == 0);
        n = 0;
        ok("sing-box vmess",
           cfg_parse_subscription(singbox, strlen(singbox), list, 2, &n) == CFG_OK && n == 1 &&
           list[0].proto == VL_PROTO_VMESS &&
           strcmp(list[0].user, "chacha20-poly1305") == 0 && list[0].security == VL_SEC_TLS);
    }

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all config compat checks passed\n");
    return 0;
}
