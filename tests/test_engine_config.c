#include "engine_config.h"
#include "cJSON.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *g_dump_dir;
static int g_dumped;

static void dump(const char *json) {
    char path[512];
    FILE *f;
    if (!g_dump_dir) return;
    snprintf(path, sizeof path, "%s/engine-%02d.yaml", g_dump_dir, g_dumped++);
    f = fopen(path, "w");
    assert(f != NULL);
    fputs(json, f);
    fclose(f);
}

static void parse(const char *link, vl_server_t *server) {
    assert(cfg_parse_link(link, server) == CFG_OK);
}

/* the client chain of the one rule of the one listener */
static cJSON *render(const char *link, const char *ip, char *buffer, size_t cap) {
    vl_server_t server;
    parse(link, &server);
    assert(engine_config_supports(&server));
    assert(engine_config_render(&server, ip, 10808, buffer, cap) == 0);
    dump(buffer);
    cJSON *root = cJSON_Parse(buffer);
    assert(root != NULL);
    assert(cJSON_IsArray(root) && cJSON_GetArraySize(root) == 1);
    return root;
}

static const cJSON *chain_of(const cJSON *root) {
    const cJSON *listener = cJSON_GetArrayItem(root, 0);
    const cJSON *rule = cJSON_GetArrayItem(cJSON_GetObjectItem(listener, "rules"), 0);
    assert(rule != NULL);
    return cJSON_GetObjectItem(rule, "client_chain");
}

static const char *str(const cJSON *obj, const char *key) {
    const cJSON *item = cJSON_GetObjectItem(obj, key);
    assert(cJSON_IsString(item));
    return item->valuestring;
}

static const cJSON *inner(const cJSON *obj) {
    const cJSON *p = cJSON_GetObjectItem(obj, "protocol");
    assert(cJSON_IsObject(p));
    return p;
}

static void unsupported(const char *link) {
    vl_server_t server;
    char buffer[256];
    parse(link, &server);
    assert(!engine_config_supports(&server));
    assert(engine_config_render(&server, "203.0.113.7", 10808, buffer, sizeof buffer) == -1);
}

int main(int argc, char **argv) {
    char json[8192];
    cJSON *root;
    const cJSON *chain, *p;

    if (argc == 3 && strcmp(argv[1], "--dump") == 0) g_dump_dir = argv[2];

    /* vless + reality + vision: the listener, the dial address and every layer */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                  "?type=tcp&security=reality&sni=cdn.example.com&fp=chrome"
                  "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
                  "&flow=xtls-rprx-vision#node", "203.0.113.7", json, sizeof json);
    {
        const cJSON *listener = cJSON_GetArrayItem(root, 0);
        assert(strcmp(str(listener, "address"), "127.0.0.1:10808") == 0);
        assert(strcmp(str(inner(listener), "type"), "socks") == 0);
        const cJSON *rule = cJSON_GetArrayItem(cJSON_GetObjectItem(listener, "rules"), 0);
        assert(strcmp(str(rule, "action"), "allow") == 0);
        assert(cJSON_GetArraySize(cJSON_GetObjectItem(rule, "masks")) == 2);
    }
    chain = chain_of(root);
    assert(strcmp(str(chain, "address"), "203.0.113.7:443") == 0);
    p = inner(chain);
    assert(strcmp(str(p, "type"), "reality") == 0);
    assert(strcmp(str(p, "public_key"), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") == 0);
    assert(strcmp(str(p, "short_id"), "0123456789abcdef") == 0);
    assert(strcmp(str(p, "sni_hostname"), "cdn.example.com") == 0);
    assert(cJSON_IsTrue(cJSON_GetObjectItem(p, "vision")));
    p = inner(p);
    assert(strcmp(str(p, "type"), "vless") == 0);
    assert(strcmp(str(p, "user_id"), "11111111-1111-4111-8111-111111111111") == 0);
    cJSON_Delete(root);

    /* vless + tls + websocket, dialled over ipv6; the sni falls back to the host */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:8443"
                  "?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=front.example.com",
                  "2001:db8::1", json, sizeof json);
    chain = chain_of(root);
    assert(strcmp(str(chain, "address"), "[2001:db8::1]:8443") == 0);
    p = inner(chain);
    assert(strcmp(str(p, "type"), "tls") == 0);
    assert(strcmp(str(p, "sni_hostname"), "example.com") == 0);
    assert(cJSON_IsTrue(cJSON_GetObjectItem(p, "verify")));
    assert(cJSON_IsFalse(cJSON_GetObjectItem(p, "vision")));
    assert(strcmp(cJSON_GetArrayItem(cJSON_GetObjectItem(p, "alpn_protocols"), 0)->valuestring,
                  "http/1.1") == 0);
    p = inner(p);
    assert(strcmp(str(p, "type"), "websocket") == 0);
    assert(strcmp(str(p, "matching_path"), "/ws") == 0);
    assert(strcmp(str(cJSON_GetObjectItem(p, "matching_headers"), "host"), "front.example.com") == 0);
    assert(strcmp(str(inner(p), "type"), "vless") == 0);
    cJSON_Delete(root);

    /* vless + reality + xhttp speaks h2; an unknown mode falls back to auto */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                  "?type=xhttp&security=reality&sni=cdn.example.com"
                  "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab"
                  "&path=%2Fxh&mode=stream-one", "203.0.113.7", json, sizeof json);
    p = inner(inner(chain_of(root)));
    assert(strcmp(str(p, "type"), "xhttp") == 0);
    assert(strcmp(str(p, "path"), "/xh") == 0);
    assert(strcmp(str(p, "mode"), "stream-one") == 0);
    assert(strcmp(str(p, "http_version"), "h2") == 0);
    assert(strcmp(str(p, "host"), "cdn.example.com") == 0);
    cJSON_Delete(root);

    /* the profile's extra reaches the engine; defaults stay unset */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                  "?type=xhttp&security=reality&sni=cdn.example.com"
                  "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=ab&path=%2Fxh"
                  "&extra=%7B%22xPaddingBytes%22%3A%2250-60%22%2C%22scMaxEachPostBytes%22"
                  "%3A4096%2C%22noGRPCHeader%22%3Atrue%7D", "203.0.113.7", json, sizeof json);
    p = inner(inner(chain_of(root)));
    assert(strcmp(str(p, "x_padding_bytes"), "50-60") == 0);
    assert(cJSON_GetObjectItem(p, "sc_max_each_post_bytes")->valueint == 4096);
    assert(cJSON_IsTrue(cJSON_GetObjectItem(p, "no_grpc_header")));
    cJSON_Delete(root);

    /* request shaping for fronts that refuse bodies, by the engine's names;
       data in headers exists only in packet-up, whatever the mode says */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                  "?type=xhttp&security=tls&sni=cdn.example.com&path=%2Fxh"
                  "&extra=%7B%22uplinkDataPlacement%22%3A%22header%22%2C%22uplinkDataKey%22"
                  "%3A%22X-Up%22%2C%22uplinkChunkSize%22%3A%221000-2000%22%2C"
                  "%22uplinkHTTPMethod%22%3A%22GET%22%2C%22sessionIDPlacement%22%3A%22query%22"
                  "%2C%22sessionIDKey%22%3A%22sid%22%2C%22seqPlacement%22%3A%22cookie%22%2C"
                  "%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingPlacement%22%3A%22queryInHeader"
                  "%22%2C%22xPaddingHeader%22%3A%22X-Ref%22%2C%22xPaddingKey%22%3A%22q%22%2C"
                  "%22scMinPostsIntervalMs%22%3A%2210-50%22%7D",
                  "203.0.113.7", json, sizeof json);
    p = inner(inner(chain_of(root)));
    assert(strcmp(str(p, "mode"), "packet-up") == 0);
    assert(strcmp(str(p, "uplink_data_placement"), "header") == 0);
    assert(strcmp(str(p, "uplink_data_key"), "X-Up") == 0);
    assert(strcmp(str(p, "uplink_chunk_size"), "1000-2000") == 0);
    assert(strcmp(str(p, "uplink_http_method"), "GET") == 0);
    assert(strcmp(str(p, "session_placement"), "query") == 0);
    assert(strcmp(str(p, "session_key"), "sid") == 0);
    assert(strcmp(str(p, "seq_placement"), "cookie") == 0);
    assert(cJSON_GetObjectItem(p, "seq_key") == NULL);
    assert(cJSON_IsTrue(cJSON_GetObjectItem(p, "x_padding_obfs_mode")));
    assert(strcmp(str(p, "x_padding_placement"), "query-in-header") == 0);
    assert(strcmp(str(p, "x_padding_header"), "X-Ref") == 0);
    assert(strcmp(str(p, "x_padding_key"), "q") == 0);
    assert(strcmp(str(p, "sc_min_posts_interval_ms"), "10-50") == 0);
    cJSON_Delete(root);

    /* vless + tls + xhttp: the engine picks the alpn itself (h2 only) */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                  "?type=xhttp&security=tls&sni=cdn.example.com&path=%2Fxh",
                  "203.0.113.7", json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "type"), "tls") == 0);
    assert(cJSON_GetObjectItem(p, "alpn_protocols") == NULL);
    p = inner(p);
    assert(strcmp(str(p, "http_version"), "h2") == 0);
    assert(strcmp(str(p, "mode"), "auto") == 0);
    assert(strcmp(str(p, "host"), "cdn.example.com") == 0);
    assert(cJSON_GetObjectItem(p, "x_padding_bytes") == NULL);
    assert(cJSON_GetObjectItem(p, "no_grpc_header") == NULL);
    assert(cJSON_GetObjectItem(p, "uplink_data_placement") == NULL);
    assert(cJSON_GetObjectItem(p, "x_padding_obfs_mode") == NULL);
    cJSON_Delete(root);

    /* other query parameters of a websocket path stay, early data goes */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                  "?type=ws&security=none&path=%2Fa%3Fed%3D2048%26k%3Dv%26ed%3D1%26z",
                  "203.0.113.7", json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "matching_path"), "/a?k=v&z") == 0);
    assert(strcmp(str(cJSON_GetObjectItem(p, "matching_headers"), "host"), "example.com") == 0);
    cJSON_Delete(root);

    /* plain xhttp stays on http/1.1 */
    root = render("vless://11111111-1111-4111-8111-111111111111@example.com:80"
                  "?type=xhttp&security=none&path=%2F&host=cdn.example.com&mode=packet-up",
                  "203.0.113.7", json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "type"), "xhttp") == 0);
    assert(strcmp(str(p, "http_version"), "h1") == 0);
    assert(strcmp(str(p, "host"), "cdn.example.com") == 0);
    assert(strcmp(str(p, "mode"), "packet-up") == 0);
    cJSON_Delete(root);

    /* trojan + tls, allowInsecure turns verification off; quotes in the
       password stay inside the json string */
    root = render("trojan://pa%22ss%5Cword@example.com:443?security=tls&sni=t.example.com"
                  "&allowInsecure=1", "203.0.113.7", json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "type"), "tls") == 0);
    assert(cJSON_IsFalse(cJSON_GetObjectItem(p, "verify")));
    assert(cJSON_GetArraySize(cJSON_GetObjectItem(p, "alpn_protocols")) == 2);
    p = inner(p);
    assert(strcmp(str(p, "type"), "trojan") == 0);
    assert(strcmp(str(p, "password"), "pa\"ss\\word") == 0);
    cJSON_Delete(root);

    /* vmess over ws and tls; auto is the cipher the cpu runs fastest */
    root = render("vmess://11111111-1111-4111-8111-111111111111@example.com:443"
                  "?security=tls&type=ws&path=%2Fvm&encryption=aes-128-gcm", "203.0.113.7",
                  json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "type"), "tls") == 0);
    p = inner(p);
    assert(strcmp(str(p, "type"), "websocket") == 0);
    p = inner(p);
    assert(strcmp(str(p, "type"), "vmess") == 0);
    assert(strcmp(str(p, "cipher"), "aes-128-gcm") == 0);
    assert(strcmp(str(p, "user_id"), "11111111-1111-4111-8111-111111111111") == 0);
    cJSON_Delete(root);
    root = render("vmess://11111111-1111-4111-8111-111111111111@example.com:80?type=tcp",
                  "203.0.113.7", json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "type"), "vmess") == 0);
#if defined(__aarch64__) || defined(__x86_64__)
    assert(strcmp(str(p, "cipher"), "aes-128-gcm") == 0);
#else
    assert(strcmp(str(p, "cipher"), "chacha20-poly1305") == 0);
#endif
    cJSON_Delete(root);

    /* shadowsocks, both link forms; xray's 2022 chacha name becomes the engine's */
    root = render("ss://YWVzLTI1Ni1nY206c2VjcmV0@example.com:8388#ss", "203.0.113.7",
                  json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "type"), "shadowsocks") == 0);
    assert(strcmp(str(p, "cipher"), "aes-256-gcm") == 0);
    assert(strcmp(str(p, "password"), "secret") == 0);
    cJSON_Delete(root);
    root = render("ss://2022-blake3-chacha20-poly1305:a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U%3D"
                  "@example.com:8388", "203.0.113.7", json, sizeof json);
    p = inner(chain_of(root));
    assert(strcmp(str(p, "cipher"), "2022-blake3-chacha20-ietf-poly1305") == 0);
    cJSON_Delete(root);

    /* hysteria2: its own quic connection, tls beside the protocol */
    root = render("hysteria2://secret@example.com:8449?sni=cdn.example.com#hy",
                  "203.0.113.7", json, sizeof json);
    chain = chain_of(root);
    assert(strcmp(str(chain, "address"), "203.0.113.7:8449") == 0);
    assert(strcmp(str(chain, "transport"), "quic") == 0);
    p = inner(chain);
    assert(strcmp(str(p, "type"), "hysteria2") == 0);
    assert(strcmp(str(p, "password"), "secret") == 0);
    assert(cJSON_GetObjectItem(p, "salamander_password") == NULL);
    {
        const cJSON *q = cJSON_GetObjectItem(chain, "quic_settings");
        const cJSON *alpn = cJSON_GetObjectItem(q, "alpn_protocols");
        assert(strcmp(str(q, "sni_hostname"), "cdn.example.com") == 0);
        assert(cJSON_IsTrue(cJSON_GetObjectItem(q, "verify")));
        assert(cJSON_GetArraySize(alpn) == 1);
        assert(strcmp(cJSON_GetArrayItem(alpn, 0)->valuestring, "h3") == 0);
        assert(cJSON_GetObjectItem(q, "server_fingerprints") == NULL);
    }
    cJSON_Delete(root);

    /* salamander, a hop list (the first port is dialed) and a pinned
       certificate in openssl's colon form; a pin is trusted on its own */
    root = render("hy2://secret@example.com:20000-20010,443?obfs=salamander"
                  "&obfs-password=mask&pinSHA256="
                  "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:"
                  "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
                  "2001:db8::7", json, sizeof json);
    chain = chain_of(root);
    assert(strcmp(str(chain, "address"), "[2001:db8::7]:20000") == 0);
    p = inner(chain);
    assert(strcmp(str(p, "salamander_password"), "mask") == 0);
    {
        const cJSON *q = cJSON_GetObjectItem(chain, "quic_settings");
        const cJSON *pins = cJSON_GetObjectItem(q, "server_fingerprints");
        assert(strcmp(str(q, "sni_hostname"), "example.com") == 0);
        assert(cJSON_IsFalse(cJSON_GetObjectItem(q, "verify")));
        assert(cJSON_GetArraySize(pins) == 1);
        assert(strcmp(cJSON_GetArrayItem(pins, 0)->valuestring,
                      "ABCDEF0123456789ABCDEF0123456789"
                      "ABCDEF0123456789ABCDEF0123456789") == 0);
    }
    cJSON_Delete(root);

    /* two pins overflow the profile's field: the whole first one is kept,
       the cut second one is dropped */
    root = render("hysteria2://secret@example.com:443?pinSHA256="
                  "0000000000000000000000000000000000000000000000000000000000000001,"
                  "0000000000000000000000000000000000000000000000000000000000000002",
                  "203.0.113.7", json, sizeof json);
    {
        const cJSON *pins = cJSON_GetObjectItem(
            cJSON_GetObjectItem(chain_of(root), "quic_settings"), "server_fingerprints");
        assert(cJSON_GetArraySize(pins) == 1);
        assert(strcmp(cJSON_GetArrayItem(pins, 0)->valuestring,
                      "0000000000000000000000000000000000000000000000000000000000000001") == 0);
    }
    cJSON_Delete(root);

    /* insecure without a pin turns verification off */
    root = render("hysteria2://secret@example.com:443?insecure=1",
                  "203.0.113.7", json, sizeof json);
    assert(cJSON_IsFalse(cJSON_GetObjectItem(
        cJSON_GetObjectItem(chain_of(root), "quic_settings"), "verify")));
    cJSON_Delete(root);

    /* an obfuscation the engine's client does not know stays off it */
    {
        vl_server_t server;
        parse("hysteria2://secret@example.com:443", &server);
        snprintf(server.obfs, sizeof server.obfs, "gecko");
        snprintf(server.obfs_password, sizeof server.obfs_password, "mask");
        assert(!engine_config_supports(&server));
        snprintf(server.obfs, sizeof server.obfs, "salamander");
        server.obfs_password[0] = '\0';
        assert(!engine_config_supports(&server));
    }

    /* what stays on the c core */
    unsupported("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                "?type=grpc&security=tls&serviceName=senko");
    unsupported("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                "?type=tcp&security=tls&encryption=mlkem768x25519plus.native.0rtt.AAAA");
    unsupported("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                "?type=ws&security=tls&flow=xtls-rprx-vision");
    unsupported("vless://11111111-1111-4111-8111-111111111111@example.com:443"
                "?type=tcp&security=reality&sni=cdn.example.com");
    unsupported("ss://cmM0LW1kNTpzZWNyZXQ@example.com:8388");
    unsupported("socks5://user:pass@example.com:1080");

    /* a buffer too small fails instead of writing a cut config */
    {
        vl_server_t server;
        char small[64];
        parse("vless://11111111-1111-4111-8111-111111111111@example.com:443"
              "?type=tcp&security=tls", &server);
        assert(engine_config_render(&server, "203.0.113.7", 10808, small, sizeof small) == -1);
        assert(engine_config_render(&server, "203.0.113.7", 0, json, sizeof json) == -1);
        assert(engine_config_render(&server, "", 10808, json, sizeof json) == -1);
    }

    puts("engine_config: ok");
    return 0;
}
