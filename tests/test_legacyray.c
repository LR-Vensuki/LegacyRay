#define _DEFAULT_SOURCE
/* the daemon features legacyray adds on top of senko: exact-domain and port
   rules, the lan bypass switch, the new settings keys and the extra
   subscription metadata that has to survive a save and a reload */
#include "rules.h"
#include "store.h"
#include "routing.h"
#include "settings.h"
#include "tls_clienthello.h"
#include "geo.h"
#include "frag.h"
#include "control.h"

#include <sys/socket.h>

#include <sys/stat.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static void ok(const char *name, int cond) {
    if (!cond) {
        printf("FAIL %s\n", name);
        ++failures;
    }
}

static void test_rules(void) {
    rule_t rule;
    ok("exact domain parses",
       rules_parse("direct domain Example.COM", 25, &rule) == RULES_OK &&
       rule.type == RULE_TYPE_DOMAIN_FULL && strcmp(rule.value, "example.com") == 0);
    ok("single port parses",
       rules_parse("block port 0443", 15, &rule) == RULES_OK &&
       rule.type == RULE_TYPE_PORT && rule.port_lo == 443 && rule.port_hi == 443 &&
       strcmp(rule.value, "443") == 0);
    ok("port range parses",
       rules_parse("direct port 8000-8999", 21, &rule) == RULES_OK &&
       rule.port_lo == 8000 && rule.port_hi == 8999 &&
       strcmp(rule.value, "8000-8999") == 0);
    ok("reversed range rejected", rules_parse("direct port 9-1", 15, &rule) != RULES_OK);
    ok("port zero rejected", rules_parse("direct port 0", 13, &rule) != RULES_OK);
    ok("port overflow rejected", rules_parse("direct port 70000", 17, &rule) != RULES_OK);
    ok("port junk rejected", rules_parse("direct port 80x", 15, &rule) != RULES_OK);
    ok("type names round trip",
       strcmp(rule_type_name(RULE_TYPE_DOMAIN_FULL), "domain") == 0 &&
       strcmp(rule_type_name(RULE_TYPE_PORT), "port") == 0);

    static ruleset_t set;
    ruleset_init(&set);
    ok("add exact", ruleset_add_text(&set, "direct domain example.com", 25, NULL) == RULES_OK);
    size_t matched = SIZE_MAX;
    ok("exact matches itself",
       ruleset_match_domain(&set, "example.com", &matched) == RULE_ACTION_DIRECT &&
       matched == 0);
    ok("exact skips subdomains",
       ruleset_match_domain(&set, "www.example.com", &matched) == RULE_ACTION_PROXY &&
       matched == SIZE_MAX);

    char text[32];
    for (int i = 0; i < RULESET_MAX_PORT_RULES; ++i) {
        int n = snprintf(text, sizeof text, "block port %d", 1000 + i);
        ok("port rule fits", ruleset_add_text(&set, text, (size_t)n, NULL) == RULES_OK);
    }
    ok("port rule cap enforced",
       ruleset_add_text(&set, "block port 5000", 15, NULL) == RULES_ERR_FULL);
    ok("ports never match names",
       ruleset_match_domain(&set, "1000", &matched) == RULE_ACTION_PROXY);
}

static void test_firewall(void) {
    static ruleset_t set;
    ruleset_init(&set);
    ruleset_add_text(&set, "direct port 8000-8999", 21, NULL);
    ruleset_add_text(&set, "block port 25", 13, NULL);
    const char ifs[1][32] = { "en0" };
    char *pf = malloc(65536);
    size_t len = 0;

    routing_set_policy(1, &set);
    ok("pf with ports builds",
       routing_pf_conf_rules("203.0.113.7", &set, ifs, 1, 40000, 15353,
                             ROUTING_PF_ROUTE_TO_LO0, pf, 65536, &len) == ROUTING_OK);
    pf[len] = '\0';
    ok("direct range uses pf colon syntax",
       strstr(pf, "pass out quick on en0 inet proto tcp from any to any port { 8000:8999 } keep state") != NULL);
    ok("blocked port filtered",
       strstr(pf, "block return out quick on en0 inet proto tcp from any to any port { 25 }") != NULL);
    ok("direct port exempt from nat",
       strstr(pf, "no nat on en0 inet proto tcp from any to any port { 8000:8999 }") != NULL);
    ok("lan ranges bypassed", strstr(pf, "192.168.0.0/16") != NULL &&
                              strstr(pf, "100.64.0.0/10") != NULL);
    ok("port filters precede the redirect",
       strstr(pf, "port { 25 }") < strstr(pf, "route-to lo0"));
    ok("the device's own dns turns to lo0",
       strstr(pf, "pass out quick on en0 route-to lo0 inet proto udp from any to any port 53 keep state") != NULL &&
       strstr(pf, "rdr pass on lo0 inet proto udp from any to any port 53 -> 127.0.0.1 port 15353") != NULL &&
       strstr(pf, "nat on en0 inet proto udp from any to any port 53 -> 127.0.0.1") != NULL);

    routing_set_policy(0, NULL);
    ok("pf without lan builds",
       routing_pf_conf_rules("203.0.113.7", NULL, ifs, 1, 40000, 15353,
                             ROUTING_PF_RDR_TO, pf, 65536, &len) == ROUTING_OK);
    pf[len] = '\0';
    ok("lan off keeps loopback", strstr(pf, "127.0.0.0/8") != NULL);
    ok("lan off drops private ranges", strstr(pf, "192.168.0.0/16") == NULL &&
                                       strstr(pf, "10.0.0.0/8") == NULL);

    routing_ipfw_rule_t rules[ROUTING_MAX_RULES];
    size_t count = 0;
    routing_set_policy(1, &set);
    ok("ipfw with ports builds",
       routing_ipfw_rules("203.0.113.7", 40000, 1080, 15353, rules,
                          ROUTING_MAX_RULES, &count) == ROUTING_OK);
    int saw_allow = 0, saw_deny = 0, ascending = 1, lan = 0;
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(rules[i].rule_plain, "allow tcp from any to any 8000-8999") == 0) saw_allow = 1;
        if (strcmp(rules[i].rule_plain, "deny tcp from any to any 25") == 0) saw_deny = 1;
        if (strstr(rules[i].rule_plain, "169.254.0.0/16")) lan = 1;
        if (i && rules[i].number <= rules[i - 1].number) ascending = 0;
        ok("ipfw port rules stay below the fwd", rules[i].number <= 12020);
    }
    ok("ipfw direct port", saw_allow);
    ok("ipfw blocked port", saw_deny);
    ok("ipfw lan extras", lan);
    ok("ipfw ascending", ascending);

/* the kill switch keeps udp off the wire beside the tunnel */
    routing_set_kill_switch(1);
    ok("pf kill switch builds",
       routing_pf_conf_rules("203.0.113.7", NULL, ifs, 1, 40000, 15353,
                             ROUTING_PF_RDR_TO, pf, 65536, &len) == ROUTING_OK);
    pf[len] = '\0';
    ok("kill switch lets dns and ntp out",
       strstr(pf, "pass out quick on en0 inet proto udp from any to any port { 53, 123 } keep state") != NULL);
    ok("kill switch blocks other udp",
       strstr(pf, "block return out quick on en0 inet proto udp from any to ! <legacyray_bypass>\n") != NULL);
    ok("kill switch replaces the quic-only rule", strstr(pf, "port 443\n") == NULL);
    ok("ipfw kill switch builds",
       routing_ipfw_rules("203.0.113.7", 40000, 1080, 15353, rules,
                          ROUTING_MAX_RULES, &count) == ROUTING_OK);
    int deny_udp = 0, server_udp = 0, top = 0;
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(rules[i].rule_plain, "deny udp from any to any") == 0 && rules[i].number == 12029)
            deny_udp = 1;
        if (strcmp(rules[i].rule_plain, "allow udp from any to 203.0.113.7") == 0) server_udp = 1;
        if (rules[i].number > top) top = rules[i].number;
    }
    ok("ipfw kill switch denies udp", deny_udp && server_udp);
    ok("ipfw kill switch inside the cleanup range", top <= 12030 && count <= ROUTING_MAX_RULES);
    routing_set_kill_switch(0);
    ok("pf default keeps the quic rule",
       routing_pf_conf_rules("203.0.113.7", NULL, ifs, 1, 40000, 15353,
                             ROUTING_PF_RDR_TO, pf, 65536, &len) == ROUTING_OK);
    pf[len] = '\0';
    ok("quic blocked by default", strstr(pf, "port 443\n") != NULL);

    routing_set_policy(1, NULL);
    free(pf);
}

static void test_settings(void) {
    daemon_settings_t s;
    daemon_settings_defaults(&s);
    ok("defaults keep full tunnel", s.rules_enabled == 1 && s.rules_default == 0 &&
                                    s.bypass_lan == 1);
    ok("default version", strcmp(s.xray_version, "26.7.28") == 0);
    ok("set rules_default",
       daemon_settings_set(&s, "rules_default", 13, "direct", 6) == SETTINGS_OK &&
       s.rules_default == 1);
    ok("bad rules_default",
       daemon_settings_set(&s, "rules_default", 13, "block", 5) == SETTINGS_ERR_VALUE);
    ok("set version",
       daemon_settings_set(&s, "xray_version", 12, "25.10.15", 8) == SETTINGS_OK &&
       strcmp(s.xray_version, "25.10.15") == 0);
    ok("version needs three parts",
       daemon_settings_set(&s, "xray_version", 12, "25.10", 5) == SETTINGS_ERR_VALUE);
    ok("version parts are bytes",
       daemon_settings_set(&s, "xray_version", 12, "1.256.0", 7) == SETTINGS_ERR_VALUE);
    const char *ua = "Happ/3.26.3/iOS CFNetwork";
    ok("user agent keeps spaces",
       daemon_settings_set(&s, "sub_user_agent", 14, ua, strlen(ua)) == SETTINGS_OK &&
       strcmp(s.sub_user_agent, ua) == 0);
    ok("bypass lan toggles",
       daemon_settings_set(&s, "bypass_lan", 10, "0", 1) == SETTINGS_OK && s.bypass_lan == 0);

    char buf[4096];
    size_t len = 0;
    ok("serialize", daemon_settings_serialize(&s, buf, sizeof buf, &len) == 0);
    daemon_settings_t back;
    daemon_settings_defaults(&back);
    daemon_settings_apply_buf(&back, buf, len);
    ok("round trip", back.rules_default == 1 && back.bypass_lan == 0 &&
                     strcmp(back.xray_version, "25.10.15") == 0 &&
                     strcmp(back.sub_user_agent, ua) == 0);
}

static void test_store_extra(void) {
    static store_t st, back;
    store_init(&st);
    size_t sub = 0;
    ok("add sub", store_add_sub(&st, "panel", "https://panel.example/sub", &sub) == STORE_OK);
    ok("set extra", store_set_sub_extra(&st, sub, 12, 1767225600ULL,
                                        "https://panel.example/me?a=1 b") == STORE_OK);
    static char buf[1 << 20];
    size_t len = 0;
    ok("store serializes", store_serialize(&st, buf, sizeof buf, &len) == STORE_OK);
    buf[len] = '\0';
    ok("extra line written", strstr(buf, "SUBEXTRA ") != NULL);
    ok("store reloads", store_deserialize(&back, buf, len) == STORE_OK);
    ok("extra survives",
       back.subs[sub].update_interval_h == 12 &&
       back.subs[sub].refill_date == 1767225600ULL &&
       strcmp(back.subs[sub].web_page_url, "https://panel.example/me?a=1 b") == 0);
    const char *link = "happ://routing/onadd/eyJOYW1lIjoiUlUifQ==";
    ok("routing stored", store_set_sub_routing(&st, sub, link) == STORE_OK &&
                         strcmp(st.subs[sub].routing, link) == 0);
    ok("routing refuses spaces", store_set_sub_routing(&st, sub, "a b") == STORE_OK &&
                                 st.subs[sub].routing[0] == '\0');
    store_set_sub_routing(&st, sub, link);
    ok("routing serializes", store_serialize(&st, buf, sizeof buf, &len) == STORE_OK);
    buf[len] = '\0';
    ok("routing line written", strstr(buf, "SUBROUTING ") != NULL);
    store_init(&back);
    ok("routing reloads", store_deserialize(&back, buf, len) == STORE_OK &&
                          strcmp(back.subs[sub].routing, link) == 0);
}

/* the first two suites after the grease slot, read out of a built hello */
static int hello_suites(tls_fp_t fp, uint16_t *first, uint16_t *second, int grease) {
    tls_ch_params_t p;
    memset(&p, 0x11, sizeof p);
    p.sni = "www.example.com";
    p.fp = fp;
    p.p256_pub = NULL;
    p.mlkem768_pub = NULL;
    static uint8_t buf[2048];
    size_t len = 0;
    if (tls_build_clienthello(&p, buf, sizeof buf, &len) != TLS_CH_OK) return -1;
    size_t at = 1 + 3 + 2 + TLS_CH_RANDOM_LEN + 1 + TLS_CH_SESSIONID_LEN + 2;
    if (grease) at += 2;
    *first = (uint16_t)(buf[at] << 8 | buf[at + 1]);
    *second = (uint16_t)(buf[at + 2] << 8 | buf[at + 3]);
    return 0;
}

static void test_cipher_order(void) {
    uint16_t a = 0, b = 0;
    tls_ch_set_prefer_chacha(0);
    ok("chrome keeps aes first", hello_suites(TLS_FP_CHROME, &a, &b, 1) == 0 &&
                                 a == 0x1301 && b == 0x1303);
    tls_ch_set_prefer_chacha(1);
    ok("chrome without aes hardware", hello_suites(TLS_FP_CHROME, &a, &b, 1) == 0 &&
                                      a == 0x1303 && b == 0x1301);
    ok("edge without aes hardware", hello_suites(TLS_FP_EDGE, &a, &b, 1) == 0 &&
                                    a == 0x1303 && b == 0x1301);
    ok("randomized prefers chacha", hello_suites(TLS_FP_RANDOMIZED, &a, &b, 0) == 0 &&
                                    a == 0x1303 && b == 0x1301);
    ok("firefox is left alone", hello_suites(TLS_FP_FIREFOX, &a, &b, 0) == 0 &&
                                a == 0x1301 && b == 0x1303);
    tls_ch_set_prefer_chacha(0);

    daemon_settings_t s;
    daemon_settings_defaults(&s);
    ok("fragment off by default", s.fragment == 0 && s.fragment_min == 100 &&
                                  s.fragment_max == 200 && s.kill_switch == 0);
    ok("fragment size range", daemon_settings_set(&s, "fragment_size", 13, "5-40", 4) == SETTINGS_OK &&
                              s.fragment_min == 5 && s.fragment_max == 40);
    ok("fragment size single", daemon_settings_set(&s, "fragment_size", 13, "64", 2) == SETTINGS_OK &&
                               s.fragment_min == 64 && s.fragment_max == 64);
    ok("fragment size order", daemon_settings_set(&s, "fragment_size", 13, "40-5", 4) == SETTINGS_ERR_VALUE);
    ok("fragment delay bound", daemon_settings_set(&s, "fragment_delay", 14, "900", 3) == SETTINGS_ERR_VALUE);
    const char *site = "https://example.org/geo/dlc.dat";
    ok("geosite url", daemon_settings_set(&s, "geosite_url", 11, site, strlen(site)) == SETTINGS_OK &&
                      strcmp(s.geosite_url, site) == 0);
    ok("geosite url has no country", daemon_settings_set(&s, "geosite_url", 11,
                                         "https://x.org/%s.dat", 20) == SETTINGS_ERR_VALUE);
    const char *ip = "https://example.org/country/%s/list.txt";
    ok("geoip template", daemon_settings_set(&s, "geoip_url", 9, ip, strlen(ip)) == SETTINGS_OK);
    ok("geoip one template only", daemon_settings_set(&s, "geoip_url", 9,
                                      "https://x.org/%s/%s", 19) == SETTINGS_ERR_VALUE);
    ok("url needs a scheme", daemon_settings_set(&s, "geosite_url", 11, "ftp://x/y", 9) == SETTINGS_ERR_VALUE);
    ok("url has no spaces", daemon_settings_set(&s, "geosite_url", 11, "https://a b", 11) == SETTINGS_ERR_VALUE);
    daemon_settings_set(&s, "kill_switch", 11, "1", 1);
    daemon_settings_set(&s, "fragment", 8, "1", 1);
    static char dump[4096];
    size_t dump_len = 0;
    ok("new settings serialize", daemon_settings_serialize(&s, dump, sizeof dump, &dump_len) == 0);
    daemon_settings_t back;
    daemon_settings_defaults(&back);
    daemon_settings_apply_buf(&back, dump, dump_len);
    ok("new settings round trip", back.kill_switch == 1 && back.fragment == 1 &&
                                  back.fragment_min == 64 && back.fragment_max == 64 &&
                                  strcmp(back.geosite_url, site) == 0 &&
                                  strcmp(back.geoip_url, ip) == 0);
    daemon_settings_defaults(&s);
    ok("chacha on by default", s.prefer_chacha == 1);
    ok("chacha switch",
       daemon_settings_set(&s, "prefer_chacha", 13, "0", 1) == SETTINGS_OK &&
       s.prefer_chacha == 0);
}

/* a tiny protobuf writer for geosite / geoip fixtures */
typedef struct { uint8_t b[4096]; size_t n; } pbw_t;
static void pbw_varint(pbw_t *w, uint64_t v) {
    do { uint8_t c = v & 0x7f; v >>= 7; w->b[w->n++] = (uint8_t)(c | (v ? 0x80 : 0)); } while (v);
}
static void pbw_bytes(pbw_t *w, uint32_t field, const void *p, size_t n) {
    pbw_varint(w, (uint64_t)field << 3 | 2);
    pbw_varint(w, n);
    memcpy(w->b + w->n, p, n);
    w->n += n;
}
static void pbw_str(pbw_t *w, uint32_t field, const char *s) { pbw_bytes(w, field, s, strlen(s)); }
static void pbw_uint(pbw_t *w, uint32_t field, uint64_t v) {
    pbw_varint(w, (uint64_t)field << 3);
    pbw_varint(w, v);
}
static void pbw_msg(pbw_t *w, uint32_t field, const pbw_t *m) { pbw_bytes(w, field, m->b, m->n); }

static void site_domain(pbw_t *site, int type, const char *value, const char *attr) {
    pbw_t d = { {0}, 0 };
    pbw_uint(&d, 1, (uint64_t)type);
    pbw_str(&d, 2, value);
    if (attr) {
        pbw_t a = { {0}, 0 };
        pbw_str(&a, 1, attr);
        pbw_uint(&a, 2, 1);
        pbw_msg(&d, 3, &a);
    }
    pbw_msg(site, 2, &d);
}

static void test_geo(void) {
    char dir[] = "/tmp/lr-geo-XXXXXX";
    ok("geo tmp dir", mkdtemp(dir) != NULL);

    static pbw_t list, ru, google, ips, cc, cidr, v6;
    memset(&list, 0, sizeof list); memset(&ru, 0, sizeof ru);
    memset(&google, 0, sizeof google);
    pbw_str(&ru, 1, "CATEGORY-RU");
    site_domain(&ru, 3, "gosuslugi.ru", NULL);
    site_domain(&ru, 2, "Yandex.RU", NULL);
    site_domain(&ru, 0, "vk", NULL);
    site_domain(&ru, 1, "^abc[0-9]+\\.ru$", NULL);
    pbw_str(&google, 1, "GOOGLE");
    site_domain(&google, 2, "google.com", "cn");
    site_domain(&google, 2, "google.ru", NULL);
    pbw_msg(&list, 1, &ru);
    pbw_msg(&list, 1, &google);

    const char *codes[] = { "category-ru", "google@cn", "missing" };
    long found[3];
    ok("geosite extract", geo_extract_sites(list.b, list.n, codes, 3, dir, found) == GEO_OK);
    ok("geosite counts", found[0] == 4 && found[1] == 1 && found[2] == -1);
    uint8_t junk[] = { 0x0a, 0xff, 0xff, 0xff, 0x0f };
    ok("geosite rejects junk", geo_extract_sites(junk, sizeof junk, codes, 3, dir, found) == GEO_ERR_FORMAT);

    memset(&ips, 0, sizeof ips); memset(&cc, 0, sizeof cc);
    pbw_str(&cc, 1, "RU");
    memset(&cidr, 0, sizeof cidr);
    uint8_t net[4] = { 5, 3, 0, 0 };
    pbw_bytes(&cidr, 1, net, 4);
    pbw_uint(&cidr, 2, 16);
    pbw_msg(&cc, 2, &cidr);
    memset(&v6, 0, sizeof v6);
    uint8_t net6[16] = { 0x2a, 0x02 };
    pbw_bytes(&v6, 1, net6, 16);
    pbw_uint(&v6, 2, 32);
    pbw_msg(&cc, 2, &v6);
    pbw_msg(&ips, 1, &cc);
    const char *ipcodes[] = { "ru" };
    long ipfound[1];
    ok("geoip extract", geo_extract_ips(ips.b, ips.n, ipcodes, 1, dir, ipfound) == GEO_OK &&
                        ipfound[0] == 1);

    const char list_text[] = "# comment\n10.1.0.0/16\n10.2.0.0/16\n  10.1.5.0/24 \nbad line\n1.2.3.4\n";
    ok("cidr list saved", geo_save_ip_list(list_text, sizeof list_text - 1, "test", dir) == 4);
    ok("private list", geo_write_private(dir) > 5);

    geo_db_t *db = geo_db_new();
    ok("load sites", geo_db_load(db, 's', "category-ru", dir) == 3); /* regexp kept aside */
    ok("load attr", geo_db_load(db, 's', "google@cn", dir) == 1);
    ok("load ips", geo_db_load(db, 'i', "ru", dir) == 1);
    ok("load list", geo_db_load(db, 'i', "test", dir) == 4);
    ok("missing code", geo_db_load(db, 's', "nope", dir) == GEO_ERR_MISSING);
    ok("full match", geo_db_site_match(db, "category-ru", "gosuslugi.ru"));
    ok("full is exact", !geo_db_site_match(db, "category-ru", "www.gosuslugi.ru"));
    ok("suffix match", geo_db_site_match(db, "category-ru", "music.yandex.ru") &&
                       geo_db_site_match(db, "category-ru", "yandex.ru"));
    ok("suffix boundary", !geo_db_site_match(db, "category-ru", "notyandex.ru"));
    ok("keyword match", geo_db_site_match(db, "category-ru", "vk.com"));
    ok("attribute filter", geo_db_site_match(db, "google@cn", "google.com") &&
                           !geo_db_site_match(db, "google@cn", "google.ru"));
    uint8_t a1[4] = { 5, 3, 200, 1 }, a2[4] = { 5, 4, 0, 1 }, a3[4] = { 10, 2, 255, 255 },
            a4[4] = { 1, 2, 3, 4 }, a5[4] = { 1, 2, 3, 5 };
    ok("geoip in", geo_db_ip_match(db, "ru", a1));
    ok("geoip out", !geo_db_ip_match(db, "ru", a2));
    ok("merged ranges", geo_db_ip_match(db, "test", a3));
    ok("host route", geo_db_ip_match(db, "test", a4) && !geo_db_ip_match(db, "test", a5));

    geo_publish(db);
    rules_set_geo_site_matcher(geo_site_match);
    static ruleset_t rules;
    ruleset_init(&rules);
    ok("geosite rule", ruleset_add_text(&rules, "direct geosite Category-RU", 26, NULL) == RULES_OK &&
                       rules.entries[0].type == RULE_TYPE_GEOSITE &&
                       strcmp(rules.entries[0].value, "category-ru") == 0);
    ok("geoip rule", ruleset_add_text(&rules, "direct geoip ru", 15, NULL) == RULES_OK);
    ok("geoip has no attribute", ruleset_add_text(&rules, "direct geoip ru@x", 17, NULL) == RULES_ERR_VALUE);
    ok("bad code", ruleset_add_text(&rules, "direct geosite a/b", 18, NULL) == RULES_ERR_VALUE);
    size_t hit = 99;
    ok("rule uses geosite", ruleset_match_domain(&rules, "music.yandex.ru", &hit) == RULE_ACTION_DIRECT &&
                            hit == 0);
    ok("rule misses", ruleset_match_domain(&rules, "example.com", &hit) == RULE_ACTION_PROXY &&
                      hit == SIZE_MAX);
    geo_publish(NULL);
    ok("unpublished matches nothing", !geo_site_match("category-ru", "yandex.ru"));
    rules_set_geo_site_matcher(NULL);

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    ok("cleanup", system(cmd) == 0);
}

static void test_frag_and_verbs(void) {
    int sv[2];
    ok("socketpair", socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    uint8_t msg[700], got[700];
    for (size_t i = 0; i < sizeof msg; ++i) msg[i] = (uint8_t)(i * 7 + 3);
    frag_configure(1, 3, 9, 0);
    ok("fragmented write", frag_write_all(sv[0], msg, sizeof msg, 1000) == 0);
    size_t have = 0;
    while (have < sizeof got) {
        ssize_t n = read(sv[1], got + have, sizeof got - have);
        if (n <= 0) break;
        have += (size_t)n;
    }
    ok("fragments arrive whole and in order", have == sizeof msg && memcmp(got, msg, sizeof msg) == 0);
    frag_configure(0, 3, 9, 0);
    ok("plain write", frag_write_all(sv[0], msg, 10, 1000) == 0 && read(sv[1], got, 10) == 10);
    close(sv[0]);
    close(sv[1]);

    ctl_cmd_t cmd;
    ok("parse geo update", ctl_parse_cmd("GEO UPDATE", 10, &cmd) == CTL_OK &&
                           cmd.kind == CTL_CMD_GEO && strcmp(cmd.name, "update") == 0);
    ok("parse geo status", ctl_parse_cmd("GEO STATUS", 10, &cmd) == CTL_OK &&
                           strcmp(cmd.name, "status") == 0);
    ok("geo needs a verb", ctl_parse_cmd("GEO", 3, &cmd) != CTL_OK);
    ok("parse watch", ctl_parse_cmd("WATCH", 5, &cmd) == CTL_OK &&
                      cmd.kind == CTL_CMD_WATCH && cmd.server_index == 1);
    ok("parse watch off", ctl_parse_cmd("WATCH OFF", 9, &cmd) == CTL_OK && cmd.server_index == 0);
    ok("watch junk", ctl_parse_cmd("WATCH NOW", 9, &cmd) != CTL_OK);
}

int main(void) {
    test_frag_and_verbs();
    test_geo();
    test_cipher_order();
    test_rules();
    test_firewall();
    test_settings();
    test_store_extra();
    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("all legacyray checks passed\n");
    return 0;
}
