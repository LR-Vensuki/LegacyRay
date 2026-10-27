#include "dns_msg.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static size_t make_query(uint8_t *buf, uint16_t type, int edns) {
    static const uint8_t name[] = {
        3, 'A', 'd', 's', 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0
    };
    memset(buf, 0, 64);
    buf[0] = 0x12;
    buf[1] = 0x34;
    buf[2] = 0x01;
    buf[5] = 1;
    buf[11] = edns ? 1 : 0;
    memcpy(buf + 12, name, sizeof name);
    size_t pos = 12 + sizeof name;
    buf[pos++] = (uint8_t)(type >> 8);
    buf[pos++] = (uint8_t)type;
    buf[pos++] = 0;
    buf[pos++] = 1;
    if (edns) {
        static const uint8_t opt[] = {
            0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0
        };
        memcpy(buf + pos, opt, sizeof opt);
        pos += sizeof opt;
    }
    return pos;
}

int main(void) {
    uint8_t query[64];
    uint8_t response[128];
    size_t query_len = make_query(query, 1, 1);
    size_t response_len = 0;
    dns_question_t question;

    ok("parse question",
       dns_msg_parse_question(query, query_len, &question) == DNS_MSG_OK &&
       strcmp(question.name, "ads.example") == 0 && question.type == 1 &&
       question.class_code == 1);
    ok("build zero response",
       dns_msg_build_block(query, query_len, DNS_BLOCK_ZERO,
                           response, sizeof response, &response_len) == DNS_MSG_OK);
    ok("zero preserves id and edns",
       response_len == query_len + 16 && response[0] == 0x12 && response[1] == 0x34 &&
       response[6] == 0 && response[7] == 1 && response[10] == 0 && response[11] == 1 &&
       memcmp(response + response_len - 11, query + query_len - 11, 11) == 0);

    dns_response_info_t info;
    ok("inspect zero response",
       dns_msg_response_info(response, response_len, &info) == DNS_MSG_OK &&
       info.min_ttl == 60 && info.ipv4_count == 1 && info.ipv4[0] == 0);
    ok("patch remaining ttl",
       dns_msg_patch_ttls(response, response_len, 25) == DNS_MSG_OK &&
       dns_msg_response_info(response, response_len, &info) == DNS_MSG_OK &&
       info.min_ttl == 35);
    ok("clamp ttl ceiling",
       dns_msg_clamp_ttls(response, response_len, 30, 32) == DNS_MSG_OK &&
       dns_msg_response_info(response, response_len, &info) == DNS_MSG_OK &&
       info.min_ttl == 32);

    query_len = make_query(query, 28, 0);
    ok("build ipv6 zero",
       dns_msg_build_block(query, query_len, DNS_BLOCK_ZERO,
                           response, sizeof response, &response_len) == DNS_MSG_OK &&
       response_len == query_len + 28 && response[response_len - 18] == 0 &&
       response[response_len - 17] == 16);

    query_len = make_query(query, 1, 1);
    ok("build nxdomain",
       dns_msg_build_block(query, query_len, DNS_BLOCK_NXDOMAIN,
                           response, sizeof response, &response_len) == DNS_MSG_OK &&
       (response[3] & 0x0f) == 3 && response[8] == 0 && response[9] == 1);
    ok("nxdomain negative ttl",
       dns_msg_response_info(response, response_len, &info) == DNS_MSG_OK &&
       info.negative && info.min_ttl == 60);

    ok("build refused",
       dns_msg_build_block(query, query_len, DNS_BLOCK_REFUSED,
                           response, sizeof response, &response_len) == DNS_MSG_OK &&
       (response[3] & 0x0f) == 5 && response[6] == 0 && response[7] == 0 &&
       response[8] == 0 && response[9] == 0);

    ok("build truncated",
       dns_msg_build_truncated(query, query_len, response, sizeof response,
                               &response_len) == DNS_MSG_OK &&
       response_len == query_len - 11 && response[0] == 0x12 && response[1] == 0x34 &&
       (response[2] & 0x82) == 0x82 && response[5] == 1 && response[7] == 0 &&
       response[11] == 0 &&
       dns_msg_parse_response_question(response, response_len, &question) == DNS_MSG_OK &&
       strcmp(question.name, "ads.example") == 0);

    ok("reject short output",
       dns_msg_build_block(query, query_len, DNS_BLOCK_ZERO,
                           response, 20, &response_len) == DNS_MSG_ERR_SPACE);

    query[12] = 0xc0;
    query[13] = 0x0c;
    ok("reject pointer loop",
       dns_msg_parse_question(query, query_len, &question) == DNS_MSG_ERR_FORMAT);

    /* what os x asks after an mDNSResponder HUP on a 10.0.2.x network */
    ok("dns-sd browse domain is local",
       dns_msg_locally_served("lb._dns-sd._udp.0.2.0.10.in-addr.arpa"));
    ok("private reverse zones are local",
       dns_msg_locally_served("1.1.168.192.in-addr.arpa") &&
       dns_msg_locally_served("5.0.16.172.in-addr.arpa") &&
       dns_msg_locally_served("31.172.in-addr.arpa") &&
       dns_msg_locally_served("9.0.254.169.in-addr.arpa") &&
       dns_msg_locally_served("1.0.0.127.in-addr.arpa") &&
       dns_msg_locally_served("3.2.1.100.100.in-addr.arpa"));
    ok("public reverse zones go upstream",
       !dns_msg_locally_served("1.1.1.1.in-addr.arpa") &&
       !dns_msg_locally_served("5.0.15.172.in-addr.arpa") &&
       !dns_msg_locally_served("5.0.32.172.in-addr.arpa") &&
       !dns_msg_locally_served("1.0.016.172.in-addr.arpa") &&
       !dns_msg_locally_served("172.in-addr.arpa") &&
       !dns_msg_locally_served("1.2.3.63.100.in-addr.arpa") &&
       !dns_msg_locally_served("in-addr.arpa"));
    ok("mdns and home names are local",
       dns_msg_locally_served("local") && dns_msg_locally_served("printer.local") &&
       dns_msg_locally_served("router.home.arpa"));
    ok("names that only end alike go upstream",
       !dns_msg_locally_served("example.com") && !dns_msg_locally_served("notlocal") &&
       !dns_msg_locally_served("xlocal") && !dns_msg_locally_served("my10.in-addr.arpa") &&
       !dns_msg_locally_served("") && !dns_msg_locally_served(NULL));
    ok("link-local and ula ipv6 reverse zones are local",
       dns_msg_locally_served("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa") &&
       dns_msg_locally_served("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa") &&
       !dns_msg_locally_served("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.0.ip6.arpa"));

    if (failures) {
        fprintf(stderr, "%d dns_msg check(s) failed\n", failures);
        return 1;
    }
    puts("dns_msg tests passed");
    return 0;
}
