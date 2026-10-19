#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void pf_natlook_put_v4_for_test(const struct sockaddr_in *sin, uint8_t addr[16],
                                uint8_t port[4]);

int pf_natlook_parse_state_line_for_test(const char *line, uint16_t redir_port,
                                         uint16_t client_port, char *host,
                                         size_t host_cap, uint16_t *port);

static int g_fail = 0;

static void ok(const char *what, int cond) {
    if (cond) return;
    g_fail++;
    fprintf(stderr, "FAIL %s\n", what);
}

int main(void) {
    char host[64];
    uint16_t port = 0;

    const char *out_style =
        "ALL tcp 192.168.0.181:49351 -> 127.0.0.1:34370 -> 172.66.147.243:443";
    memset(host, 0, sizeof host);
    ok("out style parses",
       pf_natlook_parse_state_line_for_test(out_style, 12080, 34370,
                                            host, sizeof host, &port) == 0);
    ok("out style host", strcmp(host, "172.66.147.243") == 0);
    ok("out style port", port == 443);

    const char *in_style =
        "ALL tcp 127.0.0.1:12080 <- 172.66.147.243:443 <- 127.0.0.1:34370";
    memset(host, 0, sizeof host);
    port = 0;
    ok("in style parses",
       pf_natlook_parse_state_line_for_test(in_style, 12080, 34370,
                                            host, sizeof host, &port) == 0);
    ok("in style host", strcmp(host, "172.66.147.243") == 0);
    ok("in style port", port == 443);

    const char *stale_http =
        "ALL tcp 127.0.0.1:12080 <- 2.16.56.51:80 <- 127.0.0.1:48412";
    ok("stale in style ignored",
       pf_natlook_parse_state_line_for_test(stale_http, 12080, 34370,
                                            host, sizeof host, &port) != 0);

    const char *wrong_tail =
        "ALL tcp 127.0.0.1:12080 <- 172.66.147.243:443 <- 127.0.0.1:34371";
    ok("wrong client port ignored",
       pf_natlook_parse_state_line_for_test(wrong_tail, 12080, 34370,
                                            host, sizeof host, &port) != 0);

    /* the ioctl wants the port in network order, high byte first, whatever
       the cpu's own order is */
    struct sockaddr_in sin;
    uint8_t addr_slot[16], port_slot[4];
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(34370);
    inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
    memset(addr_slot, 0xee, sizeof addr_slot);
    memset(port_slot, 0xee, sizeof port_slot);
    pf_natlook_put_v4_for_test(&sin, addr_slot, port_slot);
    ok("lookup port high byte", port_slot[0] == (34370 >> 8));
    ok("lookup port low byte", port_slot[1] == (34370 & 0xff));
    ok("lookup port tail zero", port_slot[2] == 0 && port_slot[3] == 0);
    ok("lookup address", addr_slot[0] == 127 && addr_slot[3] == 1 && addr_slot[4] == 0 &&
                         addr_slot[15] == 0);

    if (g_fail) {
        fprintf(stderr, "%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("all pf_natlook checks passed\n");
    return 0;
}
