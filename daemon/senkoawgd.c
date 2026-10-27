#define _DEFAULT_SOURCE

#include "core/awg_config.h"
#include "core/awg_handshake.h"
#include "core/awg_tunnel.h"
#include "awg_route.h"
#include "awg_pfroute.h"
#include "awg_utun.h"
#include "status.h"
#include "proc_detach.h"

#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <fcntl.h>
#include <notify.h>
#endif

static volatile sig_atomic_t g_stop;
static int g_sig_pipe[2] = { -1, -1 };

/* the wireguard timers (whitepaper section 6): a sender opens a new session
   once the current one is two minutes old, a receiver a little before the
   three minute hard limit, and a session nobody uses is left to expire. the
   old loop rekeyed every two minutes whether or not a single packet moved,
   which kept the cellular radio waking up all night for nothing */
#define AWG_REKEY_AFTER_MS        120000L
#define AWG_REJECT_AFTER_MS       180000L
#define AWG_REKEY_ON_RECEIVE_MS   (AWG_REJECT_AFTER_MS - 10000L - 5000L)
#define AWG_REKEY_RETRY_MS          5000L
#define AWG_REKEY_ATTEMPT_MS       90000L
#define AWG_STATUS_PATH "/var/run/legacyrayawgd.status"
#define AWG_STATUS_NOTIFY "com.legacyray.awg.status"
/* the app owns this file; one line, awg_keepalive=config|screen|off */
#define AWG_POWER_PATH "/var/mobile/Library/Preferences/LegacyRay/power.conf"

typedef enum {
    AWG_KEEPALIVE_CONFIG = 0, /* what the profile says */
    AWG_KEEPALIVE_SCREEN,     /* only while the screen is on */
    AWG_KEEPALIVE_OFF
} awg_keepalive_mode_t;

static void on_signal(int signal_number) {
    (void)signal_number;
    g_stop = 1;
    if (g_sig_pipe[1] >= 0) {
        char b = 's';
        ssize_t n = write(g_sig_pipe[1], &b, 1);
        (void)n;
    }
}

static awg_keepalive_mode_t read_keepalive_mode(void) {
    FILE *f = fopen(AWG_POWER_PATH, "r");
    if (!f) return AWG_KEEPALIVE_CONFIG;
    char line[128];
    awg_keepalive_mode_t mode = AWG_KEEPALIVE_CONFIG;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "awg_keepalive=", 14) != 0) continue;
        if (strncmp(line + 14, "screen", 6) == 0) mode = AWG_KEEPALIVE_SCREEN;
        else if (strncmp(line + 14, "off", 3) == 0) mode = AWG_KEEPALIVE_OFF;
        else mode = AWG_KEEPALIVE_CONFIG;
    }
    fclose(f);
    return mode;
}

static void write_status(const char *text) {
    FILE *f = fopen(AWG_STATUS_PATH, "w");
    if (!f) return;
    fprintf(f, "%s\n", text);
    fclose(f);
#if defined(__APPLE__)
/* the app listens for this instead of asking the setuid helper every second */
    (void)notify_post(AWG_STATUS_NOTIFY);
#endif
}

static void usage(const char *argv0) {
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "  %s --handshake <amneziawg.conf> [timeout_ms]\n", argv0);
    fprintf(stderr, "  %s --validate <amneziawg.conf>\n", argv0);
    fprintf(stderr, "  %s --run <amneziawg.conf> [timeout_ms]\n", argv0);
    fprintf(stderr, "  %s --interface-probe <amneziawg.conf>\n", argv0);
    fprintf(stderr, "  %s --route-probe <ipv4>\n", argv0);
    fprintf(stderr, "  %s --route-mutation-probe <destination-ipv4> <gateway-ipv4>\n", argv0);
    fprintf(stderr, "  %s --net-route-probe <amneziawg.conf> <network-ipv4> <netmask-ipv4>\n", argv0);
    fprintf(stderr, "  %s --route-plan-probe <amneziawg.conf> <endpoint-ipv4> <gateway-ipv4>\n", argv0);
}

/* the stock datagram buffers drop the tail of a burst from the server while
   the loop is busy decrypting, and each lost datagram is a tcp retransmit */
#define AWG_UDP_BUFFER (256 * 1024)

static void size_udp_buffers(int fd) {
    int size = AWG_UDP_BUFFER;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof size) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof size) != 0)
        fprintf(stderr, "legacyrayawgd: keeping the stock udp buffers (errno %d)\n", errno);
}

static int open_endpoint(const awg_config_t *cfg, char *endpoint, size_t endpoint_cap) {
    char port[8];
    snprintf(port, sizeof port, "%u", cfg->endpoint_port);
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_INET;
    if (getaddrinfo(cfg->endpoint_host, port, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        size_udp_buffers(fd);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            struct sockaddr_in *peer = (struct sockaddr_in *)ai->ai_addr;
            if (inet_ntop(AF_INET, &peer->sin_addr, endpoint, endpoint_cap)) {
                freeaddrinfo(res);
                return fd;
            }
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return -1;
}

static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static long monotonic_millis(void) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return 0;
    return (long)tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}

static int run_tunnel(const awg_config_t *cfg, int timeout_ms) {
    write_status("connecting");
    char ifname[32];
    int tun_fd = awg_utun_open(ifname, sizeof ifname);
    if (tun_fd < 0) {
        write_status("error utun unavailable");
        fprintf(stderr, "legacyrayawgd: utun unavailable (%s)\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "legacyrayawgd: created %s\n", ifname);
    char endpoint[64], gateway[64];
    int udp_fd = open_endpoint(cfg, endpoint, sizeof endpoint);
    if (udp_fd < 0) {
        write_status("error endpoint udp connect failed");
        fprintf(stderr, "legacyrayawgd: endpoint udp connect failed\n");
        close(tun_fd);
        return 1;
    }

    awg_tunnel_t tunnel;
    awg_tunnel_init(&tunnel, cfg);
    char reason[128];
    awg_hs_status_t hs = awg_handshake_establish_fd(udp_fd, cfg, timeout_ms,
                                                     &tunnel.handshake,
                                                     reason, sizeof reason);
    if (hs != AWG_HS_OK) {
        char status[160];
        snprintf(status, sizeof status, "error %s", reason);
        write_status(status);
        fprintf(stderr, "legacyrayawgd: %s\n", reason);
        close(udp_fd);
        close(tun_fd);
        return 1;
    }
    if (awg_route_gateway_for_endpoint(endpoint, gateway, sizeof gateway) != 0) {
        write_status("error physical gateway lookup failed");
        fprintf(stderr, "legacyrayawgd: physical gateway lookup failed\n");
        OPENSSL_cleanse(&tunnel, sizeof tunnel);
        close(udp_fd); close(tun_fd);
        return 1;
    }
    awg_route_plan_t route_plan;
    if (awg_route_plan_build(cfg, ifname, endpoint, gateway, &route_plan) != 0 ||
        awg_route_plan_up(&route_plan) != 0) {
        write_status("error route setup failed");
        fprintf(stderr, "legacyrayawgd: route setup failed\n");
        OPENSSL_cleanse(&tunnel, sizeof tunnel);
        close(udp_fd); close(tun_fd);
        return 1;
    }

    if (pipe(g_sig_pipe) == 0) {
        for (int i = 0; i < 2; ++i) {
            int fl = fcntl(g_sig_pipe[i], F_GETFL, 0);
            if (fl >= 0) (void)fcntl(g_sig_pipe[i], F_SETFL, fl | O_NONBLOCK);
        }
    } else {
        g_sig_pipe[0] = g_sig_pipe[1] = -1;
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    static uint8_t framed[AWG_DATAGRAM_MAX + 4];
    static uint8_t wire[AWG_DATAGRAM_MAX];
    static uint8_t inner[AWG_DATAGRAM_MAX];
    fprintf(stderr, "legacyrayawgd: linked %s to %s:%u\n",
            ifname, cfg->endpoint_host, cfg->endpoint_port);
    {
        char status[64];
        snprintf(status, sizeof status, "connected %s", ifname);
        write_status(status);
    }
    status_set(1);

    awg_keepalive_mode_t ka_mode = read_keepalive_mode();
    int screen_fd = -1, screen_token = 0, screen_off = 0;
#if defined(__APPLE__)
/* springboard posts this when the display blanks and unblanks; the state
   says which. registered only when the keepalive depends on it */
    if (ka_mode == AWG_KEEPALIVE_SCREEN && cfg->persistent_keepalive &&
        notify_register_file_descriptor("com.apple.springboard.hasBlankedScreen",
                                        &screen_fd, 0, &screen_token) == NOTIFY_STATUS_OK) {
        uint64_t st = 0;
        if (notify_get_state(screen_token, &st) == NOTIFY_STATUS_OK) screen_off = st != 0;
        int fl = fcntl(screen_fd, F_GETFL, 0);
        if (fl >= 0) (void)fcntl(screen_fd, F_SETFL, fl | O_NONBLOCK);
    } else {
        screen_fd = -1;
    }
#endif
    fprintf(stderr, "legacyrayawgd: keepalive %us, mode %s\n", cfg->persistent_keepalive,
            ka_mode == AWG_KEEPALIVE_OFF ? "off" :
            ka_mode == AWG_KEEPALIVE_SCREEN ? "screen on only" : "as configured");

    long now_ms = monotonic_millis();
    long last_tx_ms = now_ms;
    long last_handshake_ms = now_ms;
    long last_rekey_attempt_ms = 0;
    long rekey_wanted_since = 0; /* 0 when no traffic is asking for a session */
    int keys_dead_logged = 0;
/* a responder starts sending on new keys only once a packet sealed with them
   arrives, so a tunnel with nothing to send yet would leave the server's
   first packets waiting for a timer */
    {
        size_t wire_len = 0;
        if (awg_tunnel_seal(&tunnel, NULL, 0, wire, sizeof wire, &wire_len) == AWG_TUN_OK &&
            send(udp_fd, wire, wire_len, 0) != (ssize_t)wire_len)
            fprintf(stderr, "legacyrayawgd: first keepalive not sent (errno %d)\n", errno);
    }
    while (!g_stop) {
        now_ms = monotonic_millis();
        long key_age = now_ms - last_handshake_ms;
        int keepalive_s = cfg->persistent_keepalive;
        if (ka_mode == AWG_KEEPALIVE_OFF || (ka_mode == AWG_KEEPALIVE_SCREEN && screen_off))
            keepalive_s = 0;

/* a keepalive is a send like any other, so it may be the thing that asks
   for a new session */
        if (keepalive_s && now_ms - last_tx_ms >= (long)keepalive_s * 1000L) {
            if (key_age >= AWG_REKEY_AFTER_MS && !rekey_wanted_since)
                rekey_wanted_since = now_ms;
            if (key_age < AWG_REJECT_AFTER_MS) {
                size_t wire_len = 0;
                if (awg_tunnel_seal(&tunnel, NULL, 0, wire, sizeof wire, &wire_len) != AWG_TUN_OK ||
                    send(udp_fd, wire, wire_len, 0) != (ssize_t)wire_len)
                    break;
            }
            last_tx_ms = now_ms;
        }

        if (rekey_wanted_since && now_ms - rekey_wanted_since > AWG_REKEY_ATTEMPT_MS) {
/* nobody sent anything for the whole attempt window; stop knocking until
   traffic comes back */
            fprintf(stderr, "legacyrayawgd: rekey abandoned, the tunnel is idle\n");
            rekey_wanted_since = 0;
        }
        if (rekey_wanted_since && now_ms - last_rekey_attempt_ms >= AWG_REKEY_RETRY_MS) {
            last_rekey_attempt_ms = now_ms;
            awg_handshake_t refreshed;
            if (awg_handshake_establish_fd(udp_fd, cfg, timeout_ms, &refreshed,
                                           reason, sizeof reason) == AWG_HS_OK) {
                OPENSSL_cleanse(&tunnel.handshake, sizeof tunnel.handshake);
                tunnel.handshake = refreshed;
                tunnel.send_counter = 0;
                tunnel.recv_counter = 0;
                memset(tunnel.recv_window, 0, sizeof tunnel.recv_window);
                tunnel.have_recv_counter = 0;
                now_ms = monotonic_millis();
                last_handshake_ms = now_ms;
                last_tx_ms = now_ms;
                rekey_wanted_since = 0;
                keys_dead_logged = 0;
                key_age = 0;
            } else {
                OPENSSL_cleanse(&refreshed, sizeof refreshed);
                fprintf(stderr, "legacyrayawgd: rekey deferred: %s\n", reason);
                now_ms = monotonic_millis();
            }
        }

        long wait_ms = -1;
#define AWG_WAIT(v) do { long _v = (v); if (_v < 0) _v = 0; \
                         if (wait_ms < 0 || _v < wait_ms) wait_ms = _v; } while (0)
        if (keepalive_s) AWG_WAIT(last_tx_ms + (long)keepalive_s * 1000L - now_ms);
        if (rekey_wanted_since) {
            AWG_WAIT(last_rekey_attempt_ms + AWG_REKEY_RETRY_MS - now_ms);
            AWG_WAIT(rekey_wanted_since + AWG_REKEY_ATTEMPT_MS + 1 - now_ms);
        }
#undef AWG_WAIT

        struct pollfd pfd[4];
        nfds_t np = 0;
        pfd[np].fd = tun_fd; pfd[np].events = POLLIN; pfd[np].revents = 0; np++;
        pfd[np].fd = udp_fd; pfd[np].events = POLLIN; pfd[np].revents = 0; np++;
        int sig_i = -1, screen_i = -1;
        if (g_sig_pipe[0] >= 0) {
            sig_i = (int)np;
            pfd[np].fd = g_sig_pipe[0]; pfd[np].events = POLLIN; pfd[np].revents = 0; np++;
        }
        if (screen_fd >= 0) {
            screen_i = (int)np;
            pfd[np].fd = screen_fd; pfd[np].events = POLLIN; pfd[np].revents = 0; np++;
        }
        if (g_stop) break;
        int pr = poll(pfd, np, wait_ms < 0 ? -1 : (int)(wait_ms > 600000 ? 600000 : wait_ms));
        if (pr < 0 && errno == EINTR) continue;
        if (pr < 0) break;
        if (pr == 0) continue;
        now_ms = monotonic_millis();
        key_age = now_ms - last_handshake_ms;

        if (sig_i >= 0 && pfd[sig_i].revents) {
            char drain[16];
            while (read(g_sig_pipe[0], drain, sizeof drain) > 0) {}
        }
#if defined(__APPLE__)
        if (screen_i >= 0 && pfd[screen_i].revents) {
            int token = 0;
            while (read(screen_fd, &token, sizeof token) == (ssize_t)sizeof token) {}
            uint64_t st = 0;
            if (notify_get_state(screen_token, &st) == NOTIFY_STATUS_OK) {
                int off = st != 0;
                if (off != screen_off) {
                    screen_off = off;
/* waking up after a dark stretch: one keepalive now refreshes the nat
   mapping the silence may have let go */
                    if (!screen_off) last_tx_ms = 0;
                }
            }
        }
#endif
        if (pfd[0].revents & POLLIN) {
            ssize_t got = read(tun_fd, framed, sizeof framed);
            if (got > 4) {
                if (key_age >= AWG_REKEY_AFTER_MS && !rekey_wanted_since)
                    rekey_wanted_since = now_ms;
                if (key_age < AWG_REJECT_AFTER_MS) {
                    size_t wire_len = 0;
                    awg_tun_status_t tr = awg_tunnel_seal(&tunnel, framed + 4,
                                                           (size_t)got - 4,
                                                           wire, sizeof wire, &wire_len);
                    if (tr == AWG_TUN_OK) {
                        if (send(udp_fd, wire, wire_len, 0) != (ssize_t)wire_len) break;
                        last_tx_ms = now_ms;
                    }
                } else if (!keys_dead_logged) {
/* the session is past its hard limit; packets wait for the new one the
   rekey above is already asking for, as wireguard would */
                    fprintf(stderr, "legacyrayawgd: session expired, waiting for a new handshake\n");
                    keys_dead_logged = 1;
                }
            }
        }
        if (pfd[1].revents & POLLIN) {
            ssize_t got = recv(udp_fd, wire, sizeof wire, 0);
            if (got > 0) {
                size_t inner_len = 0;
                awg_tun_status_t tr = awg_tunnel_open(&tunnel, wire, (size_t)got,
                                                       inner, sizeof inner, &inner_len);
                if (tr == AWG_TUN_OK) {
                    if (key_age >= AWG_REKEY_ON_RECEIVE_MS && !rekey_wanted_since)
                        rekey_wanted_since = now_ms;
                    if (inner_len > 0) {
                        uint8_t version = inner[0] >> 4;
                        if (version == 4 || version == 6) {
                            uint32_t family = htonl(version == 4 ? AF_INET : AF_INET6);
                            memcpy(framed, &family, sizeof family);
                            memcpy(framed + 4, inner, inner_len);
                            if (write_all(tun_fd, framed, inner_len + 4) != 0) break;
                        }
                    }
                } else if (tr == AWG_TUN_ERR_FORMAT &&
                           awg_tunnel_looks_like_initiation(&tunnel, wire, (size_t)got)) {
/* the server has something for us and no session to send it in */
                    if (!rekey_wanted_since) rekey_wanted_since = now_ms;
                }
            }
        }
    }
#if defined(__APPLE__)
    if (screen_fd >= 0) notify_cancel(screen_token);
#endif
    awg_route_plan_down(&route_plan);
    status_set(0);
    write_status(g_stop ? "idle" : "error tunnel stopped");
    OPENSSL_cleanse(&tunnel, sizeof tunnel);
    close(udp_fd);
    close(tun_fd);
    return 0;
}

int main(int argc, char **argv) {
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);
    if (argc < 2 || (strcmp(argv[1], "--handshake") != 0 &&
                     strcmp(argv[1], "--validate") != 0 &&
                     strcmp(argv[1], "--run") != 0 &&
                     strcmp(argv[1], "--interface-probe") != 0 &&
                     strcmp(argv[1], "--route-probe") != 0 &&
                     strcmp(argv[1], "--route-mutation-probe") != 0 &&
                     strcmp(argv[1], "--net-route-probe") != 0 &&
                     strcmp(argv[1], "--route-plan-probe") != 0)) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--route-probe") == 0) {
        char detail[160];
        int rc = awg_pfroute_probe_get4(argv[2], detail, sizeof detail);
        fprintf(stderr, "legacyrayawgd: route probe %s\n", detail);
        return rc == 0 ? 0 : 1;
    }
    if (argc < 3) { usage(argv[0]); return 2; }
    if (strcmp(argv[1], "--route-mutation-probe") == 0) {
        if (argc < 4) { usage(argv[0]); return 2; }
        char detail[160]; int rc = awg_pfroute_probe_host4(argv[2], argv[3], detail, sizeof detail);
        fprintf(stderr, "legacyrayawgd: route mutation %s\n", detail);
        return rc == 0 ? 0 : 1;
    }
    int timeout_ms = argc > 3 ? atoi(argv[3]) : 5000;
    awg_config_t cfg;
    char reason[128];
    awg_cfg_status_t cr = awg_config_load_file(argv[2], &cfg, reason, sizeof reason);
    if (cr != AWG_CFG_OK) {
        if (strcmp(argv[1], "--validate") == 0)
            printf("ERR config rejected: %s\n", reason);
        else
            fprintf(stderr, "legacyrayawgd: config rejected: %s\n", reason);
        return 2;
    }
    if (strcmp(argv[1], "--validate") == 0) {
        printf("VALID AmneziaWG native config\n");
        return 0;
    }
    if (strcmp(argv[1], "--interface-probe") == 0) {
        char ifname[32];
        int fd = awg_utun_open(ifname, sizeof ifname);
        awg_route_plan_t plan;
        int ok = fd >= 0 && awg_route_plan_for_interface(&cfg, ifname, &plan) == 0 &&
                 awg_route_interface_up(&plan) == 0;
        if (fd >= 0) close(fd);
        fprintf(stderr, "legacyrayawgd: interface probe %s\n", ok ? "ok" : "failed");
        return ok ? 0 : 1;
    }
    if (strcmp(argv[1], "--net-route-probe") == 0) {
        if (argc < 5) { usage(argv[0]); return 2; }
        char ifname[32];
        int fd = awg_utun_open(ifname, sizeof ifname);
        awg_route_plan_t plan;
        int ok = fd >= 0 && awg_route_plan_for_interface(&cfg, ifname, &plan) == 0 &&
                 awg_route_interface_up(&plan) == 0;
        if (ok) ok = awg_pfroute_net4_if(1, argv[3], argv[4], ifname) == 0;
        if (ok) ok = awg_pfroute_net4_if(0, argv[3], argv[4], ifname) == 0;
        if (fd >= 0) close(fd);
        fprintf(stderr, "legacyrayawgd: network route probe %s\n", ok ? "ok" : "failed");
        return ok ? 0 : 1;
    }
    if (strcmp(argv[1], "--route-plan-probe") == 0) {
        if (argc < 5) { usage(argv[0]); return 2; }
        char ifname[32];
        int fd = awg_utun_open(ifname, sizeof ifname);
        awg_route_plan_t plan;
        int ok = fd >= 0 && awg_route_plan_build(&cfg, ifname, argv[3], argv[4], &plan) == 0 &&
                 awg_route_plan_up(&plan) == 0;
        if (ok) awg_route_plan_down(&plan);
        if (fd >= 0) close(fd);
        fprintf(stderr, "legacyrayawgd: route plan probe %s\n", ok ? "ok" : "failed");
        return ok ? 0 : 1;
    }
    if (strcmp(argv[1], "--run") == 0) {
        /* the tunnel has to outlive whatever started it */
        senko_proc_detach();
        return run_tunnel(&cfg, timeout_ms);
    }
    awg_hs_status_t hr = awg_handshake_probe(&cfg, timeout_ms, reason, sizeof reason);
    if (hr != AWG_HS_OK) {
        fprintf(stderr, "legacyrayawgd: %s\n", reason);
        return 1;
    }
    printf("legacyrayawgd: handshake accepted by %s:%u\n", cfg.endpoint_host, cfg.endpoint_port);
    return 0;
}
