#define _DEFAULT_SOURCE

#include "core/config.h"
#include "../common/senko_paths.h"
#include "core/transport.h"
#include "core/transport_pick.h"
#include "core/vless.h"
#include <sys/socket.h>
#include <sys/un.h>
#include "core/store.h"
#include "ctl_server.h"
#include "daemon_ctl.h"
#include "dialer.h"
#include "loop.h"
#include "proc_detach.h"
#include "storefile.h"
#include "settings.h"
#include "status.h"
#include "../common/senko_paths.h"

#include <openssl/crypto.h>

#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include "netwatch.h"
#include "geo_ctl.h"
#include "core/geo.h"

static volatile sig_atomic_t g_stop = 0;
/* the managed loop can sleep in poll for minutes, so a stop request also
   writes to a pipe that is part of the poll set; a signal landing between the
   g_stop check and poll would otherwise wait for launchd's SIGKILL and leave
   the firewall rules behind */
static int g_sig_pipe[2] = { -1, -1 };

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
    if (g_sig_pipe[1] >= 0) {
        char b = 's';
        ssize_t n = write(g_sig_pipe[1], &b, 1);
        (void)n;
    }
}

static void open_signal_pipe(void) {
    if (g_sig_pipe[0] >= 0) return;
    if (pipe(g_sig_pipe) != 0) { g_sig_pipe[0] = g_sig_pipe[1] = -1; return; }
    for (int i = 0; i < 2; ++i) {
        int fl = fcntl(g_sig_pipe[i], F_GETFL, 0);
        if (fl >= 0) (void)fcntl(g_sig_pipe[i], F_SETFL, fl | O_NONBLOCK);
        (void)fcntl(g_sig_pipe[i], F_SETFD, FD_CLOEXEC);
    }
}

/* SIGUSR1 only wakes the loop: the kick sends it before it gives up on a daemon
   whose socket does not answer, and the wake-up puts back a socket file or token
   that something removed while the daemon slept */
static void on_wake(int sig) {
    (void)sig;
    if (g_sig_pipe[1] >= 0) {
        char b = 1;
        ssize_t w = write(g_sig_pipe[1], &b, 1);
        (void)w;
    }
}

static void install_signals(void) {
    signal(SIGPIPE, SIG_IGN); /* ignore broken client sockets */
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGUSR1, on_wake);
}

/* nothing scheduled still wakes the daemon once in a long while, so a
   deadline some module forgot to report costs minutes, not a hang */
#define DAEMON_IDLE_CAP_MS (15 * 60 * 1000)

static int daemon_idle_timeout(int a, int b, int c) {
    int best = -1;
    int v[3] = { a, b, c };
    for (int i = 0; i < 3; ++i)
        if (v[i] >= 0 && (best < 0 || v[i] < best)) best = v[i];
    if (best < 0 || best > DAEMON_IDLE_CAP_MS) best = DAEMON_IDLE_CAP_MS;
    return best;
}

static int run_single(const char *link, int port) {
    vl_server_t srv;
    if (cfg_parse_link(link, &srv) != CFG_OK) {
        fprintf(stderr, "bad server link\n");
        return 2;
    }
    char reason[128];
    if (!cfg_validate_server(&srv, reason, sizeof reason)) {
        fprintf(stderr, "unsupported server: %s\n",
                reason[0] ? reason : "unknown");
        return 2;
    }
    const transport_vt_t *vt = transport_for_server(&srv);
    if (!vt) { fprintf(stderr, "unknown security mode\n"); return 2; }

    uint8_t uuid[VLESS_UUID_LEN];
    memset(uuid, 0, sizeof uuid);
    if (srv.proto == VL_PROTO_VLESS) {
        if (vless_uuid_parse(srv.uuid, uuid) != VLESS_OK) {
            fprintf(stderr, "bad uuid in link\n");
            return 2;
        }
    }

    dialer_ctx_t dctx;
    dialer_set_target(&dctx, srv.host, srv.port);

    /* heap allocation avoids overflowing the small default stack on ios 5 */
    static loop_t lp;
    if (loop_init(&lp, (uint16_t)port, 0, vt, dialer_connect, &dctx,
                  srv.proto, uuid, srv.flow, srv.user, srv.pass) != LOOP_OK) {
        fprintf(stderr, "failed to bind socks listener on port %d\n", port);
        return 1;
    }
    loop_set_tls(&lp, srv.sni, srv.fp, srv.pbk, srv.sid, srv.path, srv.ws_host,
                 srv.mode, srv.host, srv.insecure);
    {
        transport_xhttp_opts_t xh = transport_xhttp_opts(&srv);
        loop_set_xhttp(&lp, &xh);
    }

    install_signals();
    fprintf(stderr, "legacyrayd: socks5 on 127.0.0.1:%u -> %s:%u (%s)\n",
            loop_listen_port(&lp), srv.host, srv.port,
            srv.remark[0] ? srv.remark : "server");

    while (!g_stop) {
        if (loop_step(&lp, 1000) != LOOP_OK) break;
    }
    fprintf(stderr, "legacyrayd: shutting down\n");
    loop_close(&lp);
    return 0;
}

/* one managed daemon at a time. two of them used to start side by side
   (launchd's job and the kick's direct spawn, or a respawn racing a slow
   start) and take the socket file and the token from each other, which left a
   daemon running for days that no client could talk to. the lock lives in
   /var/run, where only root can create it, and is held for the life of the
   process; a second copy waits for it instead of exiting, so launchd's
   KeepAlive does not respawn it every few seconds and it takes over the
   moment the first one dies */
static int take_instance_lock(const char *ctl_path) {
    char path[128];
    const char *base = strrchr(ctl_path, '/');
    base = base ? base + 1 : ctl_path;
    size_t bl = strlen(base);
    if (bl > 5 && strcmp(base + bl - 5, ".sock") == 0) bl -= 5;
    int fd = -1;
    if (snprintf(path, sizeof path, "/var/run/%.*s.lock", (int)bl, base) < (int)sizeof path)
        fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    /* the socket's directory is world-writable on the phone, where anyone could
       hold a lock file made there; it is only a fallback for unprivileged runs */
    if (fd < 0 && geteuid() != 0 &&
        snprintf(path, sizeof path, "%s.lock", ctl_path) < (int)sizeof path)
        fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fprintf(stderr, "legacyrayd: no instance lock (%s); continuing without one\n",
                strerror(errno));
        return -1;
    }
    /* children (pfctl, the awg helper) must not keep the lock past the daemon */
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    /* the kick nudges every legacyrayd with SIGUSR1; a waiting copy ignores it */
    signal(SIGUSR1, SIG_IGN);
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        char held[24] = "?";
        ssize_t n = pread(fd, held, sizeof held - 1, 0);
        if (n > 0) {
            held[n] = '\0';
            held[strcspn(held, "\r\n")] = '\0';
        }
        fprintf(stderr, "legacyrayd: another daemon (pid %s) is running; "
                        "waiting to take over from it\n", held);
        while (flock(fd, LOCK_EX) != 0) {
            if (errno != EINTR) {
                fprintf(stderr, "legacyrayd: instance lock failed: %s\n", strerror(errno));
                close(fd);
                return -2;
            }
        }
        fprintf(stderr, "legacyrayd: the other daemon exited, taking over\n");
    }
    char pid[24];
    int pl = snprintf(pid, sizeof pid, "%ld\n", (long)getpid());
    if (ftruncate(fd, 0) == 0 && pl > 0) (void)pwrite(fd, pid, (size_t)pl, 0);
    return fd;
}

/* the system log is the daemon's stderr, opened by launchd or the kick, and
   nothing ever rotated it: on the ipad it had grown to 25 MB. past the limit
   the newest part moves to a .old file and the log starts over */
#define LOG_TRIM_BYTES (2L * 1024 * 1024)
#define LOG_KEEP_BYTES (256L * 1024)
#define LOG_TRIM_EVERY_S (10L * 60)

/* seconds are enough for a ten minute schedule, and fit a 32-bit long */
static long clock_s(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec;
}

static void trim_system_log(void) {
    struct stat st;
    if (fstat(STDERR_FILENO, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= LOG_TRIM_BYTES)
        return;
    /* stderr is write-only, so the tail is read through a descriptor of our own,
       and only from the file stderr really is */
    struct stat named;
    int in = open(SENKO_SYSTEM_LOG, O_RDONLY | O_NOFOLLOW);
    if (in < 0) return;
    if (fstat(in, &named) != 0 || named.st_dev != st.st_dev || named.st_ino != st.st_ino) {
        close(in);
        return;
    }
    char *tail = (char *)malloc((size_t)LOG_KEEP_BYTES);
    ssize_t n = tail ? pread(in, tail, (size_t)LOG_KEEP_BYTES, st.st_size - LOG_KEEP_BYTES) : -1;
    close(in);
    int saved = 0;
    if (n > 0) {
        int out = open(SENKO_SYSTEM_LOG ".old", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0640);
        if (out >= 0) {
            saved = write(out, tail, (size_t)n) == n;
            close(out);
        }
    }
    free(tail);
    if (!saved || ftruncate(STDERR_FILENO, 0) != 0) return;
    /* without O_APPEND the next write would land at the old offset */
    int fl = fcntl(STDERR_FILENO, F_GETFL, 0);
    if (fl >= 0 && !(fl & O_APPEND)) (void)lseek(STDERR_FILENO, 0, SEEK_SET);
    fprintf(stderr, "legacyrayd: log trimmed, the previous %ld KB are in %s.old\n",
            LOG_KEEP_BYTES / 1024, SENKO_SYSTEM_LOG);
}

static int run_managed(const char *ctl_path, const char *config_path,
                       int full_device, daemon_settings_t *settings) {
    if (!settings) return 2;
    /* the tunnel has to outlive whatever started it */
    senko_proc_detach();
    trim_system_log();
    int port = (int)settings->socks_port;
    int socks_public = settings->socks_public;
    /* stale socket files survive crashes, so a live connect decides ownership */
    int check_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (check_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof addr);
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, ctl_path, sizeof addr.sun_path - 1);
        if (connect(check_fd, (struct sockaddr *)&addr, sizeof addr) == 0) {
            close(check_fd);
            fprintf(stderr, "legacyrayd: already running\n");
            return 0;
        } else {
            int connect_errno = errno;
            close(check_fd);
            if (connect_errno == ENOENT || connect_errno == ECONNREFUSED)
                unlink(ctl_path);
            else
                return 1;
        }
    }

    uint8_t zero_uuid[VLESS_UUID_LEN];
    memset(zero_uuid, 0, sizeof zero_uuid);

    /* delaying activation prevents traffic from leaving through an unselected server */
    static loop_t lp;
    if (loop_init(&lp, (uint16_t)port, socks_public, &transport_tcp, dialer_connect, NULL,
                  VL_PROTO_VLESS, zero_uuid, NULL, NULL, NULL) != LOOP_OK) {
        fprintf(stderr, "failed to bind socks listener on port %d\n", port);
        return 1;
    }
    uint16_t actual_port = loop_listen_port(&lp);
    if (actual_port != (uint16_t)port) {
        fprintf(stderr, "legacyrayd: socks port %d is busy; refusing duplicate daemon\n", port);
        loop_close(&lp);
        return 1;
    }
    loop_stop(&lp); /* inactive until a server is selected */

    daemon_ctl_t dc;
    daemon_ctl_init(&dc, &lp, config_path);
    daemon_ctl_set_full_device(&dc, full_device);
    daemon_ctl_set_settings(&dc, settings);

    status_set(0);

    /* a crash can leave either rule set behind, and only the go backend
       installs none of them */
    if (!go_backend_supported()) c_backend_clear_stale();
    engine_backend_clear_stale(&dc.engine);

    static ctl_server_t cs;
    if (ctl_server_init(&cs, ctl_path, daemon_ctl_apply, &dc) != CTLS_OK) {
        fprintf(stderr, "failed to bind control socket at %s\n", ctl_path);
        loop_close(&lp);
        return 1;
    }

    ctl_server_set_persist(&cs, daemon_ctl_persist);

    ctl_server_set_fetch(&cs, daemon_ctl_fetch);

    ctl_server_set_probe(&cs, daemon_ctl_probe);
    ctl_server_set_server_probe(&cs, daemon_ctl_probe_server);

    ctl_server_set_verify(&cs, daemon_ctl_verify_tunnel);

    ctl_server_set_tunnel_probe(&cs, daemon_ctl_ping_tunnel);

    ctl_server_set_backup(&cs, daemon_ctl_backup);
    ctl_server_set_check(&cs, daemon_ctl_check);
    ctl_server_set_reason(&cs, daemon_ctl_last_reason);
/* one live copy of the settings from here on: the daemon writes it, the control
   server reads it for the SETTINGS dump and for the schedules it runs */
    ctl_server_set_settings(&cs, &dc.settings);
    ctl_server_set_diag(&cs, daemon_ctl_diag);
    ctl_server_set_fwconf(&cs, daemon_ctl_fwconf);
    ctl_server_set_flush(&cs, daemon_ctl_flush);
    ctl_server_set_native_config(&cs, daemon_ctl_native_config);
    ctl_server_set_stats(&cs, daemon_ctl_stats);
    ctl_server_set_geo(&cs, daemon_ctl_geo);
    daemon_ctl_set_rules(&dc, &cs.engine.store.rules);

    if (config_path && config_path[0]) {
/* the settings were merged from this file and the command line before the
   listener was bound, and reading them again here would put the file back on
   top of the arguments */
        storefile_status_t lrc = storefile_load(&cs.engine.store, NULL, config_path);
        if (lrc == STOREFILE_OK)
            fprintf(stderr, "legacyrayd: loaded %zu server(s) from %s\n",
                    cs.engine.store.n, config_path);
        else if (lrc == STOREFILE_ERR_PATH)
            fprintf(stderr, "legacyrayd: %s is outside the folders the daemon keeps "
                    "its config in; nothing will be loaded from it or saved to it\n",
                    config_path);
        else
            fprintf(stderr, "legacyrayd: cannot read %s (error %d)\n",
                    config_path, (int)lrc);
    }

/* the dns proxy consults geosite sets as soon as a tunnel is up, and the
   lists extracted last time are already on disk */
    rules_set_geo_site_matcher(geo_site_match);
    (void)geo_ctl_reload(&cs.engine.store.rules, NULL, 0);

    install_signals();
    if (socks_public) {
        fprintf(stderr,
                "legacyrayd: WARNING socks_public=1 binds SOCKS on 0.0.0.0 "
                "(LAN-reachable; disable unless intentional)\n");
    }
    fprintf(stderr, "legacyrayd: managed mode%s. socks5 on %s:%u, control at %s\n",
            full_device ? " (full-device routing)" : "",
            socks_public ? "0.0.0.0" : "127.0.0.1",
            loop_listen_port(&lp), ctl_path);

/* a daemon started by legacyray-kick after a reboot has no client to ask for the
   tunnel, so the stored selection is what brings routing back */
    if (dc.settings.auto_connect) {
        if (ctl_server_restore_tunnel(&cs) == 0)
            fprintf(stderr, "legacyrayd: auto-connected to server %d\n",
                    cs.engine.store.selected);
        else
            fprintf(stderr, "legacyrayd: auto-connect found no server to start\n");
    }

/* one poll over everything the daemon listens to, with a timeout that
   reaches the next thing actually scheduled. the loop used to take turns
   between two 50 ms polls, which woke the phone ten times a second around
   the clock, tunnel or not, and added up to 50 ms to every packet that
   arrived while the other half was waiting */
    open_signal_pipe();
    int route_fd = netwatch_open();
    ctl_server_set_netwatch(&cs, route_fd >= 0);
    if (route_fd < 0)
        fprintf(stderr, "legacyrayd: no routing socket; network moves are polled\n");

    static struct pollfd pfd[LOOP_POLLFD_MAX + CTL_SERVER_POLLFD_MAX + 2];
    long last_trim_s = clock_s();
    while (!g_stop) {
        size_t nl = loop_prepare(&lp, pfd, LOOP_POLLFD_MAX);
        size_t nc = ctl_server_prepare(&cs, pfd + nl, CTL_SERVER_POLLFD_MAX);
        size_t nf = nl + nc;
        int sig_idx = -1, route_idx = -1;
        if (g_sig_pipe[0] >= 0) {
            sig_idx = (int)nf;
            pfd[nf].fd = g_sig_pipe[0]; pfd[nf].events = POLLIN; pfd[nf].revents = 0;
            nf++;
        }
        if (route_fd >= 0) {
            route_idx = (int)nf;
            pfd[nf].fd = route_fd; pfd[nf].events = POLLIN; pfd[nf].revents = 0;
            nf++;
        }

        int timeout = daemon_idle_timeout(loop_timeout_ms(&lp),
                                          ctl_server_timeout_ms(&cs),
                                          daemon_ctl_timeout_ms(&dc));
        if (g_stop) break;
        int r = poll(pfd, (nfds_t)nf, timeout);
        if (r < 0 && errno != EINTR) {
            fprintf(stderr, "legacyrayd: poll failed: %s\n", strerror(errno));
            break;
        }
        if (r > 0) {
            loop_dispatch(&lp, pfd, nl);
            ctl_server_dispatch(&cs, pfd + nl, nc);
            if (sig_idx >= 0 && (pfd[sig_idx].revents & POLLIN)) {
                char drain[16];
                while (read(g_sig_pipe[0], drain, sizeof drain) > 0) {}
            }
            if (route_idx >= 0 && pfd[route_idx].revents) {
                int moved = netwatch_drain(route_fd);
                if (moved > 0) ctl_server_network_changed(&cs);
                if (moved < 0) {
                    netwatch_close(route_fd);
                    route_fd = netwatch_open();
                    ctl_server_set_netwatch(&cs, route_fd >= 0);
                }
            }
        }
/* the backend can die between two control commands, and the redial schedule
   lives with the store that knows which server to dial */
        if (daemon_ctl_maintain(&dc) != 0)
            ctl_server_tunnel_lost(&cs);
        ctl_server_tick(&cs);
        long now_s = clock_s();
        if (now_s < last_trim_s || now_s - last_trim_s >= LOG_TRIM_EVERY_S) {
            last_trim_s = now_s;
            trim_system_log();
        }
    }
    netwatch_close(route_fd);

    fprintf(stderr, "legacyrayd: shutting down\n");
    daemon_ctl_shutdown(&dc);
    if (config_path && config_path[0])
        storefile_save(&cs.engine.store, &dc.settings, config_path);
    ctl_server_close(&cs);
    loop_close(&lp);
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage:\n"
        "  %s <vless://link> [socks_port]\n"
        "  %s --managed [--ctl <sockpath>] [--config <path>]\n"
        "       [--socks-port <n>] [--socks-public] [--dns-upstream <ip>]\n"
        "       [--dns-local-port <n>] [--full-device]\n",
        argv0, argv0);
}

static void parse_managed_args(int argc, char **argv,
                               const char **ctl_path,
                               const char **config_path,
                               daemon_settings_t *settings,
                               int *full_device) {
    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--ctl") == 0 && i + 1 < argc) {
            *ctl_path = argv[++i];
        } else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            *config_path = argv[++i];
        } else if (strcmp(argv[i], "--socks-port") == 0 && i + 1 < argc) {
            int p = atoi(argv[++i]);
            if (p > 0 && p <= 65535) settings->socks_port = (uint16_t)p;
        } else if (strcmp(argv[i], "--dns-upstream") == 0 && i + 1 < argc) {
            const char *ip = argv[++i];
            struct in_addr a;
            if (inet_pton(AF_INET, ip, &a) == 1)
                snprintf(settings->dns_upstream, sizeof settings->dns_upstream,
                         "%s", ip);
        } else if (strcmp(argv[i], "--dns-local-port") == 0 && i + 1 < argc) {
            int p = atoi(argv[++i]);
            if (p > 0 && p <= 65535) settings->dns_local_port = (uint16_t)p;
        } else if (strcmp(argv[i], "--full-device") == 0) {
            *full_device = 1;
        } else if (strcmp(argv[i], "--socks-public") == 0) {
            settings->socks_public = 1;
        } else {
            int p = atoi(argv[i]);
            if (p > 0 && p <= 65535) settings->socks_port = (uint16_t)p;
        }
    }
}

int main(int argc, char **argv) {
/* early initialization prevents ios 6 teardown from entering uninitialized cleanup */
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);

    if (argc < 2) { usage(argv[0]); return 2; }

    if (strcmp(argv[1], "--managed") == 0) {
        daemon_settings_t settings;
        daemon_settings_defaults(&settings);
        const char *ctl_path = SENKO_CTL_SOCK;
        const char *config_path = "";
        int full_device = 0;
        parse_managed_args(argc, argv, &ctl_path, &config_path, &settings, &full_device);
        /* before the settings are read: a copy that waited for the lock must
           take over with what the previous daemon saved, not with what was on
           disk when it started waiting */
        if (take_instance_lock(ctl_path) == -2) return 1;
        if (config_path[0]) {
            /* two megabytes of servers do not fit the small default stack on
               ios 5, and only the settings are wanted from this first read,
               so the store goes back to the system right after */
            store_t *preload = (store_t *)calloc(1, sizeof *preload);
            if (preload) {
                store_init(preload);
                storefile_load(preload, &settings, config_path);
                free(preload);
            }
            parse_managed_args(argc, argv, &ctl_path, &config_path, &settings, &full_device);
        }
        return run_managed(ctl_path, config_path, full_device, &settings);
    }

    int port = SENKO_DEFAULT_SOCKS_PORT;
    if (argc >= 3) {
        int p = atoi(argv[2]);
        if (p > 0 && p <= 65535) port = p;
    }
    return run_single(argv[1], port);
}
