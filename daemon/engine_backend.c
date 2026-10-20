#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE

#include "engine_backend.h"
#include "engine_config.h"
#include "../common/senko_paths.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/sysctl.h>
#endif

extern char **environ;

#define ENGINE_BIN SENKO_USR_LIB "/legacyray-engine"
#define ENGINE_CONFIG "/var/run/legacyray-engine.yaml"
#define ENGINE_PID "/var/run/legacyray-engine.pid"
#define ENGINE_CONFIG_MAX (16 * 1024)
/* an a4 needs a moment to map a large binary and parse its configuration */
#define ENGINE_READY_MS 8000
/* a restart reuses a configuration that already worked, so it gets less, and
   a failed one is tried again a second later rather than given up on */
#define ENGINE_RESTART_READY_MS 3000
#define ENGINE_RETRY_MS 1000L
#define ENGINE_RESTARTS_PER_WINDOW 3
#define ENGINE_RESTART_WINDOW_MS 60000L

static const char *bin_of(const engine_backend_t *e) {
    return e && e->bin ? e->bin : ENGINE_BIN;
}

static const char *config_of(const engine_backend_t *e) {
    return e && e->config_path ? e->config_path : ENGINE_CONFIG;
}

static const char *pid_of(const engine_backend_t *e) {
    return e && e->pid_path ? e->pid_path : ENGINE_PID;
}

static void set_reason(char *reason, size_t cap, const char *value) {
    if (reason && cap) snprintf(reason, cap, "%s", value);
}

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + (long)(tv.tv_usec / 1000);
}

int engine_backend_available(const engine_backend_t *e) {
    return access(bin_of(e), X_OK) == 0;
}

/* the profile's secrets are in it: 0600, written whole or not at all */
static int write_config(const char *path, const char *contents) {
    char temporary[512];
    int n = snprintf(temporary, sizeof temporary, "%s.%ld", path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof temporary) return -1;
    (void)unlink(temporary);
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return -1;
    size_t length = strlen(contents);
    size_t offset = 0;
    while (offset < length) {
        ssize_t wrote = write(fd, contents + offset, length - offset);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) {
            close(fd);
            unlink(temporary);
            return -1;
        }
        offset += (size_t)wrote;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(temporary, path) != 0) {
        unlink(temporary);
        return -1;
    }
    return 0;
}

static void write_pid(const engine_backend_t *e, pid_t pid) {
    char text[24];
    int fd = open(pid_of(e), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (fd < 0) return;
    int n = snprintf(text, sizeof text, "%ld\n", (long)pid);
    if (n > 0 && write(fd, text, (size_t)n) != n)
        fprintf(stderr, "legacyrayd: engine pid file not written\n");
    close(fd);
}

/* a port nobody listens on right now. the engine binds it a moment later, and
   start tries once more with another if something took it in between */
static int pick_port(void) {
    struct sockaddr_in a;
    socklen_t len = sizeof a;
    int port = -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) == 0 &&
        getsockname(fd, (struct sockaddr *)&a, &len) == 0)
        port = ntohs(a.sin_port);
    close(fd);
    return port;
}

/* the engine must not inherit the daemon's sockets: a listener it kept would
   outlive the daemon and block the next one from binding */
static void close_on_exec_all(void) {
    long limit = sysconf(_SC_OPEN_MAX);
    if (limit < 0 || limit > 4096) limit = 4096;
    for (int fd = 3; fd < (int)limit; ++fd) {
        int flags = fcntl(fd, F_GETFD, 0);
        if (flags >= 0 && !(flags & FD_CLOEXEC))
            (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

static int spawn_engine(engine_backend_t *e) {
    char threads[16];
    snprintf(threads, sizeof threads, "%d", e->threads > 0 ? e->threads : 1);
    char *argv[] = { (char *)bin_of(e), (char *)"--no-reload", (char *)"-t", threads,
                     (char *)config_of(e), NULL };
    close_on_exec_all();
    if (posix_spawn(&e->child, bin_of(e), NULL, NULL, argv, environ) != 0) {
        e->child = 0;
        return -1;
    }
    write_pid(e, e->child);
    return 0;
}

static void log_exit(int status) {
    if (WIFEXITED(status))
        fprintf(stderr, "legacyrayd: engine exited with status %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(stderr, "legacyrayd: engine killed by signal %d\n", WTERMSIG(status));
}

/* 1 while the child runs; reaps it and forgets the pid once it is gone */
static int child_alive(engine_backend_t *e) {
    int status;
    pid_t waited;
    if (e->child <= 0) return 0;
    while ((waited = waitpid(e->child, &status, WNOHANG)) < 0 && errno == EINTR) {}
    if (waited == 0) return 1;
    if (waited == e->child) log_exit(status);
    e->child = 0;
    return 0;
}

static int port_answers(int port) {
    struct sockaddr_in a;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int ok = connect(fd, (struct sockaddr *)&a, sizeof a) == 0;
    close(fd);
    return ok;
}

static int wait_ready(engine_backend_t *e, long budget_ms) {
    long deadline = now_ms() + budget_ms;
    while (now_ms() < deadline) {
        if (!child_alive(e)) return -1;
        if (port_answers(e->port)) return 0;
        (void)poll(NULL, 0, 50);
    }
    return -1;
}

static void end_child(engine_backend_t *e) {
    int status;
    if (e->child <= 0) return;
    (void)kill(e->child, SIGTERM);
    for (int i = 0; i < 50; ++i) {
        pid_t waited = waitpid(e->child, &status, WNOHANG);
        if (waited == e->child || (waited < 0 && errno == ECHILD)) {
            e->child = 0;
            return;
        }
        (void)poll(NULL, 0, 10);
    }
    (void)kill(e->child, SIGKILL);
    while (waitpid(e->child, &status, 0) < 0 && errno == EINTR) {}
    e->child = 0;
}

static int cpu_threads(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    /* a5 and a6 have two cores, an a4 one; more workers only cost memory */
    if (n < 1) return 1;
    return n > 2 ? 2 : (int)n;
}

int engine_backend_start(engine_backend_t *e, const vl_server_t *server,
                         const char *dial_ip, char *reason, size_t reason_cap) {
    char *config;
    if (!e || !server || !dial_ip) return -1;
    engine_backend_stop(e);
    if (!engine_backend_available(e)) {
        set_reason(reason, reason_cap, "the engine is not installed");
        return -1;
    }
    if (!engine_config_supports(server)) {
        set_reason(reason, reason_cap, "the engine does not carry this profile");
        return -1;
    }
    config = (char *)malloc(ENGINE_CONFIG_MAX);
    if (!config) {
        set_reason(reason, reason_cap, "out of memory for the engine configuration");
        return -1;
    }
    e->threads = cpu_threads();
    for (int attempt = 0; attempt < 2; ++attempt) {
        e->port = pick_port();
        if (e->port <= 0 ||
            engine_config_render(server, dial_ip, e->port, config, ENGINE_CONFIG_MAX) != 0) {
            set_reason(reason, reason_cap, "the profile could not be converted for the engine");
            break;
        }
        if (write_config(config_of(e), config) != 0) {
            set_reason(reason, reason_cap, "the engine configuration could not be written");
            break;
        }
        if (spawn_engine(e) != 0) {
            set_reason(reason, reason_cap, "the engine could not be started");
            break;
        }
        if (wait_ready(e, ENGINE_READY_MS) == 0) {
            free(config);
            e->active = 1;
            e->restarts = 0;
            e->window_started_ms = now_ms();
            fprintf(stderr, "legacyrayd: engine on 127.0.0.1:%d (%d threads)\n",
                    e->port, e->threads);
            return 0;
        }
        set_reason(reason, reason_cap, "the engine did not come up");
        end_child(e);
    }
    free(config);
    engine_backend_stop(e);
    return -1;
}

void engine_backend_stop(engine_backend_t *e) {
    if (!e) return;
    end_child(e);
    if (e->active || e->port) {
        unlink(config_of(e));
        unlink(pid_of(e));
    }
    e->active = 0;
    e->port = 0;
    e->restarts = 0;
    e->next_try_ms = 0;
}

int engine_backend_keep_alive(engine_backend_t *e) {
    if (!e || !e->active) return 0;
    if (child_alive(e)) return 1;
    long now = now_ms();
    if (now < e->next_try_ms) return 1;
    if (now - e->window_started_ms > ENGINE_RESTART_WINDOW_MS) {
        e->window_started_ms = now;
        e->restarts = 0;
    }
    if (e->restarts < ENGINE_RESTARTS_PER_WINDOW) {
        e->restarts++;
        /* same configuration, same port: the loop's upstream stays valid */
        if (spawn_engine(e) == 0 && wait_ready(e, ENGINE_RESTART_READY_MS) == 0) {
            fprintf(stderr, "legacyrayd: engine restarted (%d in this minute)\n",
                    e->restarts);
            return 1;
        }
        end_child(e);
        if (e->restarts < ENGINE_RESTARTS_PER_WINDOW) {
            e->next_try_ms = now_ms() + ENGINE_RETRY_MS;
            return 1;
        }
    }
    fprintf(stderr, "legacyrayd: engine keeps exiting, giving up\n");
    engine_backend_stop(e);
    return 0;
}

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* the short command name the kernel keeps for a process: 16 characters on
   darwin, 15 on linux */
static int process_name(pid_t pid, char *out, size_t cap) {
#ifdef __APPLE__
    struct kinfo_proc info;
    size_t len = sizeof info;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid };
    memset(&info, 0, sizeof info);
    if (sysctl(mib, 4, &info, &len, NULL, 0) != 0 || len == 0) return -1;
    snprintf(out, cap, "%s", info.kp_proc.p_comm);
    return 0;
#else
    char path[64];
    FILE *f;
    snprintf(path, sizeof path, "/proc/%ld/comm", (long)pid);
    f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, (int)cap, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    out[strcspn(out, "\n")] = '\0';
    return 0;
#endif
}

void engine_backend_clear_stale(const engine_backend_t *e) {
    char text[32], name[64];
    long pid;
    int fd = open(pid_of(e), O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return;
    ssize_t n = read(fd, text, sizeof text - 1);
    close(fd);
    unlink(pid_of(e));
    unlink(config_of(e));
    if (n <= 0) return;
    text[n] = '\0';
    pid = strtol(text, NULL, 10);
    if (pid <= 1 || pid == (long)getpid()) return;
    /* the pid may have been reused since; only an engine is ended */
    if (process_name((pid_t)pid, name, sizeof name) != 0 || strlen(name) < 4 ||
        strncmp(base_name(bin_of(e)), name, strlen(name)) != 0)
        return;
    if (kill((pid_t)pid, SIGKILL) == 0)
        fprintf(stderr, "legacyrayd: ended engine %ld left by an earlier daemon\n", pid);
}
