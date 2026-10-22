#ifndef CTL_SERVER_H
#define CTL_SERVER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "ctl_engine.h"
#include "settings.h"

#ifdef __cplusplus
extern "C" {
#endif

/* the app keeps a WATCH stream open, holds a connection per ping until the
   answer and, on the ipad, sends half a dozen requests at once at launch. four
   slots closed the surplus on accept, and the app read the empty reply as a
   daemon that is not running */
#define CTL_SERVER_MAX_CLIENTS 16
/* every ping is a thread doing a whole handshake */
#define CTL_SERVER_MAX_PINGS 4
#define CTL_CLIENT_OUT_MAX (1024 * 1024)

typedef int (*ctl_apply_fn)(void *ctx, const ctl_action_t *action);

typedef void (*ctl_persist_fn)(void *ctx, const store_t *store);

typedef struct {
    uint64_t expire;
    uint64_t upload;
    uint64_t download;
    uint64_t total;
    char title[256];
    char description[256];
    char support_url[512];
/* the panel served a device gated placeholder instead of the node list */
    int  gated;
    char gate_reason[256];
/* legacyray */
    char     web_page_url[512];
    uint32_t update_interval_h;
    uint64_t refill_date;
    char     routing[8192];
} ctl_fetch_meta_t;

typedef int (*ctl_fetch_fn)(void *ctx, const char *url,
                            const char *request_header,
                            unsigned char *buf, size_t cap, size_t *len,
                            ctl_fetch_meta_t *meta);

typedef int (*ctl_probe_fn)(void *ctx, const char *host, uint16_t port);
typedef int (*ctl_server_probe_fn)(void *ctx, const vl_server_t *server);

typedef int (*ctl_verify_fn)(void *ctx, char *reason, size_t reason_cap);

/* the backend's own words for the last failure, or NULL */
typedef const char *(*ctl_reason_fn)(void *ctx);

typedef int (*ctl_tunnel_probe_fn)(void *ctx);
typedef int (*ctl_stats_fn)(void *ctx, uint64_t *up, uint64_t *down);

typedef int (*ctl_backup_fn)(void *ctx, int restore, store_t *store);

#define CTL_CHECK_STAGE_MAX 10
#define CTL_CHECK_STAGE_NAME_MAX 48

/* one named step of a check and how long the check had been running when it
   finished. "check failed" names nothing a tester can repeat, and the four
   check modes stop at four different places */
typedef struct {
    char name[CTL_CHECK_STAGE_NAME_MAX];
    int  ms;
    int  ok;
} ctl_check_stage_t;

typedef struct {
    ctl_check_stage_t stages[CTL_CHECK_STAGE_MAX];
    size_t            count;
    long              started_ms;
} ctl_check_trace_t;

/* trace may be NULL; when it is not, it is filled with the stages the check
   walked, in order, whether or not the check succeeded */
typedef int (*ctl_check_fn)(void *ctx, const char *mode,
                            const vl_server_t *server, ctl_check_trace_t *trace,
                            char *reason, size_t reason_cap);

/* the firewall ruleset the kernel is running, written into buf as text.
   returns 0 when there is one to show */
typedef int (*ctl_fwconf_fn)(void *ctx, char *buf, size_t cap, size_t *len);

/* drop one named piece of accumulated state. returns 0 when it was dropped */
typedef int (*ctl_flush_fn)(void *ctx, const char *what,
                            char *reason, size_t reason_cap);

/* render the validated JSON handed to a native Network Extension provider */
typedef int (*ctl_native_config_fn)(void *ctx, const vl_server_t *server,
                                    char *buf, size_t cap, size_t *len);

/* GEO UPDATE / STATUS: fills out with status lines and a final OK / ERR */
typedef int (*ctl_geo_fn)(void *ctx, const char *what, char *out, size_t cap, size_t *len);

/* append DIAG lines the daemon owns; the server adds its own before streaming */
typedef int (*ctl_diag_fn)(void *ctx, char *buf, size_t cap, size_t *len);

typedef struct {
    int   fd; /* connected ui client */
    int   authed;
    char  inbuf[1024]; /* partial control line */
    size_t in_len;
    char  *outbuf;
    size_t out_len;
    size_t out_off;
    uint64_t generation;
/* WATCH lease: STATE and STAT lines are pushed until this moment */
    long  watch_until_ms;
} ctl_client_t;

typedef struct {
    int           listen_fd;
    char          sock_path[108]; /* unix socket path */
    char          token_path[108];
    char          token[40];
/* the socket file this server bound, so it never removes a file another
   daemon made, and puts its own back when something else removed it */
    dev_t         sock_dev;
    ino_t         sock_ino;
    long          paths_checked_ms;
    int           foreign_logged;
    ctl_engine_t  engine;
    ctl_apply_fn  apply;
    ctl_reason_fn reason;
    ctl_persist_fn persist; /* save store changes */
    ctl_fetch_fn  fetch; /* fetch subscriptions */
    ctl_probe_fn  probe; /* probe an idle server */
    ctl_server_probe_fn server_probe; /* probe one server, including its protocol */
    ctl_verify_fn verify; /* verify a new tunnel */
    ctl_tunnel_probe_fn tunnel_probe; /* probe the active tunnel */
    ctl_backup_fn backup;
    ctl_check_fn check;
    ctl_diag_fn  diag;
    ctl_fwconf_fn fwconf;
    ctl_flush_fn  flush;
    ctl_native_config_fn native_config;
    ctl_stats_fn stats;
    ctl_geo_fn   geo;
    uint64_t stat_at_ms;
    int stat_failed;
    void         *apply_ctx;
/* a read only view of the copy the apply hook writes into, so the schedules
   below and the SETTINGS dump never disagree with the daemon */
    const daemon_settings_t *settings;
/* redial schedule with no client behind it. retry_at_ms is 0 when idle */
    long          retry_at_ms;
    int           retry_attempts;
/* last measured latency per server index, -1 when unknown or unreachable.
   failover orders candidates by it, and it is dropped whenever a command can
   move server indexes */
    int           ping_ms[STORE_MAX_SERVERS];
/* default egress seen at the last check, to notice a wifi to cellular move */
    char          egress_iface[32];
    char          egress_ip[16];
    long          egress_check_ms;
/* the routing socket is in the daemon's poll set, so egress checks run when
   the kernel reports a change instead of on a clock. egress_due_ms is the
   settle deadline after the last such report, 0 when nothing is pending */
    int           netwatch_live;
    long          egress_due_ms;
    long          sub_check_ms;
/* earliest retry per subscription after a scheduled refresh failed, so a dead
   panel is not pulled every minute */
    long          sub_retry_at_ms[STORE_MAX_SUBS];
    int           refresh_in_progress;
    int           ping_pipe[2];
    size_t        ping_active;
    uint64_t      client_generation;
    ctl_client_t  clients[CTL_SERVER_MAX_CLIENTS];
/* which client each pollfd after the first two belongs to, for dispatch */
    int           poll_slot[CTL_SERVER_MAX_CLIENTS];
    size_t        poll_n;
} ctl_server_t;

typedef enum {
    CTLS_OK       =  0,
    CTLS_ERR_ARG  = -1,
    CTLS_ERR_BIND = -2,
    CTLS_ERR      = -3,
    CTLS_ERR_AUTH = -4
} ctls_status_t;

ctls_status_t ctl_server_init(ctl_server_t *s, const char *path,
                              ctl_apply_fn apply, void *apply_ctx);

void ctl_server_set_persist(ctl_server_t *s, ctl_persist_fn persist);

void ctl_server_set_fetch(ctl_server_t *s, ctl_fetch_fn fetch);

void ctl_server_set_probe(ctl_server_t *s, ctl_probe_fn probe);

void ctl_server_set_server_probe(ctl_server_t *s, ctl_server_probe_fn probe);

void ctl_server_set_verify(ctl_server_t *s, ctl_verify_fn verify);

void ctl_server_set_tunnel_probe(ctl_server_t *s, ctl_tunnel_probe_fn probe);

void ctl_server_set_backup(ctl_server_t *s, ctl_backup_fn backup);
void ctl_server_set_check(ctl_server_t *s, ctl_check_fn check);

void ctl_server_set_reason(ctl_server_t *s, ctl_reason_fn reason);
void ctl_server_set_stats(ctl_server_t *s, ctl_stats_fn stats);

void ctl_server_set_settings(ctl_server_t *s, const daemon_settings_t *settings);

void ctl_server_set_diag(ctl_server_t *s, ctl_diag_fn diag);

void ctl_server_set_fwconf(ctl_server_t *s, ctl_fwconf_fn fwconf);
void ctl_server_set_flush(ctl_server_t *s, ctl_flush_fn flush);
void ctl_server_set_native_config(ctl_server_t *s, ctl_native_config_fn render);
void ctl_server_set_geo(ctl_server_t *s, ctl_geo_fn geo);

int ctl_server_restore_tunnel(ctl_server_t *s);

/* the data path went down without a DISCONNECT: schedule a redial when the
   settings allow one, or publish the failure */
void ctl_server_tunnel_lost(ctl_server_t *s);

/* run what has no client behind it: redial backoff, egress changes and
   scheduled subscription refreshes */
void ctl_server_tick(ctl_server_t *s);

/* ctl_server_step in halves for the daemon's single poll; see loop_prepare */
#define CTL_SERVER_POLLFD_MAX (2 + CTL_SERVER_MAX_CLIENTS)
struct pollfd;
size_t ctl_server_prepare(ctl_server_t *s, struct pollfd *pfd, size_t cap);
void ctl_server_dispatch(ctl_server_t *s, const struct pollfd *pfd, size_t n);

/* milliseconds until ctl_server_tick or a STAT push has work, -1 for none.
   an idle daemon with no watchers and no schedule sleeps until a socket
   wakes it */
int ctl_server_timeout_ms(ctl_server_t *s);

/* live = 1 when the caller watches the routing socket and will report
   changes through ctl_server_network_changed */
void ctl_server_set_netwatch(ctl_server_t *s, int live);
void ctl_server_network_changed(ctl_server_t *s);

ctls_status_t ctl_server_step(ctl_server_t *s, int timeout_ms);

void ctl_server_broadcast(ctl_server_t *s, const char *line, size_t len);

size_t ctl_server_client_count(const ctl_server_t *s);

/* bind the socket and write the token again if something removed them */
void ctl_server_check_paths(ctl_server_t *s);
void ctl_server_close(ctl_server_t *s);

#ifdef __cplusplus
}
#endif

#endif /* ctl_server_h */
