#ifndef ENGINE_BACKEND_H
#define ENGINE_BACKEND_H

#include "core/config.h"

#include <stddef.h>
#include <sys/types.h>

/* the rust engine (legacyray-engine) as a child process: it speaks the
   profile's protocols and offers them as a socks port on loopback, which the
   loop then uses as its upstream. routing, sniffing and the split rules stay
   in legacyrayd */
typedef struct {
    pid_t child;
    int   port;          /* the engine's socks port on 127.0.0.1 */
    int   active;
    int   threads;
/* restarts after the engine died on its own, within the current window */
    int   restarts;
    long  window_started_ms;
    long  next_try_ms;   /* after a restart that failed */
/* where the binary and its configuration live; NULL takes the installed
   paths. host tests point them at a scratch directory */
    const char *bin;
    const char *config_path;
    const char *pid_path;
} engine_backend_t;

/* 1 when the engine binary is installed */
int engine_backend_available(const engine_backend_t *engine);

/* writes the configuration for the profile (dialled at dial_ip), starts the
   engine and waits until its socks port answers */
int engine_backend_start(engine_backend_t *engine, const vl_server_t *server,
                         const char *dial_ip, char *reason, size_t reason_cap);

void engine_backend_stop(engine_backend_t *engine);

/* 1 while the engine runs. an engine that died is started again with the
   same configuration and port, a few times a minute at most; 0 once it is
   gone for good, and the tunnel with it */
int engine_backend_keep_alive(engine_backend_t *engine);

/* an engine left behind by a daemon that crashed still holds its port and
   its connections; the next daemon ends it before starting its own */
void engine_backend_clear_stale(const engine_backend_t *engine);

#endif
