#ifndef ENGINE_CONFIG_H
#define ENGINE_CONFIG_H

#include "core/config.h"

#include <stddef.h>

/* the rust engine (legacyray-engine) speaks every protocol of a profile
   itself; legacyrayd hands it the connections through a local socks port.
   1 when the engine can carry this profile, 0 when it stays on the c core */
int engine_config_supports(const vl_server_t *server);

/* the engine's configuration for one profile: a socks listener on
   127.0.0.1:socks_port whose every connection goes out through the server,
   dialled at dial_ip so the engine never resolves the server's name itself
   (once the firewall rules are up, dns goes through the tunnel). the output
   is json, which the engine reads as yaml. it holds the profile's secrets,
   so it goes to a 0600 file, never to argv or a log */
int engine_config_render(const vl_server_t *server, const char *dial_ip,
                         int socks_port, char *out, size_t out_cap);

#endif
