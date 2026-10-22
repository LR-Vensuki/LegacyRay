#ifndef SENKO_WS_PATH_H
#define SENKO_WS_PATH_H

#include <stdio.h>
#include <string.h>

/* "ed=N" in a websocket path is xray's early-data setting for the client,
   not part of the path: xray takes it out of the request, and a server that
   matches the path exactly refuses the upgrade when it is left in. the other
   query parameters stay, in order */
static inline void ws_path_without_early_data(const char *path, char *out, size_t cap) {
    const char *query;
    size_t used;
    if (!out || cap == 0) return;
    if (!path || !path[0]) path = "/";
    query = strchr(path, '?');
    if (!query) {
        snprintf(out, cap, "%s", path);
        return;
    }
    used = (size_t)(query - path);
    if (used >= cap) used = cap - 1;
    memcpy(out, path, used);
    out[used] = '\0';
    for (const char *p = query + 1; *p;) {
        const char *end = strchr(p, '&');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n && strncmp(p, "ed=", 3) != 0 && used + n + 1 < cap) {
            out[used++] = strchr(out, '?') ? '&' : '?';
            memcpy(out + used, p, n);
            used += n;
            out[used] = '\0';
        }
        p += n;
        if (*p == '&') ++p;
    }
    if (!out[0]) snprintf(out, cap, "/"); /* the path was only "?ed=..." */
}

#endif
