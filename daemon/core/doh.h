#ifndef SENKO_DOH_H
#define SENKO_DOH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* dns over https (rfc 8484) on http/1.1: the request that carries one
   wire-format question, and the reading of its answer. the tls under it
   belongs to the caller */

#define DOH_HEADER_MAX 4096

typedef enum {
    DOH_OK = 0,
    DOH_NEED_MORE = 1,
    DOH_ERR_ARG = -1,
    DOH_ERR_SPACE = -2,
    DOH_ERR_STATUS = -3, /* the server answered with something other than 200 */
    DOH_ERR_FORMAT = -4
} doh_status_t;

/* POST /dns-query on a connection that stays open for the next question */
doh_status_t doh_build_request(const char *host, const uint8_t *query,
                               size_t query_len, uint8_t *out, size_t cap,
                               size_t *out_len);

/* the bytes of one response read so far. DOH_OK once the whole body is in:
   it starts at *body_off and runs *body_len bytes. *close_after says the
   server will take no further request on this connection. *http_status is
   set as soon as the status line is in, for the log */
doh_status_t doh_parse_response(const uint8_t *buf, size_t len,
                                size_t *body_off, size_t *body_len,
                                int *close_after, int *http_status);

#ifdef __cplusplus
}
#endif

#endif
