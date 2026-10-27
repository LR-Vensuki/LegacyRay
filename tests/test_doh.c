#include "doh.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static doh_status_t parse(const char *text, size_t len, size_t *off, size_t *body,
                          int *close_after, int *status) {
    *off = *body = 0;
    *close_after = -1;
    *status = 0;
    return doh_parse_response((const uint8_t *)text, len, off, body, close_after, status);
}

int main(void) {
    static const uint8_t query[] = { 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 1 };
    uint8_t out[512];
    size_t out_len = 0;
    ok("build request",
       doh_build_request("1.1.1.1", query, sizeof query, out, sizeof out, &out_len) == DOH_OK);
    const char *head = "POST /dns-query HTTP/1.1\r\nHost: 1.1.1.1\r\n";
    ok("request line and host", out_len > strlen(head) && memcmp(out, head, strlen(head)) == 0);
    ok("content length and body",
       strstr((const char *)out, "Content-Length: 17\r\n\r\n") != NULL &&
       memcmp(out + out_len - sizeof query, query, sizeof query) == 0);
    ok("request needs room",
       doh_build_request("1.1.1.1", query, sizeof query, out, 100, &out_len) == DOH_ERR_SPACE);

    size_t off, body;
    int close_after, status;
    const char *answer = "HTTP/1.1 200 OK\r\nServer: cloudflare\r\n"
                         "Content-Type: application/dns-message\r\n"
                         "content-length: 5\r\n\r\nABCDE";
    size_t full = strlen(answer);
    ok("whole answer",
       parse(answer, full, &off, &body, &close_after, &status) == DOH_OK &&
       body == 5 && memcmp(answer + off, "ABCDE", 5) == 0 && !close_after && status == 200);
    ok("body still coming",
       parse(answer, full - 2, &off, &body, &close_after, &status) == DOH_NEED_MORE &&
       status == 200);
    ok("headers still coming",
       parse(answer, 30, &off, &body, &close_after, &status) == DOH_NEED_MORE);
    ok("status line still coming",
       parse(answer, 8, &off, &body, &close_after, &status) == DOH_NEED_MORE);

    const char *closing = "HTTP/1.1 200 OK\r\nConnection: Close\r\nContent-Length: 1\r\n\r\nZ";
    ok("connection close",
       parse(closing, strlen(closing), &off, &body, &close_after, &status) == DOH_OK &&
       close_after && body == 1);
    const char *listed = "HTTP/1.1 200 OK\r\nConnection: upgrade, close\r\nContent-Length: 1\r\n\r\nZ";
    ok("close among other tokens",
       parse(listed, strlen(listed), &off, &body, &close_after, &status) == DOH_OK &&
       close_after);
    const char *lookalike = "HTTP/1.1 200 OK\r\nConnection: enclosed\r\nContent-Length: 1\r\n\r\nZ";
    ok("a token that only contains close",
       parse(lookalike, strlen(lookalike), &off, &body, &close_after, &status) == DOH_OK &&
       !close_after);
    const char *old = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    ok("http/1.0 closes",
       parse(old, strlen(old), &off, &body, &close_after, &status) == DOH_OK && close_after);

    const char *refused = "HTTP/1.1 415 Unsupported Media Type\r\nContent-Length: 3\r\n\r\nbad";
    ok("non-200 is an error",
       parse(refused, strlen(refused), &off, &body, &close_after, &status) == DOH_ERR_STATUS &&
       status == 415 && close_after);
    const char *chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nABCDE\r\n0\r\n\r\n";
    ok("chunked is refused",
       parse(chunked, strlen(chunked), &off, &body, &close_after, &status) == DOH_ERR_FORMAT);
    const char *nolength = "HTTP/1.1 200 OK\r\nServer: x\r\n\r\n";
    ok("no length is refused",
       parse(nolength, strlen(nolength), &off, &body, &close_after, &status) == DOH_ERR_FORMAT);
    const char *junk = "SSH-2.0-OpenSSH_9.6\r\n\r\n";
    ok("not http",
       parse(junk, strlen(junk), &off, &body, &close_after, &status) == DOH_ERR_FORMAT);
    const char *two = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nABCDE";
    ok("conflicting lengths",
       parse(two, strlen(two), &off, &body, &close_after, &status) == DOH_ERR_FORMAT);
    char huge[DOH_HEADER_MAX + 16];
    memset(huge, 'x', sizeof huge);
    memcpy(huge, "HTTP/1.1 200 OK\r\nX: ", 20);
    ok("endless headers",
       parse(huge, sizeof huge, &off, &body, &close_after, &status) == DOH_ERR_FORMAT);

    if (failures) {
        fprintf(stderr, "%d doh check(s) failed\n", failures);
        return 1;
    }
    puts("doh tests passed");
    return 0;
}
