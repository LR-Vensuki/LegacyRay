#include "doh.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

doh_status_t doh_build_request(const char *host, const uint8_t *query,
                               size_t query_len, uint8_t *out, size_t cap,
                               size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!host || !host[0] || !query || query_len == 0 || query_len > 65535 ||
        !out || !out_len)
        return DOH_ERR_ARG;
    int n = snprintf((char *)out, cap,
                     "POST /dns-query HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Accept: application/dns-message\r\n"
                     "Content-Type: application/dns-message\r\n"
                     "Content-Length: %u\r\n"
                     "\r\n",
                     host, (unsigned)query_len);
    if (n < 0 || (size_t)n >= cap || cap - (size_t)n < query_len) return DOH_ERR_SPACE;
    memcpy(out + n, query, query_len);
    *out_len = (size_t)n + query_len;
    return DOH_OK;
}

/* name: matches the header line's field name, case aside */
static int header_is(const char *line, size_t len, const char *name) {
    size_t n = strlen(name);
    if (len <= n || line[n] != ':') return 0;
    for (size_t i = 0; i < n; ++i)
        if (tolower((unsigned char)line[i]) != name[i]) return 0;
    return 1;
}

/* the field value, past the colon and any blanks */
static const char *header_value(const char *line, size_t len, size_t name_len,
                                size_t *value_len) {
    size_t i = name_len + 1;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) ++i;
    size_t end = len;
    while (end > i && (line[end - 1] == ' ' || line[end - 1] == '\t')) --end;
    *value_len = end - i;
    return line + i;
}

static int has_token(const char *value, size_t len, const char *token) {
    size_t n = strlen(token);
    for (size_t i = 0; i + n <= len; ++i) {
        size_t j = 0;
        while (j < n && tolower((unsigned char)value[i + j]) == token[j]) ++j;
        if (j == n) return 1;
    }
    return 0;
}

doh_status_t doh_parse_response(const uint8_t *buf, size_t len,
                                size_t *body_off, size_t *body_len,
                                int *close_after, int *http_status) {
    if (!buf || !body_off || !body_len || !close_after || !http_status)
        return DOH_ERR_ARG;
    const char *text = (const char *)buf;
    size_t scan = len < DOH_HEADER_MAX ? len : DOH_HEADER_MAX;

    size_t line_end = 0;
    while (line_end + 1 < scan && !(text[line_end] == '\r' && text[line_end + 1] == '\n'))
        ++line_end;
    if (line_end + 1 >= scan)
        return len >= DOH_HEADER_MAX ? DOH_ERR_FORMAT : DOH_NEED_MORE;
    if (line_end < 12 || memcmp(text, "HTTP/1.", 7) != 0 || text[8] != ' ' ||
        !isdigit((unsigned char)text[9]) || !isdigit((unsigned char)text[10]) ||
        !isdigit((unsigned char)text[11]))
        return DOH_ERR_FORMAT;
    *http_status = (text[9] - '0') * 100 + (text[10] - '0') * 10 + (text[11] - '0');
    int keep_alive = text[7] == '1';

    size_t header_end = 0;
    for (size_t i = line_end; i + 3 < scan; ++i) {
        if (memcmp(text + i, "\r\n\r\n", 4) == 0) {
            header_end = i + 4;
            break;
        }
    }
    if (!header_end) return len >= DOH_HEADER_MAX ? DOH_ERR_FORMAT : DOH_NEED_MORE;

    long content_length = -1;
    size_t pos = line_end + 2;
    while (pos + 2 <= header_end - 2) {
        size_t end = pos;
        while (end + 1 < header_end && !(text[end] == '\r' && text[end + 1] == '\n')) ++end;
        const char *line = text + pos;
        size_t line_len = end - pos;
        size_t value_len = 0;
        const char *value;
        if (header_is(line, line_len, "content-length")) {
            value = header_value(line, line_len, 14, &value_len);
            if (value_len == 0 || value_len > 5) return DOH_ERR_FORMAT;
            long v = 0;
            for (size_t i = 0; i < value_len; ++i) {
                if (!isdigit((unsigned char)value[i])) return DOH_ERR_FORMAT;
                v = v * 10 + (value[i] - '0');
            }
            if (content_length >= 0 && content_length != v) return DOH_ERR_FORMAT;
            content_length = v;
        } else if (header_is(line, line_len, "connection")) {
            value = header_value(line, line_len, 10, &value_len);
            if (has_token(value, value_len, "close")) keep_alive = 0;
            else if (has_token(value, value_len, "keep-alive")) keep_alive = 1;
        } else if (header_is(line, line_len, "transfer-encoding")) {
/* a dns answer has a known size, and the resolvers say it in content-length */
            return DOH_ERR_FORMAT;
        }
        pos = end + 2;
    }
    *close_after = !keep_alive;
    if (*http_status != 200) {
        *close_after = 1;
        return DOH_ERR_STATUS;
    }
    if (content_length < 0) return DOH_ERR_FORMAT;
    if (len - header_end < (size_t)content_length) return DOH_NEED_MORE;
    *body_off = header_end;
    *body_len = (size_t)content_length;
    return DOH_OK;
}
