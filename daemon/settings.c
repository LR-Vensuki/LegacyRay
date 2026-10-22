#include "settings.h"
#include <ctype.h>

#include "routing.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

void daemon_settings_defaults(daemon_settings_t *s) {
    if (!s) return;
    memset(s, 0, sizeof *s);
    s->socks_port = SENKO_DEFAULT_SOCKS_PORT;
    s->socks_public = 0;
    s->dns_local_port = SENKO_DEFAULT_DNS_LOCAL_PORT;
    snprintf(s->dns_upstream, sizeof s->dns_upstream, "8.8.8.8");
    s->block_response = DNS_BLOCK_ZERO;
    s->auto_connect = 0;
    /* a tunnel that died with nobody watching used to stay dead until the user
       opened the app, which on a phone is the wrong default */
    s->auto_reconnect = 1;
    s->reconnect_max_attempts = SENKO_DEFAULT_RECONNECT_ATTEMPTS;
    s->sub_refresh_hours = 0;
    s->failover = 0;
    s->force_backend = SENKO_BACKEND_AUTO;
    s->force_pf_mode = SENKO_PF_MODE_AUTO;
    s->sub_ignore_gating = 0;
    s->trace = 0;
    s->rules_enabled = 1;
    s->rules_default = 0;
    s->bypass_lan = 1;
    s->sub_panel_title = 0;
    s->prefer_chacha = 1;
    s->engine_core = 1;
    snprintf(s->xray_version, sizeof s->xray_version, "26.7.28");
    snprintf(s->sub_user_agent, sizeof s->sub_user_agent, "Happ/3.26.1");
    s->kill_switch = 0;
    s->fragment = 0;
    s->fragment_min = 100;
    s->fragment_max = 200;
    s->fragment_delay = 10;
    snprintf(s->geosite_url, sizeof s->geosite_url, "%s", LR_DEFAULT_GEOSITE_URL);
    snprintf(s->geoip_url, sizeof s->geoip_url, "%s", LR_DEFAULT_GEOIP_URL);
}

/* http(s), printable, no spaces; a geoip list url may carry one %s */
static int url_ok(const char *val, size_t len, size_t cap, int allow_country) {
    if (len == 0 || len >= cap) return 0;
    if (!(len > 7 && strncmp(val, "http://", 7) == 0) &&
        !(len > 8 && strncmp(val, "https://", 8) == 0))
        return 0;
    int percents = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)val[i];
        if (c <= 0x20 || c == 0x7f) return 0;
        if (c == '%') {
            if (i + 1 < len && val[i + 1] == 's') { ++percents; ++i; continue; }
            if (i + 2 < len && isxdigit((unsigned char)val[i + 1]) &&
                isxdigit((unsigned char)val[i + 2])) continue;
            return 0;
        }
    }
    return percents == 0 || (allow_country && percents == 1);
}

/* x.y.z with every part 0..255, the shape the reality session id carries */
static int version_ok(const char *val, size_t len) {
    unsigned parts = 0, cur = 0;
    int digits = 0;
    if (len == 0 || len >= 16) return 0;
    for (size_t i = 0; i < len; ++i) {
        if (val[i] >= '0' && val[i] <= '9') {
            cur = cur * 10u + (unsigned)(val[i] - '0');
            if (cur > 255u || ++digits > 3) return 0;
        } else if (val[i] == '.' && digits) {
            ++parts;
            cur = 0;
            digits = 0;
        } else {
            return 0;
        }
    }
    return digits && parts == 2;
}

const char *daemon_settings_backend_name(senko_backend_force_t forced) {
    switch (forced) {
        case SENKO_BACKEND_GO:        return "go";
        case SENKO_BACKEND_C:         return "c";
        case SENKO_BACKEND_APP_PROXY: return "app_proxy";
        case SENKO_BACKEND_AUTO:      break;
    }
    return "auto";
}

static int parse_uint16(const char *s, const char *end, uint16_t *out) {
    unsigned long v = 0;
    int any = 0;
    for (; s < end; ++s) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10ul + (unsigned long)(*s - '0');
        any = 1;
        if (v > 65535ul) return -1;
    }
    if (!any) return -1;
    *out = (uint16_t)v;
    return 0;
}

static int parse_bool01(const char *s, const char *end, int *out) {
    if ((size_t)(end - s) == 1 && (*s == '0' || *s == '1')) {
        *out = (*s == '1');
        return 0;
    }
    return -1;
}

static int parse_bounded_int(const char *s, const char *end, int lo, int hi, int *out) {
    long v = 0;
    int any = 0;
    for (; s < end; ++s) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s - '0');
        any = 1;
        if (v > (long)hi) return -1;
    }
    if (!any || v < (long)lo) return -1;
    *out = (int)v;
    return 0;
}

static int ipv4_ok(const char *s, size_t len) {
    char tmp[SETTINGS_DNS_UPSTREAM_MAX];
    if (len == 0 || len >= sizeof tmp) return 0;
    memcpy(tmp, s, len);
    tmp[len] = '\0';
    struct in_addr a;
    return inet_pton(AF_INET, tmp, &a) == 1;
}

static int key_is(const char *key, size_t key_len, const char *name) {
    size_t n = strlen(name);
    return key_len == n && memcmp(key, name, n) == 0;
}

settings_status_t daemon_settings_set(daemon_settings_t *s,
                                      const char *key, size_t key_len,
                                      const char *val, size_t val_len) {
    if (!s || !key || !val || key_len == 0) return SETTINGS_ERR_KEY;
    const char *ve = val + val_len;

    if (key_is(key, key_len, "socks_port")) {
        uint16_t p;
        if (parse_uint16(val, ve, &p) != 0 || p == 0) return SETTINGS_ERR_VALUE;
        s->socks_port = p;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "socks_public")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->socks_public = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "dns_local_port")) {
        uint16_t p;
        if (parse_uint16(val, ve, &p) != 0 || p == 0) return SETTINGS_ERR_VALUE;
        s->dns_local_port = p;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "dns_upstream")) {
        if (!ipv4_ok(val, val_len)) return SETTINGS_ERR_VALUE;
        memcpy(s->dns_upstream, val, val_len);
        s->dns_upstream[val_len] = '\0';
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "block_response")) {
        if (val_len == 4 && memcmp(val, "zero", 4) == 0)
            s->block_response = DNS_BLOCK_ZERO;
        else if (val_len == 8 && memcmp(val, "nxdomain", 8) == 0)
            s->block_response = DNS_BLOCK_NXDOMAIN;
        else if (val_len == 7 && memcmp(val, "refused", 7) == 0)
            s->block_response = DNS_BLOCK_REFUSED;
        else
            return SETTINGS_ERR_VALUE;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "auto_connect")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->auto_connect = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "auto_reconnect")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->auto_reconnect = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "reconnect_max_attempts")) {
        int v;
        if (parse_bounded_int(val, ve, 0, 100, &v) != 0) return SETTINGS_ERR_VALUE;
        s->reconnect_max_attempts = v;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "sub_refresh_hours")) {
        int v;
        /* -1 is off; 0 follows the provider's own interval. a week is the
           longest schedule a panel expiry makes any sense at */
        if (ve - val == 2 && val[0] == '-' && val[1] == '1') v = -1;
        else if (parse_bounded_int(val, ve, 0, 168, &v) != 0) return SETTINGS_ERR_VALUE;
        s->sub_refresh_hours = v;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "failover")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->failover = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "force_backend")) {
        if (val_len == 4 && memcmp(val, "auto", 4) == 0)
            s->force_backend = SENKO_BACKEND_AUTO;
        else if (val_len == 2 && memcmp(val, "go", 2) == 0)
            s->force_backend = SENKO_BACKEND_GO;
        else if (val_len == 1 && val[0] == 'c')
            s->force_backend = SENKO_BACKEND_C;
        else if (val_len == 9 && memcmp(val, "app_proxy", 9) == 0)
            s->force_backend = SENKO_BACKEND_APP_PROXY;
        else
            return SETTINGS_ERR_VALUE;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "force_pf_mode")) {
        int v;
        if (val_len == 4 && memcmp(val, "auto", 4) == 0) {
            s->force_pf_mode = SENKO_PF_MODE_AUTO;
            return SETTINGS_OK;
        }
        if (parse_bounded_int(val, ve, 0, ROUTING_PF_MODE_COUNT - 1, &v) != 0)
            return SETTINGS_ERR_VALUE;
        s->force_pf_mode = v;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "sub_ignore_gating")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->sub_ignore_gating = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "trace")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->trace = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "rules_enabled")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->rules_enabled = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "rules_default")) {
        if (val_len == 5 && memcmp(val, "proxy", 5) == 0) s->rules_default = 0;
        else if (val_len == 6 && memcmp(val, "direct", 6) == 0) s->rules_default = 1;
        else return SETTINGS_ERR_VALUE;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "bypass_lan")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->bypass_lan = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "prefer_chacha")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->prefer_chacha = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "engine_core")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->engine_core = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "sub_panel_title")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->sub_panel_title = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "xray_version")) {
        if (!version_ok(val, val_len)) return SETTINGS_ERR_VALUE;
        memcpy(s->xray_version, val, val_len);
        s->xray_version[val_len] = '\0';
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "kill_switch")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->kill_switch = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "fragment")) {
        int b;
        if (parse_bool01(val, ve, &b) != 0) return SETTINGS_ERR_VALUE;
        s->fragment = b;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "fragment_size")) {
        /* "10-30" or a single "20" */
        const char *dash = memchr(val, '-', val_len);
        int lo, hi;
        if (dash) {
            if (parse_bounded_int(val, dash, 1, 1000, &lo) != 0 ||
                parse_bounded_int(dash + 1, ve, 1, 1000, &hi) != 0 || hi < lo)
                return SETTINGS_ERR_VALUE;
        } else {
            if (parse_bounded_int(val, ve, 1, 1000, &lo) != 0) return SETTINGS_ERR_VALUE;
            hi = lo;
        }
        s->fragment_min = lo;
        s->fragment_max = hi;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "fragment_delay")) {
        int v;
        if (parse_bounded_int(val, ve, 0, 500, &v) != 0) return SETTINGS_ERR_VALUE;
        s->fragment_delay = v;
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "geosite_url")) {
        if (!url_ok(val, val_len, sizeof s->geosite_url, 0)) return SETTINGS_ERR_VALUE;
        memcpy(s->geosite_url, val, val_len);
        s->geosite_url[val_len] = '\0';
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "geoip_url")) {
        if (!url_ok(val, val_len, sizeof s->geoip_url, 1)) return SETTINGS_ERR_VALUE;
        memcpy(s->geoip_url, val, val_len);
        s->geoip_url[val_len] = '\0';
        return SETTINGS_OK;
    }
    if (key_is(key, key_len, "sub_user_agent")) {
        /* spaces are fine inside a user agent; the SET line keeps everything
           after the key as the value */
        if (val_len == 0 || val_len >= sizeof s->sub_user_agent) return SETTINGS_ERR_VALUE;
        for (size_t i = 0; i < val_len; ++i)
            if ((unsigned char)val[i] < 0x20 || val[i] == 0x7f) return SETTINGS_ERR_VALUE;
        memcpy(s->sub_user_agent, val, val_len);
        s->sub_user_agent[val_len] = '\0';
        return SETTINGS_OK;
    }
    return SETTINGS_ERR_KEY;
}

/* a config written by a newer build carries keys this one has no field for, and
   dropping the whole file over one of them would lose every server in it */
int daemon_settings_apply_line(daemon_settings_t *s, const char *line, size_t len) {
    if (!s || !line || len < 5 || memcmp(line, "SET ", 4) != 0) return 0;

    const char *rest = line + 4;
    const char *sp = memchr(rest, ' ', (size_t)(line + len - rest));
    if (!sp) return 1;

    size_t key_len = (size_t)(sp - rest);
    const char *val = sp + 1;
    size_t val_len = (size_t)(line + len - val);
    while (val_len > 0 && (val[val_len - 1] == '\n' || val[val_len - 1] == '\r'
                           || val[val_len - 1] == ' '))
        val_len--;

    (void)daemon_settings_set(s, rest, key_len, val, val_len);
    return 1;
}

void daemon_settings_apply_buf(daemon_settings_t *s, const char *buf, size_t len) {
    if (!s || !buf) return;
    const char *p = buf;
    const char *end = buf + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *le = nl ? nl : end;
        daemon_settings_apply_line(s, p, (size_t)(le - p));
        if (!nl) break;
        p = nl + 1;
    }
}

int daemon_settings_serialize(const daemon_settings_t *s, char *buf, size_t cap,
                              size_t *out_len) {
    if (!s || !buf) return -1;
    size_t off = 0;
    int n;

#define SETTINGS_EMIT(fmt, value)                                     \
    do {                                                              \
        n = snprintf(buf + off, cap - off, fmt, value);               \
        if (n < 0 || (size_t)n >= cap - off) return -1;               \
        off += (size_t)n;                                             \
    } while (0)

    SETTINGS_EMIT("SET socks_port %u\n", (unsigned)s->socks_port);
    SETTINGS_EMIT("SET socks_public %d\n", s->socks_public ? 1 : 0);
    SETTINGS_EMIT("SET dns_upstream %s\n", s->dns_upstream);
    SETTINGS_EMIT("SET dns_local_port %u\n", (unsigned)s->dns_local_port);
    SETTINGS_EMIT("SET block_response %s\n",
                  s->block_response == DNS_BLOCK_NXDOMAIN ? "nxdomain" :
                  s->block_response == DNS_BLOCK_REFUSED ? "refused" : "zero");
    SETTINGS_EMIT("SET auto_connect %d\n", s->auto_connect ? 1 : 0);
    SETTINGS_EMIT("SET auto_reconnect %d\n", s->auto_reconnect ? 1 : 0);
    SETTINGS_EMIT("SET reconnect_max_attempts %d\n", s->reconnect_max_attempts);
    SETTINGS_EMIT("SET sub_refresh_hours %d\n", s->sub_refresh_hours);
    SETTINGS_EMIT("SET failover %d\n", s->failover ? 1 : 0);
    SETTINGS_EMIT("SET force_backend %s\n",
                  daemon_settings_backend_name(s->force_backend));
    if (s->force_pf_mode == SENKO_PF_MODE_AUTO)
        SETTINGS_EMIT("SET force_pf_mode %s\n", "auto");
    else
        SETTINGS_EMIT("SET force_pf_mode %d\n", s->force_pf_mode);
    SETTINGS_EMIT("SET sub_ignore_gating %d\n", s->sub_ignore_gating ? 1 : 0);
    SETTINGS_EMIT("SET trace %d\n", s->trace ? 1 : 0);
    SETTINGS_EMIT("SET rules_enabled %d\n", s->rules_enabled ? 1 : 0);
    SETTINGS_EMIT("SET rules_default %s\n", s->rules_default ? "direct" : "proxy");
    SETTINGS_EMIT("SET bypass_lan %d\n", s->bypass_lan ? 1 : 0);
    SETTINGS_EMIT("SET sub_panel_title %d\n", s->sub_panel_title ? 1 : 0);
    SETTINGS_EMIT("SET prefer_chacha %d\n", s->prefer_chacha ? 1 : 0);
    SETTINGS_EMIT("SET engine_core %d\n", s->engine_core ? 1 : 0);
    SETTINGS_EMIT("SET xray_version %s\n", s->xray_version);
    SETTINGS_EMIT("SET sub_user_agent %s\n", s->sub_user_agent);
    SETTINGS_EMIT("SET kill_switch %d\n", s->kill_switch ? 1 : 0);
    SETTINGS_EMIT("SET fragment %d\n", s->fragment ? 1 : 0);
    char range[24];
    snprintf(range, sizeof range, "%d-%d", s->fragment_min, s->fragment_max);
    SETTINGS_EMIT("SET fragment_size %s\n", range);
    SETTINGS_EMIT("SET fragment_delay %d\n", s->fragment_delay);
    SETTINGS_EMIT("SET geosite_url %s\n", s->geosite_url);
    SETTINGS_EMIT("SET geoip_url %s\n", s->geoip_url);

#undef SETTINGS_EMIT

    if (out_len) *out_len = off;
    return 0;
}
