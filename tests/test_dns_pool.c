/* the dns forwarder's worker pool against a fake socks upstream that answers
   A at once, never answers PTR and hangs up on TXT. the statics are reached by
   building the forwarder into this file */
#include "../daemon/routing_exec.c"

#include <stdio.h>
#include <sys/time.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static long now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000L + tv.tv_usec / 1000;
}

static int read_full(int fd, uint8_t *buf, size_t len) {
    while (len > 0) {
        ssize_t n = read(fd, buf, len);
        if (n <= 0) return -1;
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

static void *upstream_conn(void *arg) {
    int fd = (int)(intptr_t)arg;
    uint8_t buf[600];
    static const uint8_t reply[10] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    if (read_full(fd, buf, 3) != 0 || write(fd, "\x05\x00", 2) != 2 ||
        read_full(fd, buf, 10) != 0 || write(fd, reply, sizeof reply) != sizeof reply)
        goto done;
    for (;;) {
        if (read_full(fd, buf, 2) != 0) break;
        size_t len = ((size_t)buf[0] << 8) | buf[1];
        if (len < 17 || len > sizeof buf - 2 || read_full(fd, buf + 2, len) != 0) break;
        uint16_t type = (uint16_t)((buf[2 + len - 4] << 8) | buf[2 + len - 3]);
        if (type == 16) break;              /* TXT: hang up */
        if (type == 12) {                   /* PTR: never answer */
            while (read(fd, buf, sizeof buf) > 0) {}
            break;
        }
        buf[2 + 2] |= 0x80;                 /* A: the question back, as an empty answer */
        if (write(fd, buf, 2 + len) != (ssize_t)(2 + len)) break;
    }
done:
    close(fd);
    return NULL;
}

static void *upstream_main(void *arg) {
    int listen_fd = (int)(intptr_t)arg;
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) return NULL;
        pthread_t t;
        if (pthread_create(&t, NULL, upstream_conn, (void *)(intptr_t)fd) == 0)
            pthread_detach(t);
        else
            close(fd);
    }
}

static size_t make_query(uint8_t *out, uint16_t id, const char *label, uint16_t type) {
    memset(out, 0, 12);
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = 0x01;
    out[5] = 1;
    size_t pos = 12, n = strlen(label);
    out[pos++] = (uint8_t)n;
    memcpy(out + pos, label, n);
    pos += n;
    memcpy(out + pos, "\x03" "com", 4);
    pos += 4;
    out[pos++] = 0;
    out[pos++] = (uint8_t)(type >> 8);
    out[pos++] = (uint8_t)type;
    out[pos++] = 0;
    out[pos++] = 1;
    return pos;
}

static int udp_socket(struct sockaddr_in *bound) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    socklen_t len = sizeof *bound;
    memset(bound, 0, sizeof *bound);
    bound->sin_family = AF_INET;
    bound->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)bound, sizeof *bound) != 0 ||
        getsockname(fd, (struct sockaddr *)bound, &len) != 0)
        return -1;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    return fd;
}

static int submit(dns_pool_t *pool, uint16_t id, const char *label, uint16_t type,
                  const struct sockaddr_in *client) {
    uint8_t query[64];
    size_t len = make_query(query, id, label, type);
    dns_question_t question;
    if (dns_msg_parse_question(query, len, &question) != DNS_MSG_OK) return -9;
    return dns_submit(pool, &question, RULE_ACTION_PROXY, query, len, client, sizeof *client);
}

/* finish what the workers did and collect the ids that reached the client */
static size_t pump(routing_exec_t *st, dns_pool_t *pool, int send_fd, int client_fd,
                   uint16_t *ids, size_t cap, size_t want, long deadline_ms) {
    dns_said_t said = { NULL, -1 };
    size_t got = 0;
    while (got < want && now_ms() < deadline_ms) {
        dns_finish_jobs(st, pool, send_fd, &said);
        uint8_t buf[512];
        ssize_t n = recv(client_fd, buf, sizeof buf, 0);
        if (n >= 12 && got < cap) {
            ids[got++] = (uint16_t)((buf[0] << 8) | buf[1]);
            continue;
        }
        usleep(5000);
    }
    return got;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in up;
    socklen_t up_len = sizeof up;
    memset(&up, 0, sizeof up);
    up.sin_family = AF_INET;
    up.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr *)&up, sizeof up) != 0 || listen(listen_fd, 64) != 0 ||
        getsockname(listen_fd, (struct sockaddr *)&up, &up_len) != 0) {
        fprintf(stderr, "no listener\n");
        return 1;
    }
    pthread_t upstream;
    pthread_create(&upstream, NULL, upstream_main, (void *)(intptr_t)listen_fd);

    routing_exec_t st;
    memset(&st, 0, sizeof st);
    st.socks_port = ntohs(up.sin_port);
    snprintf(st.dns_upstream, sizeof st.dns_upstream, "127.0.0.1");
    ok("tables", tables_reset() == 0);
    struct sockaddr_in client_addr, send_addr;
    int client_fd = udp_socket(&client_addr);
    int send_fd = udp_socket(&send_addr);
    dns_pool_t *pool = dns_pool_start(&st);
    ok("pool starts", pool != NULL && client_fd >= 0 && send_fd >= 0);
    if (!pool) return 1;
    pool->https_down_until = (uint64_t)-1; /* port 53 only: no https resolver here */

    /* an upstream that hangs up is asked once more, then the job ends */
    uint32_t unanswered = g_dns_unanswered;
    ok("TXT queued", submit(pool, 0x400, "txt", 16, &client_addr) == 0);
    long started = now_ms();
    while (g_dns_unanswered == unanswered && now_ms() - started < 3000) {
        dns_said_t said = { NULL, -1 };
        dns_finish_jobs(&st, pool, send_fd, &said);
        usleep(5000);
    }
    ok("a hang-up ends the job", g_dns_unanswered == unanswered + 1);
    ok("and ends it quickly", now_ms() - started < 1500);

    /* six questions the upstream never answers take at most half the workers */
    for (int i = 0; i < 6; ++i) {
        char label[8];
        snprintf(label, sizeof label, "ptr%d", i);
        submit(pool, (uint16_t)(0x100 + i), label, 12, &client_addr);
    }
    usleep(200000);
    started = now_ms();
    for (int i = 0; i < 5; ++i) {
        char label[8];
        snprintf(label, sizeof label, "a%d", i);
        submit(pool, (uint16_t)(0x200 + i), label, 1, &client_addr);
    }
    uint16_t ids[16];
    size_t got = pump(&st, pool, send_fd, client_fd, ids, 16, 5, started + 3000);
    ok("A and AAAA pass while PTR hangs", got == 5);
    ok("and pass quickly", now_ms() - started < 1500);
    pthread_mutex_lock(&pool->lock);
    size_t slow = 0;
    for (size_t i = 0; i < DNS_JOBS; ++i)
        if (pool->jobs[i].state == DNS_JOB_RUNNING && pool->jobs[i].question.type == 12) slow++;
    pthread_mutex_unlock(&pool->lock);
    ok("PTR holds half the workers", slow == DNS_WORKERS / 2);

    /* a resend joins the question under way and both ids hear back */
    ok("first copy queued", submit(pool, 0x300, "same", 1, &client_addr) == 0);
    ok("resend joins", submit(pool, 0x301, "same", 1, &client_addr) == 0);
    started = now_ms();
    got = pump(&st, pool, send_fd, client_fd, ids, 16, 2, started + 3000);
    ok("both copies answered",
       got == 2 && ((ids[0] == 0x300 && ids[1] == 0x301) || (ids[0] == 0x301 && ids[1] == 0x300)));

    /* stop does not wait out the workers stuck on PTR */
    started = now_ms();
    dns_pool_stop(pool);
    ok("stop is quick", now_ms() - started < 1000);

    close(client_fd);
    close(send_fd);
    if (failures) {
        fprintf(stderr, "%d dns pool check(s) failed\n", failures);
        return 1;
    }
    puts("dns pool tests passed");
    return 0;
}
