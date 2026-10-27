#import "LRDaemonClient.h"
#include "senko_paths.h"
#include "b64.h"
#include "control.h"

#import <sys/socket.h>
#import <sys/un.h>
#import <sys/wait.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <errno.h>
#import <spawn.h>
#import <stdio.h>

extern char **environ;

static NSString *LRKickPath(void) {
    static const char *paths[] = { "/usr/bin/legacyray-kick", "/bin/legacyray-kick", NULL };
    for (NSUInteger i = 0; paths[i]; ++i)
        if (access(paths[i], X_OK) == 0) return [NSString stringWithUTF8String:paths[i]];
    return @"/usr/bin/legacyray-kick";
}

/* a CONNECT reply streams "STATE connecting" before its final state, so the
   answer is the first state that is not "connecting" (the same line
   reply_tunnel stops reading at). taking the first line made every connect
   look stuck: the app said "timed out" and tore down a tunnel that was up */
NSString *LRStateFromReply(NSString *reply, long *uptime) {
    if (uptime) *uptime = 0;
    BOOL seen = NO;
    ctl_state_t found = CTL_STATE_IDLE;
    for (NSString *line in [reply componentsSeparatedByString:@"\n"]) {
        NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
        ctl_state_t state;
        long age;
        if (ctl_parse_state([data bytes], [data length], &state, &age) != CTL_OK)
            continue;
        seen = YES;
        found = state;
        if (uptime) *uptime = age;
        if (state != CTL_STATE_CONNECTING) break;
    }
    return seen ? [NSString stringWithUTF8String:ctl_state_name(found)] : nil;
}

NSString *LRErrorFromReply(NSString *reply) {
    for (NSString *line in [reply componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:@"ERR "]) return LRTrim([line substringFromIndex:4]);
    }
    return nil;
}

BOOL LRReplyIsOK(NSString *reply) {
    for (NSString *line in [reply componentsSeparatedByString:@"\n"]) {
        if ([line hasPrefix:@"OK"]) return YES;
    }
    return NO;
}

/* the reply of each verb ends on a different record; streaming records that
   come before the end (and events the daemon pushes into the middle) must not
   end the read early */
typedef int (*LRReplyDoneFn)(const char *buf, size_t len);

static int LRLineStarts(const char *ln, size_t llen, const char *prefix) {
    size_t n = strlen(prefix);
    return llen >= n && memcmp(ln, prefix, n) == 0;
}

static int reply_generic(const char *buf, size_t len) {
    size_t start = 0;
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != '\n') continue;
        size_t llen = i - start;
        const char *ln = buf + start;
        if (llen > 0) {
            int stream = LRLineStarts(ln, llen, "STAT ") || LRLineStarts(ln, llen, "SET ") ||
                LRLineStarts(ln, llen, "RULE ") || LRLineStarts(ln, llen, "DIAG ") ||
                LRLineStarts(ln, llen, "SRV ") || LRLineStarts(ln, llen, "SUB") ||
                LRLineStarts(ln, llen, "SECTION ") || LRLineStarts(ln, llen, "FDATA ") ||
                LRLineStarts(ln, llen, "STAGE ") || LRLineStarts(ln, llen, "FWLINE ");
            if (!stream) return 1;
        }
        start = i + 1;
    }
    return 0;
}

static int reply_until(const char *buf, size_t len, const char *terminal) {
    size_t start = 0;
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != '\n') continue;
        size_t llen = i - start;
        const char *ln = buf + start;
        if (LRLineStarts(ln, llen, terminal) || LRLineStarts(ln, llen, "ERR ")) return 1;
        start = i + 1;
    }
    return 0;
}

static int reply_list(const char *b, size_t l) { return reply_until(b, l, "LISTEND "); }
static int reply_rules(const char *b, size_t l) { return reply_until(b, l, "RULEEND "); }
static int reply_diag(const char *b, size_t l) { return reply_until(b, l, "DIAGEND"); }
static int reply_blob(const char *b, size_t l) { return reply_until(b, l, "FDEND "); }
static int reply_settings(const char *b, size_t l) { return reply_until(b, l, "SETEND"); }
static int reply_fw(const char *b, size_t l) { return reply_until(b, l, "FWEND"); }
static int reply_check(const char *b, size_t l) { return reply_until(b, l, "PONG "); }

static int reply_tunnel(const char *buf, size_t len) {
    size_t start = 0;
    int terminal = 0;
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != '\n') continue;
        size_t llen = i - start;
        const char *ln = buf + start;
        if (LRLineStarts(ln, llen, "ERR ")) return 1;
        if (LRLineStarts(ln, llen, "STATE ")) {
            const char *st = ln + 6;
            size_t slen = llen - 6;
            if (!(slen >= 10 && memcmp(st, "connecting", 10) == 0))
                terminal = 1;
        }
        start = i + 1;
    }
    return terminal;
}

static LRReplyDoneFn LRDoneFnForCommand(NSString *cmd) {
    if ([cmd hasPrefix:@"CONNECT "] || [cmd hasPrefix:@"DISCONNECT"]) return reply_tunnel;
    if ([cmd hasPrefix:@"LIST"]) return reply_list;
    if ([cmd hasPrefix:@"RULES"]) return reply_rules;
    if ([cmd hasPrefix:@"DIAG"]) return reply_diag;
    if ([cmd hasPrefix:@"SETTINGS"]) return reply_settings;
    if ([cmd hasPrefix:@"FWCONF"]) return reply_fw;
    if ([cmd hasPrefix:@"LOGS"] || [cmd hasPrefix:@"FETCH "]) return reply_blob;
    if ([cmd hasPrefix:@"CHECK "] || [cmd hasPrefix:@"PING "]) return reply_check;
    return reply_generic;
}

static void LRSetReadTimeout(int fd, int ms) {
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

static int LRWriteAll(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

@implementation LRDaemonClient

+ (LRDaemonClient *)shared {
    static LRDaemonClient *client = nil;
    if (!client) client = [[LRDaemonClient alloc] initWithSocketPath:LR_DAEMON_SOCKET];
    return client;
}

- (id)initWithSocketPath:(NSString *)path {
    if ((self = [super init])) _socketPath = [path copy];
    return self;
}

- (void)dealloc {
    [_socketPath release];
    [_ensureWaiters release];
    [super dealloc];
}

/* the daemon writes a token next to its socket; a client that cannot read it
   is not allowed to drive the tunnel */
- (NSString *)tokenPath {
    if ([_socketPath hasSuffix:@".sock"])
        return [[_socketPath substringToIndex:[_socketPath length] - 5]
                stringByAppendingString:@".token"];
    return [_socketPath stringByAppendingString:@".token"];
}

- (BOOL)authenticate:(int)fd {
    NSString *token = LRTrim([NSString stringWithContentsOfFile:[self tokenPath]
                                                       encoding:NSUTF8StringEncoding
                                                          error:NULL]);
    if (!token) return YES;
    char line[128];
    int n = snprintf(line, sizeof line, "AUTH %s\n", [token UTF8String]);
    if (n <= 0 || (size_t)n >= sizeof line || LRWriteAll(fd, line, (size_t)n) != 0) return NO;
    LRSetReadTimeout(fd, 1500);
    char buf[128];
    size_t total = 0;
    while (total + 1 < sizeof buf) {
        ssize_t r = read(fd, buf + total, sizeof buf - 1 - total);
        if (r <= 0) break;
        total += (size_t)r;
        if (memchr(buf, '\n', total)) break;
    }
    return total >= 2 && memcmp(buf, "OK", 2) == 0;
}

- (int)openControlSocket {
    const char *path = [_socketPath fileSystemRepresentation];
    if (!path) return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0 || ![self authenticate:fd]) {
        close(fd);
        return -1;
    }
    return fd;
}

- (NSString *)blockingSend:(NSString *)cmd timeoutMs:(int)timeoutMs {
    int fd = [self openControlSocket];
    if (fd < 0) return nil;
    NSString *line = [cmd hasSuffix:@"\n"] ? cmd : [cmd stringByAppendingString:@"\n"];
    NSData *out = [line dataUsingEncoding:NSUTF8StringEncoding];
    if (LRWriteAll(fd, [out bytes], [out length]) != 0) {
        close(fd);
        return nil;
    }
    LRReplyDoneFn done = LRDoneFnForCommand(cmd);
    NSMutableData *acc = [NSMutableData data];
    char buf[4096];
    BOOL finished = NO, closed = NO;
    LRSetReadTimeout(fd, timeoutMs > 0 ? timeoutMs : 2000);
    for (;;) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r > 0) {
            [acc appendBytes:buf length:(NSUInteger)r];
            if (done([acc bytes], [acc length])) {
                finished = YES;
                break;
            }
            continue;
        }
        if (r < 0 && errno == EINTR) continue;
        closed = r == 0;
        break;
    }
    close(fd);
    if (![acc length]) return nil;
    /* a tunnel verb cut off before its final state either lost the daemon
       (it closed the socket) or ran out of time, and the two need different
       words for the user */
    if (!finished && done == reply_tunnel) {
        const char *mark = closed ? "\n" LR_REPLY_CLOSED "\n" : "\n" LR_REPLY_TIMEOUT "\n";
        [acc appendBytes:mark length:strlen(mark)];
    }
    NSString *s = [[[NSString alloc] initWithData:acc encoding:NSUTF8StringEncoding] autorelease];
    if (!s) s = [[[NSString alloc] initWithData:acc encoding:NSISOLatin1StringEncoding] autorelease];
    return s;
}

- (void)sendCommand:(NSString *)cmd reply:(void (^)(NSString *))done {
    [self sendCommand:cmd timeoutMs:3000 reply:done];
}

- (void)sendCommand:(NSString *)cmd timeoutMs:(int)timeoutMs reply:(void (^)(NSString *))done {
    NSString *command = [[cmd copy] autorelease];
    void (^callback)(NSString *) = [[done copy] autorelease];
    [self retain];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
        NSString *reply = [[self blockingSend:command timeoutMs:timeoutMs] retain];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSMutableString *clean = reply ? [NSMutableString string] : nil;
            BOOL sawStat = NO;
            for (NSString *line in [reply componentsSeparatedByString:@"\n"]) {
                if ([line hasPrefix:@"STAT "]) {
                    uint64_t up = 0, down = 0;
                    NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
                    if (ctl_parse_stat([data bytes], [data length], &up, &down) == CTL_OK) {
                        _trafficUp = up;
                        _trafficDown = down;
                        sawStat = YES;
                    }
                } else if ([line length]) {
                    [clean appendFormat:@"%@\n", line];
                }
            }
            if ([command isEqualToString:@"STATUS"]) _trafficKnown = sawStat;
            if (callback) callback(clean);
            [reply release];
            [self release];
        });
        [pool drain];
    });
}

#pragma mark daemon lifecycle

- (void)probeDaemon:(void (^)(BOOL))done {
    void (^callback)(BOOL) = [[done copy] autorelease];
    [self sendCommand:@"STATUS" timeoutMs:1500 reply:^(NSString *reply) {
        if (callback) callback(LRStateFromReply(reply, NULL) != nil);
    }];
}

/* the helper leaves its reason in a log the app can read when it fails */
static NSString *LRKickLogTail(void) {
    NSArray *paths = [NSArray arrayWithObjects:@"/var/log/legacyray-kick.log",
                      @(SENKO_CRASH_DIR "/kick.log"), nil];
    NSString *best = nil;
    NSDate *bestDate = nil;
    for (NSString *p in paths) {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:p error:NULL];
        NSDate *d = [attrs objectForKey:NSFileModificationDate];
        if (d && (!bestDate || [d compare:bestDate] == NSOrderedDescending)) {
            best = p;
            bestDate = d;
        }
    }
    NSData *blob = best ? [NSData dataWithContentsOfFile:best] : nil;
    if (![blob length]) return nil;
    NSUInteger want = MIN([blob length], (NSUInteger)4096);
    NSString *text = [[[NSString alloc] initWithData:
                       [blob subdataWithRange:NSMakeRange([blob length] - want, want)]
                                            encoding:NSUTF8StringEncoding] autorelease];
    NSArray *lines = [text componentsSeparatedByString:@"\n"];
    for (NSInteger i = (NSInteger)[lines count] - 1; i >= 0; --i) {
        NSString *line = LRTrim([lines objectAtIndex:i]);
        if (!line) continue;
        if ([line hasPrefix:@"legacyray-kick: "]) line = [line substringFromIndex:16];
        return line;
    }
    return nil;
}

static NSString *LRKickFailureText(int status, pid_t reaped) {
    NSString *tail = LRKickLogTail();
    if (reaped <= 0) return @"legacyray-kick could not be waited for";
    if (WIFSIGNALED(status)) {
        if (!tail)
            return [NSString stringWithFormat:@"legacyray-kick was killed (signal %d) before it "
                    "logged anything: this jailbreak did not let it run as root", WTERMSIG(status)];
        return [NSString stringWithFormat:@"legacyray-kick was killed (signal %d): %@",
                WTERMSIG(status), tail];
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    switch (code) {
        case 1: return tail ? tail : @"legacyray-kick is not setuid root: reinstall the package";
        case 2: return @"legacyrayd is missing: reinstall the package";
        case 3: return @"another daemon start is still running";
        case 5: return @"legacyrayd did not open its control socket";
        default: break;
    }
    return tail ? [NSString stringWithFormat:@"daemon start failed (%d): %@", code, tail]
                : [NSString stringWithFormat:@"daemon start failed (%d)", code];
}

- (void)kickDaemon:(void (^)(BOOL, NSString *))done {
    void (^callback)(BOOL, NSString *) = [[done copy] autorelease];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
        const char *path = [LRKickPath() fileSystemRepresentation];
        BOOL ok = NO;
        NSString *detail = nil;
        if (access(path, X_OK) != 0) {
            detail = @"legacyray-kick is missing: reinstall the package";
        } else {
            for (int attempt = 0; attempt < 3 && !ok; ++attempt) {
                pid_t pid = 0;
                char *argv[] = { (char *)path, NULL };
                int rc = posix_spawn(&pid, path, NULL, NULL, argv, environ);
                if (rc != 0) {
                    detail = [NSString stringWithFormat:@"cannot start legacyray-kick (%s)",
                              strerror(rc)];
                    usleep(250000);
                    continue;
                }
                int st = 0;
                pid_t waited;
                do { waited = waitpid(pid, &st, 0); } while (waited < 0 && errno == EINTR);
                if (waited > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0) {
                    ok = YES;
                    detail = @"daemon started";
                } else {
                    detail = LRKickFailureText(st, waited);
                    break;
                }
            }
        }
        [detail retain];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (callback) callback(ok, detail);
            [detail release];
        });
        [pool drain];
    });
}

- (void)finishEnsure:(BOOL)up detail:(NSString *)detail {
    NSArray *waiters = [_ensureWaiters autorelease];
    _ensureWaiters = nil;
    for (id waiter in waiters) {
        if (waiter == [NSNull null]) continue;
        ((void (^)(BOOL, NSString *))waiter)(up, detail);
    }
}

/* every screen that finds the daemon silent asks at once, and each ask started
   its own legacyray-kick that only queued behind the first one's lock. one
   check runs at a time and every caller gets its answer */
- (void)ensureDaemon:(void (^)(BOOL, NSString *))done {
    BOOL running = _ensureWaiters != nil;
    if (!running) _ensureWaiters = [[NSMutableArray alloc] init];
    [_ensureWaiters addObject:done ? [[done copy] autorelease] : (id)[NSNull null]];
    if (running) return;
    [self probeDaemon:^(BOOL up) {
        if (up) {
            [self finishEnsure:YES detail:nil];
            return;
        }
        [self kickDaemon:^(BOOL kicked, NSString *detail) {
            NSString *why = [[detail copy] autorelease];
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
                BOOL up2 = NO;
                for (int i = 0; i < 24 && !up2; ++i) {
                    NSString *r = [self blockingSend:@"STATUS" timeoutMs:800];
                    if (LRStateFromReply(r, NULL)) up2 = YES;
                    else usleep(250000);
                }
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self finishEnsure:up2
                                detail:(up2 || why) ? why : @"daemon still offline"];
                });
                [pool drain];
            });
        }];
    }];
}

#pragma mark catalog

static BOOL LRTokenIsProto(NSString *s) {
    static NSSet *set = nil;
    if (!set) set = [[NSSet alloc] initWithObjects:@"vless", @"vmess", @"socks5", @"http", @"https",
                     @"trojan", @"shadowsocks", @"ss", @"hysteria2", nil];
    return [set containsObject:s];
}

static BOOL LRTokenIsNet(NSString *s) {
    static NSSet *set = nil;
    if (!set) set = [[NSSet alloc] initWithObjects:@"tcp", @"ws", @"grpc", @"http",
                     @"xhttp", @"quic", nil];
    return [set containsObject:s];
}

static BOOL LRTokenIsSecurity(NSString *s) {
    return [s isEqualToString:@"none"] || [s isEqualToString:@"tls"] ||
           [s isEqualToString:@"reality"] || [s isEqualToString:@"unknown"] ||
           [s hasPrefix:@"aes-"] || [s hasPrefix:@"chacha20"] || [s isEqualToString:@"aead"] ||
           [s hasPrefix:@"2022-"];
}

static LRServer *LRParseSRV(NSString *line) {
    NSArray *t = [line componentsSeparatedByString:@" "];
    if ([t count] < 7) return nil;
    LRServer *sv = [[[LRServer alloc] init] autorelease];
    sv.index = [[t objectAtIndex:1] intValue];
    sv.selected = [[t objectAtIndex:2] intValue] != 0;
    sv.group = [[t objectAtIndex:3] intValue];
    NSUInteger remarkStart = 7;
    BOOL newLayout = [t count] >= 10 && LRTokenIsProto([t objectAtIndex:4]) &&
        LRTokenIsNet([t objectAtIndex:5]) && LRTokenIsSecurity([t objectAtIndex:6]) &&
        ([[t objectAtIndex:7] isEqualToString:@"0"] || [[t objectAtIndex:7] isEqualToString:@"1"]) &&
        [[t objectAtIndex:9] intValue] > 0;
    if (newLayout) {
        sv.proto = [t objectAtIndex:4];
        sv.net = [t objectAtIndex:5];
        sv.security = [t objectAtIndex:6];
        sv.supported = [[t objectAtIndex:7] intValue] != 0;
        sv.host = [t objectAtIndex:8];
        sv.port = [[t objectAtIndex:9] intValue];
        remarkStart = 10;
    } else {
        sv.proto = @"vless";
        sv.net = @"tcp";
        sv.security = [t objectAtIndex:4];
        sv.supported = YES;
        sv.host = [t objectAtIndex:5];
        sv.port = [[t objectAtIndex:6] intValue];
    }
    if ([t count] > remarkStart)
        sv.remark = [[t subarrayWithRange:NSMakeRange(remarkStart, [t count] - remarkStart)]
                     componentsJoinedByString:@" "];
    else
        sv.remark = @"";
    return sv;
}

static NSString *LRPercentField(NSString *field) {
    if (!field || [field isEqualToString:@"-"]) return @"";
    NSString *d = [field stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    return d ? d : @"";
}

static LRSubscription *LRFindSub(NSArray *subs, int idx) {
    for (LRSubscription *s in subs) if (s.index == idx) return s;
    return nil;
}

- (void)listCatalog:(void (^)(NSArray *, NSArray *, NSArray *))done {
    void (^callback)(NSArray *, NSArray *, NSArray *) = [[done copy] autorelease];
    [self sendCommand:@"LIST" timeoutMs:6000 reply:^(NSString *reply) {
        if (!reply) { if (callback) callback(nil, nil, nil); return; }
        NSMutableArray *servers = [NSMutableArray array];
        NSMutableArray *subs = [NSMutableArray array];
        NSMutableArray *order = [NSMutableArray array];
        NSInteger expected = -1;
        for (NSString *ln in [reply componentsSeparatedByString:@"\n"]) {
            if (![ln length]) continue;
            NSArray *t = [ln componentsSeparatedByString:@" "];
            if ([ln hasPrefix:@"LISTEND "]) {
                expected = [[ln substringFromIndex:8] intValue];
            } else if ([ln hasPrefix:@"SUB "] && [t count] >= 3) {
                LRSubscription *s = [[[LRSubscription alloc] init] autorelease];
                s.index = [[t objectAtIndex:1] intValue];
                /* SUB <idx> <name, spaces sent as underscores> <url> */
                s.name = [[t objectAtIndex:2] stringByReplacingOccurrencesOfString:@"_"
                                                                        withString:@" "];
                s.url = [t count] > 3
                    ? [[t subarrayWithRange:NSMakeRange(3, [t count] - 3)] componentsJoinedByString:@" "]
                    : @"";
                [subs addObject:s];
            } else if ([ln hasPrefix:@"SUBMETA "] && [t count] >= 3) {
                LRFindSub(subs, [[t objectAtIndex:1] intValue]).expire =
                    (unsigned long long)[[t objectAtIndex:2] longLongValue];
            } else if ([ln hasPrefix:@"SUBINFO "] && [t count] >= 7) {
                LRSubscription *s = LRFindSub(subs, [[t objectAtIndex:1] intValue]);
                s.upload = (unsigned long long)[[t objectAtIndex:2] longLongValue];
                s.download = (unsigned long long)[[t objectAtIndex:3] longLongValue];
                s.total = (unsigned long long)[[t objectAtIndex:4] longLongValue];
                s.summary = LRPercentField([t objectAtIndex:5]);
                s.supportURL = LRPercentField([t objectAtIndex:6]);
            } else if ([ln hasPrefix:@"SUBHDR "] && [t count] >= 3) {
                LRFindSub(subs, [[t objectAtIndex:1] intValue]).header =
                    LRPercentField([[t subarrayWithRange:NSMakeRange(2, [t count] - 2)]
                                    componentsJoinedByString:@" "]);
            } else if ([ln hasPrefix:@"SUBEXTRA "] && [t count] >= 5) {
                LRSubscription *s = LRFindSub(subs, [[t objectAtIndex:1] intValue]);
                s.updateIntervalHours = (unsigned int)[[t objectAtIndex:2] intValue];
                s.refillDate = (unsigned long long)[[t objectAtIndex:3] longLongValue];
                s.webPageURL = LRPercentField([t objectAtIndex:4]);
            } else if ([ln hasPrefix:@"SUBROUTING "] && [t count] >= 3) {
                LRSubscription *s = LRFindSub(subs, [[t objectAtIndex:1] intValue]);
                s.routingLink = [t objectAtIndex:2];
            } else if ([ln hasPrefix:@"SECTION "]) {
                for (NSUInteger i = 1; i < [t count]; ++i)
                    [order addObject:[NSNumber numberWithInt:[[t objectAtIndex:i] intValue]]];
            } else if ([ln hasPrefix:@"SRV "]) {
                LRServer *sv = LRParseSRV(ln);
                if (sv) [servers addObject:sv];
            }
        }
        if (expected < 0 || expected != (NSInteger)[servers count]) {
            if (callback) callback(nil, nil, nil);
            return;
        }
        if (callback) callback(servers, subs, order);
    }];
}

- (void)serverLinkIndex:(int)idx reply:(void (^)(NSString *))done {
    void (^callback)(NSString *) = [[done copy] autorelease];
    [self sendCommand:[NSString stringWithFormat:@"GETSRV %d", idx] timeoutMs:5000
                reply:^(NSString *reply) {
        NSString *link = nil;
        for (NSString *part in [reply componentsSeparatedByString:@"\n"]) {
            if (![part hasPrefix:@"LINK "]) continue;
            NSRange first = [part rangeOfString:@" "];
            NSRange second = [part rangeOfString:@" " options:0
                                           range:NSMakeRange(first.location + 1,
                                                             [part length] - first.location - 1)];
            if (second.location != NSNotFound) link = [part substringFromIndex:second.location + 1];
        }
        if (callback) callback(link);
    }];
}

- (void)addServerLink:(NSString *)link reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"ADDSRV %@", link] timeoutMs:5000 reply:done];
}

- (void)replaceServerIndex:(int)idx link:(NSString *)link reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"REPLACESRV %d %@", idx, link]
            timeoutMs:5000 reply:done];
}

- (void)deleteServerIndex:(int)idx reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"DELSRV %d", idx] reply:done];
}

- (void)clearManualServers:(void (^)(NSString *))done {
    [self sendCommand:@"CLEARMANUAL" timeoutMs:5000 reply:done];
}

static NSString *LROneLine(NSString *s) {
    s = [s ? s : @"" stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
    return [s stringByReplacingOccurrencesOfString:@"\n" withString:@" "];
}

static NSString *LRPercentEncodeField(NSString *s) {
    NSString *e = [LROneLine(s) stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    e = [e stringByReplacingOccurrencesOfString:@"+" withString:@"%2B"];
    return [e length] ? e : @"-";
}

- (void)addSubscriptionURL:(NSString *)url name:(NSString *)name reply:(void (^)(NSString *))done {
    NSString *safeURL = [url stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    NSString *safeName = LRTrim(LROneLine(name));
    if (![safeURL length] || !safeName) {
        if (done) done(@"ERR name and url required");
        return;
    }
    [self sendCommand:[NSString stringWithFormat:@"ADDSUB %@ %@", safeURL, safeName]
            timeoutMs:25000 reply:done];
}

- (void)replaceSubscriptionIndex:(int)idx name:(NSString *)name url:(NSString *)url
                          header:(NSString *)header reply:(void (^)(NSString *))done {
    NSString *safeURL = [url stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    NSString *safeName = LRTrim(LROneLine(name));
    if (![safeURL length] || !safeName) {
        if (done) done(@"ERR name and url required");
        return;
    }
    [self sendCommand:[NSString stringWithFormat:@"REPLACESUB %d %@ %@ %@", idx, safeURL,
                       LRPercentEncodeField(header), safeName] timeoutMs:5000 reply:done];
}

- (void)deleteSubscriptionIndex:(int)idx reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"DELSUB %d", idx] reply:done];
}

- (void)refreshSubscriptionIndex:(int)idx reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"REFRESH %d", idx] timeoutMs:30000 reply:done];
}

- (void)moveSection:(int)sectionId toPosition:(int)position reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"MOVESECTION %d %d", sectionId, position]
                reply:done];
}

- (void)moveManualServerIndex:(int)idx toPosition:(int)position reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"MOVEMANUAL %d %d", idx, position] reply:done];
}

- (BOOL)stageData:(NSData *)data atPath:(NSString *)stage {
    NSString *dir = [stage stringByDeletingLastPathComponent];
    return [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                     withIntermediateDirectories:YES attributes:nil error:NULL] &&
           [data writeToFile:stage atomically:YES];
}

- (void)importContent:(NSData *)data reply:(void (^)(NSString *))done {
    if (![data length]) { if (done) done(@"ERR nothing to import"); return; }
    NSString *stage = @SENKO_IMPORT_STAGE;
    if (![self stageData:data atPath:stage]) {
        if (done) done(@"ERR could not stage the import file");
        return;
    }
    void (^callback)(NSString *) = [[done copy] autorelease];
    [self sendCommand:@"IMPORT" timeoutMs:15000 reply:^(NSString *reply) {
        [[NSFileManager defaultManager] removeItemAtPath:stage error:NULL];
        if (callback) callback(reply);
    }];
}

#pragma mark tunnel

- (void)status:(void (^)(NSString *, long, BOOL, uint64_t, uint64_t))done {
    void (^callback)(NSString *, long, BOOL, uint64_t, uint64_t) = [[done copy] autorelease];
    [self sendCommand:@"STATUS" timeoutMs:2500 reply:^(NSString *reply) {
        long uptime = 0;
        NSString *state = LRStateFromReply(reply, &uptime);
        if (callback) callback(state, uptime, _trafficKnown, _trafficUp, _trafficDown);
    }];
}

- (void)connectIndex:(int)idx reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"CONNECT %d", idx] timeoutMs:60000 reply:done];
}

- (void)disconnect:(void (^)(NSString *))done {
    [self sendCommand:@"DISCONNECT" timeoutMs:10000 reply:done];
}

#pragma mark checks

static BOOL LRCheckModeValid(NSString *mode) {
    return [mode isEqualToString:@"tcp"] || [mode isEqualToString:@"proxy"] ||
           [mode isEqualToString:@"tunnel"] || [mode isEqualToString:@"handshake"];
}

- (void)checkIndex:(int)idx mode:(NSString *)mode reply:(void (^)(int, NSString *))done {
    if (!LRCheckModeValid(mode)) { if (done) done(-1, @"unknown check type"); return; }
    void (^callback)(int, NSString *) = [[done copy] autorelease];
    NSString *command = [mode isEqualToString:@"tcp"]
        ? [NSString stringWithFormat:@"PING %d", idx]
        : [NSString stringWithFormat:@"CHECK %@ %d", mode, idx];
    [self sendCommand:command timeoutMs:12000 reply:^(NSString *reply) {
        int ms = -1;
        NSString *error = nil;
        for (NSString *raw in [reply componentsSeparatedByString:@"\n"]) {
            NSString *line = LRTrim(raw);
            if ([line hasPrefix:@"PONG "]) {
                NSArray *parts = [line componentsSeparatedByString:@" "];
                if ([parts count] >= 3) ms = [[parts objectAtIndex:2] intValue];
            } else if ([line hasPrefix:@"ERR "]) {
                error = [line substringFromIndex:4];
            }
        }
        if (ms < 0 && !error) error = reply ? @"no answer" : @"daemon offline";
        if (callback) callback(ms, ms >= 0 ? nil : error);
    }];
}

- (void)checkIndex:(int)idx mode:(NSString *)mode
            stages:(void (^)(NSArray *, int, NSString *))done {
    if (!LRCheckModeValid(mode)) { if (done) done(nil, -1, @"unknown check type"); return; }
    void (^callback)(NSArray *, int, NSString *) = [[done copy] autorelease];
    [self sendCommand:[NSString stringWithFormat:@"CHECK %@ %d stages", mode, idx]
            timeoutMs:15000 reply:^(NSString *reply) {
        NSMutableArray *stages = [NSMutableArray array];
        int ms = -1;
        NSString *error = nil;
        for (NSString *raw in [reply componentsSeparatedByString:@"\n"]) {
            NSString *ln = LRTrim(raw);
            if ([ln hasPrefix:@"STAGE "]) {
                NSArray *p = [[ln substringFromIndex:6] componentsSeparatedByString:@" "];
                if ([p count] < 3) continue;
                LRCheckStage *stage = [[[LRCheckStage alloc] init] autorelease];
                stage.ok = [[p objectAtIndex:0] intValue] != 0;
                stage.ms = [[p objectAtIndex:1] intValue];
                stage.name = [[p subarrayWithRange:NSMakeRange(2, [p count] - 2)]
                              componentsJoinedByString:@" "];
                [stages addObject:stage];
            } else if ([ln hasPrefix:@"PONG "]) {
                NSArray *parts = [ln componentsSeparatedByString:@" "];
                if ([parts count] >= 3) ms = [[parts objectAtIndex:2] intValue];
            } else if ([ln hasPrefix:@"ERR "]) {
                error = [ln substringFromIndex:4];
            }
        }
        if (ms < 0 && !error) error = reply ? @"no answer" : @"daemon offline";
        if (callback) callback(stages, ms, ms >= 0 ? nil : error);
    }];
}

#pragma mark settings, rules, diagnostics

- (void)daemonSettings:(void (^)(NSDictionary *))done {
    void (^callback)(NSDictionary *) = [[done copy] autorelease];
    [self sendCommand:@"SETTINGS" timeoutMs:3000 reply:^(NSString *reply) {
        NSMutableDictionary *values = [NSMutableDictionary dictionary];
        BOOL sawEnd = NO;
        for (NSString *ln in [reply componentsSeparatedByString:@"\n"]) {
            if ([ln hasPrefix:@"SETEND"]) { sawEnd = YES; break; }
            if (![ln hasPrefix:@"SET "]) continue;
            NSString *pair = [ln substringFromIndex:4];
            NSRange sp = [pair rangeOfString:@" "];
            if (sp.location == NSNotFound) continue;
            NSString *key = [pair substringToIndex:sp.location];
            NSString *value = LRTrim([pair substringFromIndex:sp.location + 1]);
            if ([key length]) [values setObject:value ? value : @"" forKey:key];
        }
        if (callback) callback(sawEnd ? values : nil);
    }];
}

- (void)setSetting:(NSString *)key value:(NSString *)value reply:(void (^)(NSString *))done {
    if (![key length] || ![value length]) { if (done) done(@"ERR bad setting"); return; }
    [self sendCommand:[NSString stringWithFormat:@"SET %@ %@", key, LROneLine(value)]
            timeoutMs:3000 reply:done];
}

- (void)listRules:(void (^)(NSArray *))done {
    void (^callback)(NSArray *) = [[done copy] autorelease];
    [self sendCommand:@"RULES" timeoutMs:3000 reply:^(NSString *reply) {
        NSMutableArray *rules = [NSMutableArray array];
        BOOL sawEnd = NO;
        for (NSString *ln in [reply componentsSeparatedByString:@"\n"]) {
            if ([ln hasPrefix:@"RULEEND "]) { sawEnd = YES; break; }
            if (![ln hasPrefix:@"RULE "]) continue;
            NSArray *t = [ln componentsSeparatedByString:@" "];
            if ([t count] < 6) continue;
            LRRule *r = [[[LRRule alloc] init] autorelease];
            r.index = [[t objectAtIndex:1] intValue];
            r.action = [t objectAtIndex:2];
            r.type = [t objectAtIndex:3];
            r.hits = (unsigned long long)[[t objectAtIndex:4] longLongValue];
            r.value = [t objectAtIndex:5];
            [rules addObject:r];
        }
        if (callback) callback(sawEnd ? rules : nil);
    }];
}

- (void)addRuleAction:(NSString *)action type:(NSString *)type value:(NSString *)value
                reply:(void (^)(NSString *))done {
    if (![action length] || ![type length] || ![value length]) {
        if (done) done(@"ERR bad rule");
        return;
    }
    [self sendCommand:[NSString stringWithFormat:@"SET rule %@ %@ %@", action, type, value]
            timeoutMs:3000 reply:done];
}

- (void)deleteRuleIndex:(int)index reply:(void (^)(NSString *))done {
    [self sendCommand:[NSString stringWithFormat:@"DELRULE %d", index] timeoutMs:3000 reply:done];
}

- (void)diagnostics:(void (^)(NSArray *))done {
    void (^callback)(NSArray *) = [[done copy] autorelease];
    [self sendCommand:@"DIAG" timeoutMs:6000 reply:^(NSString *reply) {
        NSMutableArray *facts = [NSMutableArray array];
        BOOL sawEnd = NO;
        for (NSString *ln in [reply componentsSeparatedByString:@"\n"]) {
            if ([ln hasPrefix:@"DIAGEND"]) { sawEnd = YES; break; }
            if (![ln hasPrefix:@"DIAG "]) continue;
            NSString *rest = [ln substringFromIndex:5];
            NSRange sp = [rest rangeOfString:@" "];
            if (sp.location == NSNotFound) continue;
            LRDiagFact *fact = [[[LRDiagFact alloc] init] autorelease];
            fact.key = [rest substringToIndex:sp.location];
            fact.value = LRTrim([rest substringFromIndex:sp.location + 1]);
            [facts addObject:fact];
        }
        if (callback) callback(sawEnd ? facts : nil);
    }];
}

- (void)firewallConfig:(void (^)(NSString *, NSString *))done {
    void (^callback)(NSString *, NSString *) = [[done copy] autorelease];
    [self sendCommand:@"FWCONF" timeoutMs:6000 reply:^(NSString *reply) {
        NSMutableString *text = [NSMutableString string];
        BOOL sawEnd = NO;
        NSString *error = nil;
        for (NSString *ln in [reply componentsSeparatedByString:@"\n"]) {
            if ([ln hasPrefix:@"FWEND"]) { sawEnd = YES; break; }
            if ([ln hasPrefix:@"FWLINE "]) [text appendFormat:@"%@\n", [ln substringFromIndex:7]];
            else if ([ln hasPrefix:@"ERR "]) error = [ln substringFromIndex:4];
        }
        if (callback) callback(sawEnd ? text : nil,
                               sawEnd ? nil : (error ? error : @"the daemon did not answer"));
    }];
}

- (void)geo:(NSString *)verb timeout:(int)ms done:(void (^)(NSArray *, NSString *, BOOL))done {
    void (^callback)(NSArray *, NSString *, BOOL) = [[done copy] autorelease];
    [self sendCommand:[@"GEO " stringByAppendingString:verb] timeoutMs:ms reply:^(NSString *reply) {
        NSMutableArray *lines = [NSMutableArray array];
        NSString *summary = nil;
        BOOL ok = NO;
        for (NSString *raw in [reply componentsSeparatedByString:@"\n"]) {
            NSString *ln = LRTrim(raw);
            if (!ln) continue;
            if ([ln hasPrefix:@"GEO "]) [lines addObject:[ln substringFromIndex:4]];
            else if ([ln hasPrefix:@"OK "]) { ok = YES; summary = [ln substringFromIndex:3]; }
            else if ([ln hasPrefix:@"ERR "]) summary = [ln substringFromIndex:4];
        }
        if (!reply) summary = L(@"The daemon did not answer");
        if (callback) callback(lines, summary, ok);
    }];
}

- (void)geoStatus:(void (^)(NSArray *, NSString *, BOOL))done {
    [self geo:@"STATUS" timeout:8000 done:done];
}

- (void)geoUpdate:(void (^)(NSArray *, NSString *, BOOL))done {
    [self geo:@"UPDATE" timeout:420000 done:done];
}

- (void)flushTarget:(NSString *)what reply:(void (^)(NSString *))done {
    NSArray *known = [NSArray arrayWithObjects:@"dns", @"bypass", @"rules", @"config", nil];
    if (![known containsObject:what]) { if (done) done(@"ERR unknown flush target"); return; }
    [self sendCommand:[NSString stringWithFormat:@"FLUSH %@", what] timeoutMs:6000 reply:done];
}

- (void)deviceHWID:(void (^)(NSString *))done {
    void (^callback)(NSString *) = [[done copy] autorelease];
    [self sendCommand:@"HWID" timeoutMs:5000 reply:^(NSString *reply) {
        NSString *value = [reply hasPrefix:@"OK "] ? LRTrim([reply substringFromIndex:3]) : nil;
        if (!value) value = LRTrim([NSString stringWithContentsOfFile:@SENKO_HWID_PATH
                                                            encoding:NSUTF8StringEncoding
                                                               error:NULL]);
        if (callback) callback(value);
    }];
}

- (void)resetDeviceHWID:(void (^)(NSString *, NSString *))done {
    void (^callback)(NSString *, NSString *) = [[done copy] autorelease];
    [self sendCommand:@"HWIDRESET" timeoutMs:6000 reply:^(NSString *reply) {
        if ([reply hasPrefix:@"OK "]) {
            NSString *value = LRTrim([reply substringFromIndex:3]);
            if (value) { if (callback) callback(value, nil); return; }
        }
        NSString *error = LRErrorFromReply(reply);
        if (callback) callback(nil, error ? error : @"the daemon did not answer");
    }];
}

static NSData *LRDecodeBlob(NSString *reply, NSString **error) {
    if (![reply length]) { if (error) *error = @"the daemon did not answer"; return nil; }
    NSMutableData *raw = [NSMutableData data];
    BOOL sawEnd = NO;
    for (NSString *ln in [reply componentsSeparatedByString:@"\n"]) {
        if ([ln hasPrefix:@"FDEND "]) { sawEnd = YES; break; }
        if ([ln hasPrefix:@"ERR "]) { if (error) *error = [ln substringFromIndex:4]; return nil; }
        if (![ln hasPrefix:@"FDATA "]) continue;
        const char *encoded = [[ln substringFromIndex:6] UTF8String];
        size_t encoded_len = encoded ? strlen(encoded) : 0;
        size_t cap = b64_decoded_maxlen(encoded_len);
        if (!cap) continue;
        NSMutableData *chunk = [NSMutableData dataWithLength:cap];
        size_t got = 0;
        if (b64_decode(encoded, encoded_len, [chunk mutableBytes], cap, &got) != 0) {
            if (error) *error = @"corrupt reply";
            return nil;
        }
        [chunk setLength:got];
        [raw appendData:chunk];
    }
    if (!sawEnd) { if (error) *error = @"truncated reply"; return nil; }
    return raw;
}

- (void)daemonLogTail:(void (^)(NSString *))done {
    void (^callback)(NSString *) = [[done copy] autorelease];
    [self sendCommand:@"LOGS" timeoutMs:6000 reply:^(NSString *reply) {
        NSData *raw = LRDecodeBlob(reply, NULL);
        NSString *text = raw ? [[[NSString alloc] initWithData:raw encoding:NSUTF8StringEncoding]
                                autorelease] : nil;
        if (raw && !text)
            text = [[[NSString alloc] initWithData:raw encoding:NSISOLatin1StringEncoding] autorelease];
        if (callback) callback(text);
    }];
}

- (void)fetchURL:(NSString *)url reply:(void (^)(NSData *, NSString *))done {
    if (![url length]) { if (done) done(nil, @"empty url"); return; }
    void (^callback)(NSData *, NSString *) = [[done copy] autorelease];
    [self sendCommand:[NSString stringWithFormat:@"FETCH %@", url] timeoutMs:30000
                reply:^(NSString *reply) {
        NSString *error = nil;
        NSData *body = LRDecodeBlob(reply, &error);
        if (callback) callback(body, body ? nil : error);
    }];
}

- (void)exportBackup:(void (^)(NSString *))done {
    [self sendCommand:@"EXPORT" timeoutMs:5000 reply:done];
}

- (void)restoreBackupData:(NSData *)data reply:(void (^)(NSString *))done {
    if (![data length] ||
        ![self stageData:data atPath:@"/var/mobile/Library/Preferences/LegacyRay/import.lray"]) {
        if (done) done(@"ERR could not stage the backup");
        return;
    }
    [self sendCommand:@"RESTORE" timeoutMs:6000 reply:done];
}

#pragma mark helper processes

- (void)runKickWithArguments:(NSArray *)args reply:(void (^)(NSString *))done {
    void (^callback)(NSString *) = [[done copy] autorelease];
    NSArray *argsCopy = [[args copy] autorelease];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
        const char *path = [LRKickPath() fileSystemRepresentation];
        char *argv[6] = { (char *)path, NULL, NULL, NULL, NULL, NULL };
        NSUInteger n = MIN([argsCopy count], (NSUInteger)4);
        for (NSUInteger i = 0; i < n; ++i)
            argv[i + 1] = (char *)[[argsCopy objectAtIndex:i] fileSystemRepresentation];
        char output[256] = {0};
        int fds[2] = { -1, -1 };
        if (pipe(fds) == 0) {
            posix_spawn_file_actions_t fa;
            posix_spawn_file_actions_init(&fa);
            posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
            posix_spawn_file_actions_addclose(&fa, fds[0]);
            posix_spawn_file_actions_addclose(&fa, fds[1]);
            pid_t pid = 0;
            int rc = posix_spawn(&pid, path, &fa, NULL, argv, environ);
            posix_spawn_file_actions_destroy(&fa);
            close(fds[1]);
            if (rc == 0) {
                size_t total = 0;
                while (total + 1 < sizeof output) {
                    ssize_t r = read(fds[0], output + total, sizeof output - 1 - total);
                    if (r > 0) { total += (size_t)r; continue; }
                    if (r < 0 && errno == EINTR) continue;
                    break;
                }
                output[total] = '\0';
                int st = 0;
                while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
            }
            close(fds[0]);
        }
        NSString *status = output[0] ? [[NSString stringWithUTF8String:output] retain] : nil;
        dispatch_async(dispatch_get_main_queue(), ^{
            if (callback) callback(status);
            [status release];
        });
        [pool drain];
    });
}

/* nothing to ask the helper when both of its state files say it is idle */
static BOOL LRAWGIdle(void) {
    struct stat st;
    if (stat("/var/run/legacyrayawgd.pid", &st) == 0 || errno != ENOENT) return NO;
    FILE *f = fopen("/var/run/legacyrayawgd.status", "r");
    if (!f) return errno == ENOENT;
    char line[64] = {0};
    if (!fgets(line, sizeof line, f)) line[0] = '\0';
    fclose(f);
    line[strcspn(line, "\r\n")] = '\0';
    return line[0] == '\0' || strcmp(line, "idle") == 0;
}

- (void)startAWGAtPath:(NSString *)path reply:(void (^)(NSString *))done {
    if (![path length]) { if (done) done(nil); return; }
    [self runKickWithArguments:[NSArray arrayWithObjects:@"--awg", path, nil] reply:done];
}

- (void)stopAWG:(void (^)(NSString *))done {
    if (LRAWGIdle()) {
        void (^callback)(NSString *) = [[done copy] autorelease];
        dispatch_async(dispatch_get_main_queue(), ^{ if (callback) callback(@"idle\n"); });
        return;
    }
    [self runKickWithArguments:[NSArray arrayWithObject:@"--awg-stop"] reply:done];
}

- (void)awgStatus:(void (^)(NSString *))done {
    if (LRAWGIdle()) {
        void (^callback)(NSString *) = [[done copy] autorelease];
        dispatch_async(dispatch_get_main_queue(), ^{ if (callback) callback(@"idle\n"); });
        return;
    }
    [self runKickWithArguments:[NSArray arrayWithObject:@"--awg-status"] reply:done];
}

- (void)validateAWGAtPath:(NSString *)path reply:(void (^)(NSString *))done {
    if (![path length]) { if (done) done(nil); return; }
    [self runKickWithArguments:[NSArray arrayWithObjects:@"--awg-validate", path, nil] reply:done];
}

- (void)updatePackageAtPath:(NSString *)path progress:(void (^)(NSString *))progress
                      reply:(void (^)(NSString *))done {
    if (![path length]) { if (done) done(@"UPDATE ERR empty path"); return; }
    void (^callback)(NSString *) = [[done copy] autorelease];
    void (^onLine)(NSString *) = [[progress copy] autorelease];
    NSString *pathCopy = [[path copy] autorelease];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
        const char *bin = [LRKickPath() fileSystemRepresentation];
        const char *p = [pathCopy fileSystemRepresentation];
        NSString *status = nil;
        int fds[2] = { -1, -1 };
        if (access(bin, X_OK) != 0) {
            status = @"UPDATE ERR legacyray-kick missing";
        } else if (!p || pipe(fds) != 0) {
            status = @"UPDATE ERR pipe failed";
        } else {
            char *argv[] = { (char *)bin, (char *)"--update", (char *)p, NULL };
            posix_spawn_file_actions_t fa;
            posix_spawn_file_actions_init(&fa);
            posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
            if (posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/tmp/legacyray-update.log",
                                                 O_WRONLY | O_CREAT | O_APPEND, 0600) != 0)
                posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
            posix_spawn_file_actions_addclose(&fa, fds[0]);
            posix_spawn_file_actions_addclose(&fa, fds[1]);
            pid_t pid = 0;
            int rc = posix_spawn(&pid, bin, &fa, NULL, argv, environ);
            posix_spawn_file_actions_destroy(&fa);
            close(fds[1]);
            NSMutableString *pending = [NSMutableString string];
            NSString *terminal = nil;
            if (rc == 0) {
                char buf[256];
                for (;;) {
                    ssize_t n = read(fds[0], buf, sizeof buf);
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) break;
                    NSString *chunk = [[NSString alloc] initWithBytes:buf length:(NSUInteger)n
                                                             encoding:NSUTF8StringEncoding];
                    if (!chunk) chunk = [[NSString alloc] initWithBytes:buf length:(NSUInteger)n
                                                                encoding:NSISOLatin1StringEncoding];
                    if (chunk) [pending appendString:chunk];
                    [chunk release];
                    for (;;) {
                        NSRange nl = [pending rangeOfString:@"\n"];
                        if (nl.location == NSNotFound) break;
                        NSString *line = LRTrim([pending substringToIndex:nl.location]);
                        [pending deleteCharactersInRange:NSMakeRange(0, nl.location + 1)];
                        if (!line) continue;
                        if ([line hasPrefix:@"UPDATE OK"] || [line hasPrefix:@"UPDATE ERR"])
                            terminal = line;
                        if (onLine) {
                            NSString *copy = [line retain];
                            dispatch_async(dispatch_get_main_queue(), ^{
                                onLine(copy);
                                [copy release];
                            });
                        }
                    }
                }
                int st = 0;
                while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
                NSString *rest = LRTrim(pending);
                if (rest && ([rest hasPrefix:@"UPDATE OK"] || [rest hasPrefix:@"UPDATE ERR"]))
                    terminal = rest;
                if (terminal) status = terminal;
                else if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
                    status = [NSString stringWithFormat:@"UPDATE ERR helper exit %d",
                              WIFEXITED(st) ? WEXITSTATUS(st) : -1];
                else status = @"UPDATE ERR no status from helper";
            } else {
                status = [NSString stringWithFormat:@"UPDATE ERR spawn failed (%d)", rc];
            }
            close(fds[0]);
        }
        [status retain];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (callback) callback(status);
            [status release];
        });
        [pool drain];
    });
}

@end
