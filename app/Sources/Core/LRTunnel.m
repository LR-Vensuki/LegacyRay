#import "LRTunnel.h"
#include "senko_paths.h"
#import "LRDaemonClient.h"
#import "LRCatalog.h"
#import "LRActivityLog.h"
#import "control.h"
#import <fcntl.h>
#import <unistd.h>
#import <errno.h>
#import <signal.h>
#import <stdio.h>
#import <sys/types.h>
#import <sys/socket.h>
#import <ifaddrs.h>
#import <net/if.h>

NSString * const LRTunnelDidChangeNotification = @"LRTunnelDidChangeNotification";
NSString * const LRTunnelTickNotification = @"LRTunnelTickNotification";

/* springboard's vpn badge reads this file; the daemon writes it while it runs
   and the app clears it when a tunnel ends badly */
static void LRClearStatusBadge(void) {
    int fd = open(SENKO_STATUS_STATE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        (void)write(fd, "0\n", 2);
        close(fd);
    }
}

/* the daemon answers "layer: reason" in english for the log. the user gets
   what went wrong in words, with the daemon's own reason kept in brackets so
   a screenshot still says exactly which step failed */
static NSString *LRConnectErrorText(NSString *err) {
    NSString *lower = [err lowercaseString];
    NSString *what = L(@"Could not connect");
    if ([lower rangeOfString:@"dns resolution failed"].location != NSNotFound ||
        [lower rangeOfString:@"cannot be resolved"].location != NSNotFound)
        what = L(@"The server address could not be found (DNS)");
    else if ([lower rangeOfString:@"unsupported"].location != NSNotFound)
        what = L(@"This kind of server is not supported");
    else if ([lower rangeOfString:@"uuid"].location != NSNotFound)
        what = L(@"The server link has a wrong key (UUID)");
    else if ([lower hasPrefix:@"routing"])
        what = L(@"Traffic could not be sent into the tunnel");
    else if ([lower rangeOfString:@"tunnel open failed"].location != NSNotFound)
        what = L(@"The server refused the connection");
    /* the loop drops the local handshake when it cannot reach the server */
    else if ([lower rangeOfString:@"greet"].location != NSNotFound)
        what = L(@"The server does not answer");
    else if ([lower rangeOfString:@"socks listener"].location != NSNotFound ||
             [lower rangeOfString:@"socks not ready"].location != NSNotFound)
        what = L(@"The local proxy port could not be opened");
    else if ([lower rangeOfString:@"response"].location != NSNotFound ||
             [lower rangeOfString:@"dial"].location != NSNotFound ||
             [lower rangeOfString:@"verify"].location != NSNotFound ||
             [lower rangeOfString:@"write failed"].location != NSNotFound)
        what = L(@"The server does not pass traffic");
    return [NSString stringWithFormat:@"%@ (%@)", what, err];
}

@implementation LRTunnel
@synthesize state = _state, activeBackend = _activeBackend, uptime = _uptime,
            bytesUp = _bytesUp, bytesDown = _bytesDown, speedUp = _speedUp,
            speedDown = _speedDown, busy = _busy, lastError = _lastError;

+ (LRTunnel *)shared {
    static LRTunnel *tunnel = nil;
    if (!tunnel) tunnel = [[LRTunnel alloc] init];
    return tunnel;
}

- (id)init {
    if ((self = [super init])) {
        _state = LRTunnelOffline;
        _activeBackend = LRBackendServer;
    }
    return self;
}

- (void)dealloc {
    [self stop];
    [_stream release];
    [_awgInterface release];
    [_lastError release];
    [super dealloc];
}

- (void)notifyChange {
    [[NSNotificationCenter defaultCenter] postNotificationName:LRTunnelDidChangeNotification
                                                        object:self];
}

- (void)setState:(LRTunnelState)state {
    if (state == _state) return;
    LRTunnelState old = _state;
    _state = state;
    if (state == LRTunnelConnected && old != LRTunnelConnected) {
        _lastSampleTime = 0;
        _peakDown = 0;
        LRServer *sv = [[LRCatalog shared] selectedServer];
        LRLog(@"tunnel", @"connected%@", sv && _activeBackend == LRBackendServer
              ? [@" · " stringByAppendingString:[sv protocolSummary]] : @" · AmneziaWG");
    } else if (state == LRTunnelIdle && old == LRTunnelConnected) {
        LRLog(@"tunnel", @"disconnected");
    }
    if (state != LRTunnelConnected) {
        _speedUp = _speedDown = 0;
        _uptime = 0;
    }
    [self updateTickTimer];
    [self notifyChange];
}

#pragma mark monitoring

#define LR_AWG_PID_PATH     SENKO_AWG_PID
#define LR_AWG_STATUS_PATH  @SENKO_AWG_STATUS
#define LR_AWG_STATUS_NOTE  "com.legacyray.awg.status"
#define LR_WATCH_RENEW      20.0

static void LRAWGStatusChanged(CFNotificationCenterRef center, void *observer,
                               CFStringRef name, const void *object,
                               CFDictionaryRef info) {
    [[LRTunnel shared] performSelectorOnMainThread:@selector(awgStatusChanged)
                                        withObject:nil waitUntilDone:NO];
}

/* the helper runs as root and the app as mobile, so kill answers EPERM for a
   live process and ESRCH for a dead one; either way no helper is spawned */
static BOOL LRAWGRunning(void) {
    FILE *f = fopen(LR_AWG_PID_PATH, "r");
    if (!f) return NO;
    int pid = 0;
    int got = fscanf(f, "%d", &pid);
    fclose(f);
    if (got != 1 || pid <= 1) return NO;
    return kill(pid, 0) == 0 || errno == EPERM;
}

/* "connected utun3", "connecting", "error ...", "idle" */
static NSString *LRAWGStatusText(void) {
    if (!LRAWGRunning()) return @"idle";
    NSString *text = LRTrim([NSString stringWithContentsOfFile:LR_AWG_STATUS_PATH
                                                      encoding:NSUTF8StringEncoding error:NULL]);
    return [text length] ? text : @"connecting";
}

/* bytes through an interface, from the kernel's own counters */
static BOOL LRInterfaceBytes(NSString *name, uint64_t *inBytes, uint64_t *outBytes) {
    struct ifaddrs *list = NULL;
    if (!name || getifaddrs(&list) != 0) return NO;
    BOOL found = NO;
    const char *want = [name UTF8String];
    for (struct ifaddrs *it = list; it; it = it->ifa_next) {
        if (!it->ifa_addr || it->ifa_addr->sa_family != AF_LINK || !it->ifa_data) continue;
        if (strcmp(it->ifa_name, want) != 0) continue;
        const struct if_data *d = (const struct if_data *)it->ifa_data;
        *inBytes = d->ifi_ibytes;
        *outBytes = d->ifi_obytes;
        found = YES;
        break;
    }
    freeifaddrs(list);
    return found;
}

- (BOOL)awgSelected {
    return _activeBackend == LRBackendAmneziaWG || [LRPrefs selectedBackend] == LRBackendAmneziaWG;
}

- (void)updateTickTimer {
    BOOL want = _active && _state == LRTunnelConnected;
    if (want && !_timer) {
        _timer = [[NSTimer scheduledTimerWithTimeInterval:1.0 target:self
                                                 selector:@selector(timerFired:)
                                                 userInfo:nil repeats:YES] retain];
    } else if (!want && _timer) {
        [_timer invalidate];
        [_timer release];
        _timer = nil;
    }
}

- (void)start {
    if (_active) return;
    _active = YES;
    static BOOL observing = NO;
    if (!observing) {
        observing = YES;
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL,
                                        LRAWGStatusChanged, CFSTR(LR_AWG_STATUS_NOTE), NULL,
                                        CFNotificationSuspensionBehaviorCoalesce);
    }
    if (!_stream) _stream = [[LRStatusStream alloc] initWithDelegate:self];
    [_stream open];
    if (!_renewTimer)
        _renewTimer = [[NSTimer scheduledTimerWithTimeInterval:LR_WATCH_RENEW target:self
                                                      selector:@selector(renewWatch:)
                                                      userInfo:nil repeats:YES] retain];
    [self pollNow];
    [self updateTickTimer];
}

- (void)stop {
    _active = NO;
    [_stream close];
    [_renewTimer invalidate];
    [_renewTimer release];
    _renewTimer = nil;
    [_retryTimer invalidate];
    [_retryTimer release];
    _retryTimer = nil;
    [self updateTickTimer];
}

- (void)renewWatch:(NSTimer *)timer {
    if ([_stream isOpen]) [_stream renew];
}

- (void)retryStream:(NSTimer *)timer {
    [_retryTimer release];
    _retryTimer = nil;
    if (_active) [_stream open];
}

- (void)timerFired:(NSTimer *)timer {
    if (_activeBackend == LRBackendAmneziaWG && _awgInterface) {
        uint64_t in = 0, out = 0;
        if (LRInterfaceBytes(_awgInterface, &in, &out)) [self applySampleUp:out down:in];
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:LRTunnelTickNotification object:self];
}

- (LRTunnelState)stateFromName:(NSString *)name {
    if ([name isEqualToString:@"connected"]) return LRTunnelConnected;
    if ([name isEqualToString:@"connecting"]) return LRTunnelConnecting;
    if ([name isEqualToString:@"error"]) return LRTunnelError;
    return LRTunnelIdle;
}

- (void)applySampleUp:(uint64_t)up down:(uint64_t)down {
    NSTimeInterval now = [NSDate timeIntervalSinceReferenceDate];
    if (_lastSampleTime > 0 && up >= _lastSampleUp && down >= _lastSampleDown) {
        double dt = now - _lastSampleTime;
        if (dt > 0.2) {
            double su = (double)(up - _lastSampleUp) / dt;
            double sd = (double)(down - _lastSampleDown) / dt;
            /* light smoothing so the needles settle instead of twitching */
            _speedUp = _speedUp * 0.35 + su * 0.65;
            _speedDown = _speedDown * 0.35 + sd * 0.65;
            if (_speedDown > _peakDown) _peakDown = _speedDown;
        }
    }
    _lastSampleTime = now;
    _lastSampleUp = up;
    _lastSampleDown = down;
    _bytesUp = up;
    _bytesDown = down;
}

#pragma mark stream

- (void)statusStream:(LRStatusStream *)stream line:(NSString *)line {
    if ([line hasPrefix:@"STAT "]) {
        NSData *data = [line dataUsingEncoding:NSUTF8StringEncoding];
        uint64_t up = 0, down = 0;
        if (_activeBackend == LRBackendServer &&
            ctl_parse_stat([data bytes], [data length], &up, &down) == CTL_OK)
            [self applySampleUp:up down:down];
        return;
    }
    if (![line hasPrefix:@"STATE "]) return;
    if (_busy || _activeBackend == LRBackendAmneziaWG) return;
    long uptime = 0;
    NSString *name = LRStateFromReply(line, &uptime);
    if (!name) return;
    LRTunnelState st = [self stateFromName:name];
    if (st == LRTunnelConnected) {
        _uptime = uptime;
        _uptimeBase = [NSDate timeIntervalSinceReferenceDate] - uptime;
    }
    /* a connect this app did not start (it is not busy) chose its server
       elsewhere, and the card and the list should show that one. the daemon
       stores its selection once the tunnel is up, not while connecting */
    if (st == LRTunnelConnected && _state != LRTunnelConnected)
        [[LRCatalog shared] adoptDaemonSelection];
    [self setState:st];
}

- (void)statusStreamClosed:(LRStatusStream *)stream {
    if (!_active) return;
    if (!_busy && _activeBackend == LRBackendServer && ![self awgSelected])
        [self setState:LRTunnelOffline];
    if (!_retryTimer)
        _retryTimer = [[NSTimer scheduledTimerWithTimeInterval:4.0 target:self
                                                      selector:@selector(retryStream:)
                                                      userInfo:nil repeats:NO] retain];
}

#pragma mark amneziawg

- (void)awgStatusChanged {
    if (!_active || _busy) return;
    [self applyAWGStatus:LRAWGStatusText()];
}

/* returns NO when amneziawg is not running, so the caller asks the daemon */
- (BOOL)applyAWGStatus:(NSString *)s {
    if ([s hasPrefix:@"connected"] || [s hasPrefix:@"connecting"]) {
        _activeBackend = LRBackendAmneziaWG;
        BOOL up = [s hasPrefix:@"connected"];
        NSArray *words = [s componentsSeparatedByString:@" "];
        [_awgInterface release];
        _awgInterface = up && [words count] > 1 ? [[words objectAtIndex:1] copy] : nil;
        if (up && _state != LRTunnelConnected) {
            _uptimeBase = [NSDate timeIntervalSinceReferenceDate];
            _lastSampleTime = 0;
        }
        [self setState:up ? LRTunnelConnected : LRTunnelConnecting];
        return YES;
    }
    [_awgInterface release];
    _awgInterface = nil;
    if (_activeBackend == LRBackendAmneziaWG) {
        _activeBackend = LRBackendServer;
        if ([s hasPrefix:@"error"]) {
            self.lastError = [s length] > 6 ? [s substringFromIndex:6] : s;
            [self setState:LRTunnelError];
        } else {
            [self setState:LRTunnelIdle];
        }
    }
    return NO;
}

- (void)pollNow {
    if (_polling) return;
    if ([self awgSelected] && [self applyAWGStatus:LRAWGStatusText()]) return;
    _polling = YES;
    [self pollDaemon];
}

- (void)pollDaemon {
    [[LRDaemonClient shared] status:^(NSString *stateName, long uptime, BOOL known,
                                      uint64_t up, uint64_t down) {
        _polling = NO;
        if (_busy) return;
        if (!stateName) {
            [self setState:LRTunnelOffline];
            return;
        }
        LRTunnelState st = [self stateFromName:stateName];
        if (st == LRTunnelConnected) {
            _uptime = uptime;
            _uptimeBase = [NSDate timeIntervalSinceReferenceDate] - uptime;
            if (known) [self applySampleUp:up down:down];
        }
        [self setState:st];
    }];
}

- (long)liveUptime {
    if (_state != LRTunnelConnected || _uptimeBase <= 0) return 0;
    return (long)([NSDate timeIntervalSinceReferenceDate] - _uptimeBase);
}

- (NSString *)stateTitle {
    switch (_state) {
        case LRTunnelOffline: return L(@"Service Stopped");
        case LRTunnelIdle: return L(@"Not Connected");
        case LRTunnelConnecting: return L(@"Connecting…");
        case LRTunnelConnected: return L(@"Connected");
        case LRTunnelError: return L(@"Connection Failed");
    }
    return @"";
}

#pragma mark control

- (BOOL)isOn {
    return _state == LRTunnelConnected || _state == LRTunnelConnecting;
}

- (void)setBusy:(BOOL)busy {
    _busy = busy;
    [self notifyChange];
}

- (void)failWith:(NSString *)reason {
    self.lastError = reason;
    if (reason) LRLogFail(@"tunnel", @"%@", reason);
    LRClearStatusBadge();
    _busy = NO;
    _state = LRTunnelIdle;
    [self setState:LRTunnelError];
}

- (void)toggle {
    if (_busy) return;
    if ([self isOn]) [self disconnect];
    else [self connect];
}

- (void)connect {
    if ([LRPrefs selectedBackend] == LRBackendAmneziaWG) {
        [self startAWG];
        return;
    }
    int idx = [LRCatalog shared].selectedIndex;
    if (idx < 0) {
        LRServer *first = [[LRCatalog shared] serverAfterSelected:0];
        if (!first) {
            [self failWith:L(@"No server selected. Import a server or a subscription first.")];
            return;
        }
        idx = first.index;
    }
    [self connectServerIndex:idx];
}

- (void)connectServerIndex:(int)index {
    if (_busy) return;
    self.lastError = nil;
    [LRPrefs setSelectedBackend:LRBackendServer];
    [LRCatalog shared].selectedIndex = index;
    _state = LRTunnelConnecting;
    [self setBusy:YES];
    LRDaemonClient *client = [LRDaemonClient shared];
    [client ensureDaemon:^(BOOL up, NSString *detail) {
        if (!up) {
            [self failWith:detail ? detail : L(@"The daemon is not running")];
            return;
        }
        /* amneziawg and the vless daemon both want the default route */
        [client stopAWG:^(NSString *stopReply) {
            NSString *stop = LRTrim(stopReply);
            if (!stop || [stop hasPrefix:@"error"]) {
                [self failWith:stop ? stop : @"could not stop amneziawg"];
                return;
            }
            _activeBackend = LRBackendServer;
            [client connectIndex:index reply:^(NSString *reply) {
                NSString *err = LRErrorFromReply(reply);
                NSString *finalState = LRStateFromReply(reply, NULL);
                BOOL stuck = [finalState isEqualToString:@"connecting"] && !err;
                if (!reply || stuck) {
                    NSString *why = !reply ? L(@"The LegacyRay service did not answer")
                        : [reply rangeOfString:@LR_REPLY_CLOSED].location != NSNotFound
                            ? L(@"The LegacyRay service restarted while connecting")
                            : L(@"Connection timed out");
                    /* a missing answer can leave routing half applied */
                    [client disconnect:^(NSString *r) {
                        [self failWith:why];
                    }];
                    return;
                }
                _busy = NO;
                if ([finalState isEqualToString:@"connected"]) {
                    _uptimeBase = [NSDate timeIntervalSinceReferenceDate];
                    [self setState:LRTunnelConnected];
                } else {
                    [self failWith:err ? LRConnectErrorText(err) : L(@"The server did not accept the connection")];
                }
                [[LRCatalog shared] reload];
            }];
        }];
    }];
}

- (void)disconnect {
    if (_busy) return;
    [self setBusy:YES];
    LRDaemonClient *client = [LRDaemonClient shared];
    void (^finish)(void) = ^{
        _busy = NO;
        _activeBackend = LRBackendServer;
        self.lastError = nil;
        LRClearStatusBadge();
        [self setState:LRTunnelIdle];
        [self pollNow];
    };
    if (_activeBackend == LRBackendAmneziaWG) {
        [client stopAWG:^(NSString *status) { finish(); }];
        return;
    }
    [client disconnect:^(NSString *reply) { finish(); }];
}

- (void)seek:(NSInteger)step {
    if (_busy) return;
    LRServer *next = [[LRCatalog shared] serverAfterSelected:step];
    if (!next) return;
    [LRCatalog shared].selectedIndex = next.index;
    [self notifyChange];
    if ([self isOn] && _activeBackend == LRBackendServer) [self connectServerIndex:next.index];
}

- (void)startAWG {
    if (_busy) return;
    NSString *path = [LRPrefs awgProfilePath];
    if (![LRPrefs hasAWGProfile]) {
        [self failWith:L(@"No AmneziaWG profile is saved")];
        return;
    }
    [LRPrefs setSelectedBackend:LRBackendAmneziaWG];
    self.lastError = nil;
    _state = LRTunnelConnecting;
    [self setBusy:YES];
    LRDaemonClient *client = [LRDaemonClient shared];
    [client disconnect:^(NSString *reply) {
        [client startAWGAtPath:path reply:^(NSString *status) {
            NSString *s = LRTrim(status);
            if (!s || [s hasPrefix:@"error"]) {
                [self failWith:s ? s : @"could not start amneziawg"];
                return;
            }
            _activeBackend = LRBackendAmneziaWG;
            _busy = NO;
            [self setState:LRTunnelConnecting];
            LRLog(@"tunnel", @"amneziawg started");
            /* the helper posts its status as it changes; this picks up
               anything it said while the start command was running */
            [self applyAWGStatus:LRAWGStatusText()];
        }];
    }];
}
@end
