#import "LRCatalog.h"
#import "LRReminders.h"
#import "LRRoutingProfiles.h"
#import "LRDaemonClient.h"
#import "LRPrefs.h"
#import "LRActivityLog.h"

NSString * const LRCatalogDidChangeNotification = @"LRCatalogDidChangeNotification";
NSString * const LRCatalogPingNotification = @"LRCatalogPingNotification";

static const NSUInteger kPingParallel = 4;

@implementation LRSection
@synthesize sectionId = _sectionId, subscription = _subscription, title = _title,
            countryCode = _countryCode, servers = _servers, shownNames = _shownNames;

- (void)dealloc {
    [_subscription release];
    [_title release];
    [_countryCode release];
    [_servers release];
    [_shownNames release];
    [super dealloc];
}

- (BOOL)isManual {
    return _sectionId < 0;
}

- (NSString *)collapseKey {
    if (_sectionId < 0) return @"manual";
    return [_subscription.url length] ? _subscription.url
                                      : [NSString stringWithFormat:@"sub-%d", _sectionId];
}

- (BOOL)collapsed {
    return [LRPrefs sectionCollapsed:[self collapseKey]];
}

- (NSString *)nameForServer:(LRServer *)server {
    NSUInteger i = [_servers indexOfObjectIdenticalTo:server];
    if (i != NSNotFound && i < [_shownNames count]) return [_shownNames objectAtIndex:i];
    return [server displayName];
}
@end

@implementation LRCatalog
@synthesize servers = _servers, subscriptions = _subscriptions, sections = _sections,
            loaded = _loaded, loading = _loading, lastError = _lastError,
            selectedIndex = _selectedIndex;

+ (LRCatalog *)shared {
    static LRCatalog *catalog = nil;
    if (!catalog) catalog = [[LRCatalog alloc] init];
    return catalog;
}

- (id)init {
    if ((self = [super init])) {
        _servers = [[NSArray alloc] init];
        _subscriptions = [[NSArray alloc] init];
        _order = [[NSArray alloc] init];
        _sections = [[NSArray alloc] init];
        _pings = [[NSMutableDictionary alloc] init];
        _pingQueue = [[NSMutableArray alloc] init];
        _selectedIndex = -1;
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(prefsChanged:)
                                                     name:LRPrefsDidChangeNotification object:nil];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_servers release];
    [_subscriptions release];
    [_order release];
    [_sections release];
    [_pings release];
    [_pingQueue release];
    [_lastError release];
    [super dealloc];
}

- (void)prefsChanged:(NSNotification *)note {
    /* the sort mode may have changed */
    [self rebuildSections];
    [[NSNotificationCenter defaultCenter] postNotificationName:LRCatalogDidChangeNotification
                                                        object:self];
}

#pragma mark loading

- (void)reload {
    [self reload:nil];
}

- (void)reload:(void (^)(BOOL))done {
    void (^callback)(BOOL) = [[done copy] autorelease];
    _loading = YES;
    [[LRDaemonClient shared] listCatalog:^(NSArray *servers, NSArray *subs, NSArray *order) {
        _loading = NO;
        if (!servers) {
            self.lastError = @"the daemon did not answer";
            [[NSNotificationCenter defaultCenter] postNotificationName:LRCatalogDidChangeNotification
                                                                object:self];
            if (callback) callback(NO);
            return;
        }
        self.lastError = nil;
        BOOL renumbered = [servers count] != [_servers count];
        [_servers release];
        _servers = [servers retain];
        [_subscriptions release];
        _subscriptions = [subs retain];
        [_order release];
        _order = [order retain];
        _loaded = YES;
        if (renumbered) [self forgetPings];
        [self restoreSelection];
        [LRReminders scheduleForSubscriptions:_subscriptions];
        [LRRoutingProfiles offerProviderRoutingFrom:_subscriptions];
        [self rebuildSections];
        [[NSNotificationCenter defaultCenter] postNotificationName:LRCatalogDidChangeNotification
                                                            object:self];
        if (callback) callback(YES);
    }];
}

/* panel feeds put the same banner in front of every node name and a row only
   has room for the first words, so the shared head is dropped for display */
static NSString *LRSharedHead(NSArray *names) {
    if ([names count] < 2) return nil;
    NSString *first = [names objectAtIndex:0];
    NSUInteger common = [first length];
    for (NSString *name in names) {
        NSUInteger i = 0;
        while (i < common && i < [name length] &&
               [name characterAtIndex:i] == [first characterAtIndex:i]) ++i;
        common = i;
        if (!common) return nil;
    }
    NSCharacterSet *seps = [NSCharacterSet characterSetWithCharactersInString:@" |·-—:/,"];
    NSUInteger cut = 0;
    for (NSUInteger i = 0; i < common; ++i)
        if ([seps characterIsMember:[first characterAtIndex:i]]) cut = i + 1;
    return cut >= 6 ? [first substringToIndex:cut] : nil;
}

static NSArray *LRShownNames(NSArray *rows) {
    NSMutableArray *raw = [NSMutableArray array];
    for (LRServer *sv in rows) [raw addObject:[sv displayName]];
    NSString *head = LRSharedHead(raw);
    if (![head length]) return raw;
    NSMutableArray *shown = [NSMutableArray array];
    for (NSString *name in raw) {
        NSString *cut = [name length] > [head length] ? LRTrim([name substringFromIndex:[head length]]) : nil;
        [shown addObject:cut ? cut : name];
    }
    return shown;
}

- (NSArray *)sortedRows:(NSArray *)rows {
    LRSortMode mode = [LRPrefs sortMode];
    if (mode == LRSortManual) return rows;
    return [rows sortedArrayUsingComparator:^NSComparisonResult(LRServer *a, LRServer *b) {
        if (mode == LRSortPing) {
            NSNumber *pa = [_pings objectForKey:[NSNumber numberWithInt:a.index]];
            NSNumber *pb = [_pings objectForKey:[NSNumber numberWithInt:b.index]];
            int ra = !pa ? 1 : ([pa intValue] >= 0 ? 0 : 2);
            int rb = !pb ? 1 : ([pb intValue] >= 0 ? 0 : 2);
            if (ra != rb) return ra < rb ? NSOrderedAscending : NSOrderedDescending;
            if (ra == 0 && [pa intValue] != [pb intValue])
                return [pa intValue] < [pb intValue] ? NSOrderedAscending : NSOrderedDescending;
        }
        return [[a displayName] compare:[b displayName] options:NSCaseInsensitiveSearch];
    }];
}

- (LRSection *)makeSection:(int)sectionId rows:(NSArray *)rows {
    LRSection *sec = [[[LRSection alloc] init] autorelease];
    sec.sectionId = sectionId;
    LRSubscription *sub = sectionId >= 0 ? [self subscriptionWithIndex:sectionId] : nil;
    sec.subscription = sub;
    NSString *title = sectionId < 0 ? L(@"Manual") : ([sub.name length] ? sub.name : L(@"Subscription"));
    sec.title = title;
    for (LRServer *sv in rows) {
        NSString *cc = [sv countryCode];
        if (cc) { sec.countryCode = cc; break; }
    }
    NSArray *sorted = [self sortedRows:rows];
    sec.servers = sorted;
    sec.shownNames = LRShownNames(sorted);
    return sec;
}

- (void)rebuildSections {
    NSMutableDictionary *bySection = [NSMutableDictionary dictionary];
    for (LRServer *sv in _servers) {
        NSNumber *key = [NSNumber numberWithInt:sv.group < 0 ? -1 : sv.group];
        NSMutableArray *rows = [bySection objectForKey:key];
        if (!rows) {
            rows = [NSMutableArray array];
            [bySection setObject:rows forKey:key];
        }
        [rows addObject:sv];
    }
    NSMutableArray *order = [NSMutableArray arrayWithArray:_order];
    if (![order containsObject:[NSNumber numberWithInt:-1]])
        [order insertObject:[NSNumber numberWithInt:-1] atIndex:0];
    for (LRSubscription *sub in _subscriptions) {
        NSNumber *key = [NSNumber numberWithInt:sub.index];
        if (![order containsObject:key]) [order addObject:key];
    }
    NSMutableArray *sections = [NSMutableArray array];
    for (NSNumber *key in order) {
        int sid = [key intValue];
        NSArray *rows = [bySection objectForKey:key];
        if (sid < 0 && ![rows count]) continue;
        if (sid >= 0 && ![self subscriptionWithIndex:sid]) continue;
        [sections addObject:[self makeSection:sid rows:rows ? rows : [NSArray array]]];
    }
    [_sections release];
    _sections = [sections retain];
}

#pragma mark selection

/* a server's identity survives the renumbering a refresh causes */
static NSString *LRServerIdentity(LRServer *sv) {
    return [NSString stringWithFormat:@"%d|%@|%d|%@|%@", sv.group < 0 ? -1 : sv.group, sv.host, sv.port,
            sv.proto, sv.remark];
}

/* the user can tune to a station while idle; the daemon only learns about it
   on the next connect, so the choice is kept here until then */
- (void)restoreSelection {
    NSString *wanted = [[NSUserDefaults standardUserDefaults] stringForKey:@"LRSelectedStation"];
    int daemonSelected = -1;
    _selectedIndex = -1;
    for (LRServer *sv in _servers) {
        if (sv.selected) daemonSelected = sv.index;
        if (wanted && [LRServerIdentity(sv) isEqualToString:wanted]) _selectedIndex = sv.index;
    }
    if (_selectedIndex < 0) _selectedIndex = daemonSelected;
    /* the server the tunnel is up on outranks a choice made here while idle */
    if (_adoptDaemonSelection && daemonSelected >= 0) [self setSelectedIndex:daemonSelected];
    _adoptDaemonSelection = NO;
}

- (void)adoptDaemonSelection {
    _adoptDaemonSelection = YES;
    [self reload];
}

- (void)setSelectedIndex:(int)index {
    _selectedIndex = index;
    LRServer *sv = [self serverWithIndex:index];
    if (sv) [[NSUserDefaults standardUserDefaults] setObject:LRServerIdentity(sv) forKey:@"LRSelectedStation"];
    else [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"LRSelectedStation"];
}

#pragma mark lookup

- (LRServer *)serverWithIndex:(int)index {
    for (LRServer *sv in _servers) if (sv.index == index) return sv;
    return nil;
}

- (LRSubscription *)subscriptionWithIndex:(int)index {
    for (LRSubscription *s in _subscriptions) if (s.index == index) return s;
    return nil;
}

- (LRSection *)sectionForServer:(LRServer *)server {
    for (LRSection *sec in _sections)
        if ([sec.servers indexOfObjectIdenticalTo:server] != NSNotFound) return sec;
    return nil;
}

- (LRServer *)selectedServer {
    return _selectedIndex >= 0 ? [self serverWithIndex:_selectedIndex] : nil;
}

- (NSString *)displayNameForServer:(LRServer *)server {
    LRSection *sec = [self sectionForServer:server];
    return sec ? [sec nameForServer:server] : [server displayName];
}

- (LRServer *)serverAfterSelected:(NSInteger)step {
    NSMutableArray *flat = [NSMutableArray array];
    for (LRSection *sec in _sections) [flat addObjectsFromArray:sec.servers];
    if (![flat count]) return nil;
    LRServer *current = [self selectedServer];
    NSInteger i = current ? (NSInteger)[flat indexOfObjectIdenticalTo:current] : NSNotFound;
    if (i == NSNotFound) return [flat objectAtIndex:0];
    NSInteger n = (NSInteger)[flat count];
    NSInteger next = ((i + step) % n + n) % n;
    return [flat objectAtIndex:(NSUInteger)next];
}

- (BOOL)isEmpty {
    return [_servers count] == 0 && [_subscriptions count] == 0 && ![LRPrefs hasAWGProfile];
}

#pragma mark latency

- (NSNumber *)pingForServer:(LRServer *)server {
    return server ? [_pings objectForKey:[NSNumber numberWithInt:server.index]] : nil;
}

- (void)forgetPings {
    ++_pingGeneration;
    [_pingQueue removeAllObjects];
    _pingInFlight = 0;
    [_pings removeAllObjects];
}

- (BOOL)pinging {
    return _pingInFlight > 0 || [_pingQueue count] > 0;
}

- (void)cancelPings {
    ++_pingGeneration;
    for (NSNumber *idx in _pingQueue) [_pings removeObjectForKey:idx];
    [_pingQueue removeAllObjects];
    _pingInFlight = 0;
    for (NSNumber *key in [_pings allKeys])
        if ([[_pings objectForKey:key] intValue] == LR_PING_RUNNING) [_pings removeObjectForKey:key];
    [[NSNotificationCenter defaultCenter] postNotificationName:LRCatalogPingNotification object:self];
}

- (void)pumpPings {
    NSString *mode = [LRPrefs pingModeName];
    while (_pingInFlight < kPingParallel && [_pingQueue count]) {
        NSNumber *idx = [[[_pingQueue objectAtIndex:0] retain] autorelease];
        [_pingQueue removeObjectAtIndex:0];
        ++_pingInFlight;
        NSUInteger generation = _pingGeneration;
        [[LRDaemonClient shared] checkIndex:[idx intValue] mode:mode reply:^(int ms, NSString *error) {
            if (generation != _pingGeneration) return;
            if (_pingInFlight) --_pingInFlight;
            [_pings setObject:[NSNumber numberWithInt:ms >= 0 ? ms : LR_PING_FAILED] forKey:idx];
            [[NSNotificationCenter defaultCenter] postNotificationName:LRCatalogPingNotification
                                                                object:self];
            [self checkPick];
            if (![self pinging]) {
                if ([LRPrefs sortMode] == LRSortPing) {
                    [self rebuildSections];
                    [[NSNotificationCenter defaultCenter]
                        postNotificationName:LRCatalogDidChangeNotification object:self];
                }
            }
            [self pumpPings];
        }];
    }
}

#pragma mark fastest

- (void)finishPick {
    [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(finishPick) object:nil];
    if (!_bestDone) return;
    LRServer *best = nil;
    int bestMs = 0;
    for (LRServer *sv in _bestCandidates) {
        int ms = [[self pingForServer:sv] intValue];
        if (![self pingForServer:sv] || ms < 0) continue;
        if (!best || ms < bestMs) { best = sv; bestMs = ms; }
    }
    void (^done)(LRServer *, int) = [_bestDone autorelease];
    _bestDone = nil;
    [_bestCandidates release];
    _bestCandidates = nil;
    done(best, bestMs);
}

- (void)checkPick {
    if (!_bestDone) return;
    for (LRServer *sv in _bestCandidates)
        if ([[self pingForServer:sv] intValue] == LR_PING_RUNNING) return;
    [self finishPick];
}

- (void)pickFastestOf:(NSArray *)servers done:(void (^)(LRServer *best, int ms))done {
    if (_bestDone || ![servers count]) {
        if (done) done(nil, 0);
        return;
    }
    _bestCandidates = [servers copy];
    _bestDone = [done copy];
    [self pingServers:servers];
    /* a daemon that stops answering must not leave the pick hanging */
    [self performSelector:@selector(finishPick) withObject:nil afterDelay:45.0];
    [self checkPick];
}

- (void)pingServers:(NSArray *)servers {
    for (LRServer *sv in servers) {
        NSNumber *idx = [NSNumber numberWithInt:sv.index];
        if ([_pingQueue containsObject:idx]) continue;
        if ([[_pings objectForKey:idx] intValue] == LR_PING_RUNNING &&
            [_pings objectForKey:idx]) continue;
        [_pings setObject:[NSNumber numberWithInt:LR_PING_RUNNING] forKey:idx];
        [_pingQueue addObject:idx];
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:LRCatalogPingNotification object:self];
    [self pumpPings];
}

- (void)pingAll {
    NSMutableArray *all = [NSMutableArray array];
    for (LRSection *sec in _sections) [all addObjectsFromArray:sec.servers];
    LRLog(@"ping", @"latency check of %lu servers (%@)", (unsigned long)[all count],
          [LRPrefs pingModeName]);
    [self pingServers:all];
}

#pragma mark mutations

- (void)setSection:(LRSection *)section collapsed:(BOOL)collapsed {
    [LRPrefs setSection:[section collapseKey] collapsed:collapsed];
}

- (void)moveSection:(LRSection *)section toPosition:(NSUInteger)position {
    if (!section) return;
    NSNumber *key = [NSNumber numberWithInt:section.sectionId];
    NSMutableArray *visible = [NSMutableArray array];
    for (LRSection *s in _sections) [visible addObject:[NSNumber numberWithInt:s.sectionId]];
    [visible removeObject:key];
    if (position > [visible count]) position = [visible count];
    /* the daemon position counts every section it knows, including an empty
       manual one the list hides, so the target is found in the full order */
    NSMutableArray *full = [NSMutableArray arrayWithArray:_order];
    for (NSNumber *n in visible) if (![full containsObject:n]) [full addObject:n];
    [full removeObject:key];
    NSUInteger daemonPos = position < [visible count]
        ? [full indexOfObject:[visible objectAtIndex:position]] : [full count];
    if (daemonPos == NSNotFound) daemonPos = [full count];
    [full insertObject:key atIndex:daemonPos];
    [_order release];
    _order = [full copy];
    [self rebuildSections];
    [[NSNotificationCenter defaultCenter] postNotificationName:LRCatalogDidChangeNotification object:self];
    [[LRDaemonClient shared] moveSection:section.sectionId toPosition:(int)daemonPos
                                   reply:^(NSString *reply) {
        if (!LRReplyIsOK(reply)) [self reload];
    }];
}

- (void)refreshAllSubscriptions:(void (^)(NSUInteger, NSUInteger))done {
    void (^callback)(NSUInteger, NSUInteger) = [[done copy] autorelease];
    NSArray *subs = [[_subscriptions copy] autorelease];
    if (![subs count]) { if (callback) callback(0, 0); return; }
    __block NSUInteger ok = 0, failed = 0;
    LRLog(@"subscriptions", @"updating %lu subscriptions", (unsigned long)[subs count]);
    /* one at a time: the daemon serialises fetches anyway, and a parallel burst
       only makes every panel time out together on a slow link */
    __block void (^next)(NSUInteger) = nil;
    next = [^(NSUInteger i) {
        if (i >= [subs count]) {
            [self reload];
            LRLog(@"subscriptions", @"updated %lu of %lu", (unsigned long)ok, (unsigned long)[subs count]);
            if (callback) callback(ok, failed);
            [next release];
            return;
        }
        LRSubscription *sub = [subs objectAtIndex:i];
        [[LRDaemonClient shared] refreshSubscriptionIndex:sub.index reply:^(NSString *reply) {
            if (LRReplyIsOK(reply)) ++ok;
            else {
                ++failed;
                LRLogFail(@"subscriptions", @"%@: %@", sub.name,
                          LRErrorFromReply(reply) ? LRErrorFromReply(reply) : @"no answer");
            }
            next(i + 1);
        }];
    } copy];
    next(0);
}
@end
