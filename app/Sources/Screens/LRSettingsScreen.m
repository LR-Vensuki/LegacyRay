#import "LRSettingsScreen.h"
#import "LRSimpleScreens.h"
#import "LRDaemonSettings.h"
#import "LRDaemonClient.h"
#import "LRPrefs.h"
#import "LRTunnel.h"
#import "LRCatalog.h"
#import "LRActivityLog.h"
#import "LRImporter.h"
#import "LRAlert.h"
#import "LRMenu.h"
#import "LRToast.h"
#import "LRAppDelegate.h"
#import "LRVersion.h"
#import "LRAWGScreen.h"
#import "LRFilesScreen.h"
#import "LRDiagnosticsScreen.h"
#import "LRAboutScreen.h"
#import "LRUpdatesScreen.h"
#import "LRRoutingProfiles.h"
#import "LRNetInfo.h"
#import "LRReminders.h"
#import "LRSSH.h"
#import "LRServersScreen.h"
#import "LRAWGProfiles.h"
#import "LRRoutingProfilesScreen.h"

static LRDaemonSettings *DS(void) { return [LRDaemonSettings shared]; }

static void LRRoutingChanged(void) {
    if ([[LRTunnel shared] isOn]) [LRToast show:L(@"Reconnect the VPN to apply routing changes.")];
}

@implementation LRSettingsScreen

- (id)init {
    if ((self = [super init])) self.title = L(@"Setup");
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_hwid release];
    [super dealloc];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserver:self selector:@selector(reloadSections) name:LRDaemonSettingsDidChangeNotification object:nil];
    [nc addObserver:self selector:@selector(reloadSections) name:LRPrefsDidChangeNotification object:nil];
    [DS() refresh];
    [[LRDaemonClient shared] listRules:^(NSArray *rules) {
        self->_ruleCount = [rules count];
        [self reloadSections];
    }];
    [[LRDaemonClient shared] deviceHWID:^(NSString *hwid) {
        [self->_hwid release];
        self->_hwid = [hwid copy];
        [self reloadSections];
    }];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadSections];
}

- (LRRow *)daemonToggle:(NSString *)title key:(NSString *)key fallback:(BOOL)fallback routing:(BOOL)routing {
    return [LRRow toggle:title on:[DS() boolForKey:key fallback:fallback] changed:^(BOOL on) {
        [DS() setBool:on forKey:key];
        if (routing) LRRoutingChanged();
    }];
}

- (void)choose:(NSString *)title options:(NSArray *)options selected:(NSInteger)selected
        picked:(void (^)(NSInteger))picked {
    LRChoiceScreen *c = [[[LRChoiceScreen alloc] initWithTitle:title options:options selected:selected
                                                        picked:picked] autorelease];
    [self openScreen:c];
}

- (NSArray *)buildSections {
    __block LRSettingsScreen *me = self;
    NSMutableArray *sections = [NSMutableArray array];

    /* connection */
    NSInteger attempts = [DS() integerForKey:@"reconnect_max_attempts" fallback:5];
    NSArray *attemptValues = [NSArray arrayWithObjects:@"0", @"3", @"5", @"10", @"20", nil];
    NSArray *attemptNames = [NSArray arrayWithObjects:L(@"Until it works"), @"3", @"5", @"10", @"20", nil];
    NSArray *pingNames = [NSArray arrayWithObjects:L(@"TCP connect"), L(@"TLS / Reality handshake"),
                          L(@"Real delay (HTTP through the server)"), nil];
    NSArray *connection = [NSArray arrayWithObjects:
        [self daemonToggle:L(@"Reconnect automatically") key:@"auto_reconnect" fallback:YES routing:NO],
        [self daemonToggle:L(@"Connect at startup") key:@"auto_connect" fallback:NO routing:NO],
        [self daemonToggle:L(@"Failover to the next server") key:@"failover" fallback:NO routing:NO],
        [LRRow value:L(@"Reconnect attempts")
              detail:attempts == 0 ? L(@"Until it works") : [NSString stringWithFormat:@"%ld", (long)attempts]
              action:^(LRRow *r, UIView *c) {
            NSUInteger sel = [attemptValues indexOfObject:[NSString stringWithFormat:@"%ld", (long)attempts]];
            [me choose:L(@"Reconnect attempts") options:attemptNames
              selected:sel == NSNotFound ? -1 : (NSInteger)sel picked:^(NSInteger i) {
                [DS() setValue:[attemptValues objectAtIndex:(NSUInteger)i] forKey:@"reconnect_max_attempts" done:nil];
            }];
        }],
        [LRRow value:L(@"Ping type") detail:[pingNames objectAtIndex:[LRPrefs pingType]]
              action:^(LRRow *r, UIView *c) {
            [me choose:L(@"Ping type") options:pingNames selected:[LRPrefs pingType] picked:^(NSInteger i) {
                [LRPrefs setPingType:(LRPingType)i];
                [[LRCatalog shared] forgetPings];
            }];
        }], nil];
    [sections addObject:[LRSectionSpec header:L(@"Connection") rows:connection
                                       footer:L(@"Failover walks the same subscription when a server will not come up.")]];

    /* routing */
    BOOL routing = [DS() boolForKey:@"rules_enabled" fallback:YES];
    NSString *routingDetail = routing ? [NSString stringWithFormat:@"%@ · %lu", L(@"On"), (unsigned long)_ruleCount]
                                      : L(@"Off");
    [sections addObject:[LRSectionSpec header:L(@"Routing") rows:[NSArray arrayWithObjects:
        [LRRow value:L(@"Rules and exceptions") detail:routingDetail action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRRoutingScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Split tunneling")
              detail:[[DS() stringForKey:@"rules_default"] isEqualToString:@"direct"] ? L(@"Only the list") : L(@"All but the list")
              action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRSitesScreen alloc] init] autorelease]];
        }],
        [self daemonToggle:L(@"Bypass local networks") key:@"bypass_lan" fallback:YES routing:YES], nil]
                                       footer:nil]];

    /* anti-censorship and safety */
    BOOL frag = [DS() boolForKey:@"fragment" fallback:NO];
    NSString *fragSize = [DS() stringForKey:@"fragment_size"];
    NSInteger fragDelay = [DS() integerForKey:@"fragment_delay" fallback:10];
    NSArray *sizeValues = [NSArray arrayWithObjects:@"10-30", @"50-100", @"100-200", @"200-400", nil];
    NSArray *delayValues = [NSArray arrayWithObjects:@"0", @"5", @"10", @"20", @"50", nil];
    NSMutableArray *dpi = [NSMutableArray array];
    [dpi addObject:[self daemonToggle:L(@"Fragment the TLS handshake") key:@"fragment" fallback:NO routing:NO]];
    if (frag) {
        [dpi addObject:[LRRow value:L(@"Fragment size") detail:[NSString stringWithFormat:L(@"%@ bytes"), fragSize ? fragSize : @"100-200"]
                             action:^(LRRow *r, UIView *c) {
            NSMutableArray *names = [NSMutableArray array];
            for (NSString *v in sizeValues) [names addObject:[NSString stringWithFormat:L(@"%@ bytes"), v]];
            NSUInteger sel = fragSize ? [sizeValues indexOfObject:fragSize] : 2;
            [me choose:L(@"Fragment size") options:names selected:sel == NSNotFound ? -1 : (NSInteger)sel
                picked:^(NSInteger i) {
                [DS() setValue:[sizeValues objectAtIndex:(NSUInteger)i] forKey:@"fragment_size" done:nil];
            }];
        }]];
        [dpi addObject:[LRRow value:L(@"Pause between fragments")
                             detail:[NSString stringWithFormat:L(@"%ld ms"), (long)fragDelay]
                             action:^(LRRow *r, UIView *c) {
            NSMutableArray *names = [NSMutableArray array];
            for (NSString *v in delayValues) [names addObject:[NSString stringWithFormat:L(@"%@ ms"), v]];
            NSUInteger sel = [delayValues indexOfObject:[NSString stringWithFormat:@"%ld", (long)fragDelay]];
            [me choose:L(@"Pause between fragments") options:names selected:sel == NSNotFound ? -1 : (NSInteger)sel
                picked:^(NSInteger i) {
                [DS() setValue:[delayValues objectAtIndex:(NSUInteger)i] forKey:@"fragment_delay" done:nil];
            }];
        }]];
    }
    [sections addObject:[LRSectionSpec header:L(@"Getting past blocking") rows:dpi
                                       footer:L(@"Sends the first packet of every TLS and Reality connection in small pieces, so filters that read the server name out of it see only part of it. Each new connection starts a little slower.")]];

    NSString *dns = [DS() stringForKey:@"dns_upstream"];
    NSArray *dnsValues = [NSArray arrayWithObjects:@"1.1.1.1", @"8.8.8.8", @"9.9.9.9", @"77.88.8.8", nil];
    NSArray *dnsNames = [NSArray arrayWithObjects:@"Cloudflare 1.1.1.1", @"Google 8.8.8.8", @"Quad9 9.9.9.9",
                         L(@"Yandex 77.88.8.8"), L(@"Custom..."), nil];
    BOOL lan = [DS() boolForKey:@"socks_public" fallback:NO];
    NSString *ip = [LRNetInfo localIPv4];
    NSInteger socksPort = [DS() integerForKey:@"socks_port" fallback:1080];
    NSMutableArray *safety = [NSMutableArray array];
    [safety addObject:[self daemonToggle:L(@"Kill switch") key:@"kill_switch" fallback:NO routing:YES]];
    [safety addObject:[LRRow value:L(@"DNS server") detail:dns ? dns : @"8.8.8.8" action:^(LRRow *r, UIView *c) {
        NSUInteger sel = dns ? [dnsValues indexOfObject:dns] : 1;
        [me choose:L(@"DNS server") options:dnsNames selected:sel == NSNotFound ? (NSInteger)[dnsValues count] : (NSInteger)sel
            picked:^(NSInteger i) {
            if (i < (NSInteger)[dnsValues count]) {
                [DS() setValue:[dnsValues objectAtIndex:(NSUInteger)i] forKey:@"dns_upstream" done:nil];
                LRRoutingChanged();
                return;
            }
            [LRAlert promptTitle:L(@"DNS server") message:L(@"An IPv4 address") placeholder:@"1.1.1.1"
                            text:dns button:L(@"Save") done:^(NSString *v) {
                [DS() setValue:LRTrim(v) forKey:@"dns_upstream" done:^(BOOL ok, NSString *err) {
                    if (!ok) [LRToast showError:L(@"That address was not accepted")];
                    else LRRoutingChanged();
                }];
            }];
        }];
    }]];
    [safety addObject:[LRRow toggle:L(@"Share the proxy on the local network") on:lan changed:^(BOOL on) {
        [DS() setBool:on forKey:@"socks_public"];
        [LRToast show:L(@"Takes effect after the daemon restarts (or a reboot).")];
    }]];
    [sections addObject:[LRSectionSpec header:L(@"Security and network") rows:safety
                                       footer:lan && ip ? [NSString stringWithFormat:L(@"Other devices on this Wi-Fi can use SOCKS5 %@:%ld. Anyone on the network can, so turn it off on public networks."), ip, (long)socksPort]
                                                        : L(@"The kill switch keeps UDP other than DNS off the network while a tunnel is up, so nothing leaks around it. Queries go through the tunnel to the DNS server.")]];

    /* battery */
    NSArray *kaNames = [NSArray arrayWithObjects:L(@"As in the profile"), L(@"Only while the screen is on"), L(@"Off"), nil];
    [sections addObject:[LRSectionSpec header:L(@"Battery") rows:[NSArray arrayWithObjects:
        [self daemonToggle:L(@"Economical cipher (ChaCha20)") key:@"prefer_chacha" fallback:YES routing:NO],
        [LRRow value:L(@"AmneziaWG keepalive") detail:[kaNames objectAtIndex:[LRPrefs awgKeepalive]]
              action:^(LRRow *r, UIView *c) {
            LRChoiceScreen *choice = [[[LRChoiceScreen alloc] initWithTitle:L(@"AmneziaWG keepalive") options:kaNames
                                                                   selected:[LRPrefs awgKeepalive] picked:^(NSInteger i) {
                [LRPrefs setAWGKeepalive:(LRAWGKeepaliveMode)i];
            }] autorelease];
            choice.footer = L(@"Keepalives hold the tunnel open for incoming traffic, but each one wakes the cellular radio. With the screen off, messages that arrive through the tunnel may be delayed until the phone sends something itself. Applies on the next connect.");
            [me openScreen:choice];
        }], nil]
                                       footer:L(@"Old iPhones have no AES instructions; ChaCha20 costs them a fraction of the work, and servers pick it when asked first. The daemon sleeps while idle either way.")]];

    /* subscriptions */
    /* 0 is automatic: the provider's own interval, twice a day without one */
    NSInteger hours = [DS() integerForKey:@"sub_refresh_hours" fallback:0];
    NSArray *hourValues = [NSArray arrayWithObjects:@"0", @"6", @"12", @"24", @"48", @"168", @"-1", nil];
    NSArray *hourNames = [NSArray arrayWithObjects:L(@"Automatic"), L(@"Every 6 hours"), L(@"Every 12 hours"),
                          L(@"Every day"), L(@"Every 2 days"), L(@"Every week"), L(@"Off"), nil];
    NSUInteger hourIndex = [hourValues indexOfObject:[NSString stringWithFormat:@"%ld", (long)hours]];
    NSString *ua = [DS() stringForKey:@"sub_user_agent"];
    NSString *xver = [DS() stringForKey:@"xray_version"];
    NSArray *subs = [NSArray arrayWithObjects:
        [LRRow value:L(@"Auto-update subscriptions")
              detail:hourIndex == NSNotFound ? [NSString stringWithFormat:@"%ld h", (long)hours]
                                            : [hourNames objectAtIndex:hourIndex]
              action:^(LRRow *r, UIView *c) {
            [me choose:L(@"Auto-update subscriptions") options:hourNames
              selected:hourIndex == NSNotFound ? -1 : (NSInteger)hourIndex picked:^(NSInteger i) {
                [DS() setValue:[hourValues objectAtIndex:(NSUInteger)i] forKey:@"sub_refresh_hours" done:nil];
            }];
        }],
        [LRRow toggle:L(@"Refresh subscriptions on app open") on:[LRPrefs refreshSubscriptionsOnOpen]
              changed:^(BOOL on) { [LRPrefs setRefreshSubscriptionsOnOpen:on]; }],
        [LRRow toggle:L(@"Remind before a subscription ends") on:[LRReminders enabled]
              changed:^(BOOL on) {
            [LRReminders setEnabled:on];
            if (on) [LRReminders scheduleForSubscriptions:[LRCatalog shared].subscriptions];
        }],
        [LRRow toggle:L(@"Keep renamed subscriptions after updates") on:![DS() boolForKey:@"sub_panel_title" fallback:NO]
              changed:^(BOOL on) { [DS() setBool:!on forKey:@"sub_panel_title"]; }],
        [LRRow value:@"User-Agent" detail:ua ? ua : @"Happ/3.26.1" action:^(LRRow *r, UIView *c) {
            [me pickUserAgent];
        }],
        [LRRow value:L(@"Xray version") detail:xver ? xver : @"26.7.28" action:^(LRRow *r, UIView *c) {
            [LRAlert promptTitle:L(@"Xray version")
                         message:L(@"The version this client reports inside the Reality handshake. Change it only when a server requires a specific client version.")
                     placeholder:@"26.7.28" text:xver button:L(@"Save") done:^(NSString *v) {
                NSString *clean = LRTrim(v);
                if (!clean) return;
                [DS() setValue:clean forKey:@"xray_version" done:^(BOOL ok, NSString *err) {
                    if (!ok) [LRToast showError:L(@"Use x.y.z; each number must be from 0 to 255.")];
                }];
            }];
        }],
        [LRRow value:L(@"Device ID (HWID)") detail:_hwid ? LRStealth(_hwid) : @"—" action:^(LRRow *r, UIView *c) {
            [me hwidMenu:c];
        }], nil];
    [sections addObject:[LRSectionSpec header:L(@"Subscriptions") rows:subs
                                       footer:L(@"Panels identify this device by its HWID and pick the feed format by the User-Agent.")]];

    /* appearance */
    NSArray *themeNames = [NSArray arrayWithObjects:L(@"Automatic"), L(@"Classic"), L(@"Flat"), nil];
    LRThemeSetting theme = [LRPrefs theme];
    NSInteger themeIndex = theme == LRThemeFlat ? 2 : (theme == LRThemeClassic ? 1 : 0);
    NSArray *langs = [NSArray arrayWithObjects:LRLanguageName(LRLanguageAuto), @"English", @"Русский", @"中文", nil];
    NSArray *sorts = [NSArray arrayWithObjects:L(@"As added"), L(@"By name"), L(@"By latency"), nil];
    NSArray *appearance = [NSArray arrayWithObjects:
        [LRRow value:L(@"Theme") detail:[themeNames objectAtIndex:themeIndex] action:^(LRRow *r, UIView *c) {
            LRChoiceScreen *choice = [[[LRChoiceScreen alloc] initWithTitle:L(@"Theme") options:themeNames
                                                                   selected:themeIndex picked:^(NSInteger i) {
                LRThemeSetting picked[3] = { LRThemeAuto, LRThemeClassic, LRThemeFlat };
                [LRPrefs setTheme:picked[i < 0 || i > 2 ? 0 : i]];
                [[LRAppDelegate shared] performSelector:@selector(rebuildInterface) withObject:nil afterDelay:0.25];
            }] autorelease];
            choice.notes = [NSArray arrayWithObjects:L(@"Flat on iOS 7 and later, classic before"),
                            L(@"iOS 6: black denim bars, grouped tables"),
                            L(@"White cards and hairlines, like iOS 7"), nil];
            [me openScreen:choice];
        }],
        [LRRow value:L(@"Language") detail:LRLanguageName(LRLanguageSetting()) action:^(LRRow *r, UIView *c) {
            [me choose:L(@"Language") options:langs selected:LRLanguageSetting() picked:^(NSInteger i) {
                LRSetLanguageSetting((LRLanguage)i);
                [[LRAppDelegate shared] performSelector:@selector(rebuildInterface) withObject:nil afterDelay:0.25];
            }];
        }],
        [LRRow toggle:L(@"Sounds") on:[LRPrefs soundEffects] changed:^(BOOL on) { [LRPrefs setSoundEffects:on]; }],
        [LRRow value:L(@"Sort servers") detail:[sorts objectAtIndex:[LRPrefs sortMode]] action:^(LRRow *r, UIView *c) {
            [me choose:L(@"Sort servers") options:sorts selected:[LRPrefs sortMode] picked:^(NSInteger i) {
                [LRPrefs setSortMode:(LRSortMode)i];
            }];
        }], nil];
    [sections addObject:[LRSectionSpec header:L(@"Appearance") rows:appearance footer:nil]];

    /* privacy */
    [sections addObject:[LRSectionSpec header:L(@"Privacy") rows:[NSArray arrayWithObjects:
        [LRRow toggle:L(@"Stealth mode") on:[LRPrefs stealthMode] changed:^(BOOL on) { [LRPrefs setStealthMode:on]; }],
        [LRRow toggle:L(@"Record app activity") on:[LRPrefs activityLogging]
              changed:^(BOOL on) { [LRPrefs setActivityLogging:on]; }], nil]
                                       footer:L(@"Stealth mode hides addresses, links and keys on screen and in reports, for screenshots.")]];

    /* connections and tools */
    NSArray *tools = [NSArray arrayWithObjects:
        [LRRow value:@"AmneziaWG" detail:[LRPrefs hasAWGProfile]
                  ? [NSString stringWithFormat:@"%lu", (unsigned long)[[LRAWGProfiles profiles] count]] : nil
              action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRAWGScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Own servers") detail:[[LRServerHosts hosts] count]
                  ? [NSString stringWithFormat:@"%lu", (unsigned long)[[LRServerHosts hosts] count]] : nil
              action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRServersScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Export backup") detail:nil action:^(LRRow *r, UIView *c) { [me exportBackup]; }],
        [LRRow value:L(@"Restore backup") detail:nil action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRFilesScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Advanced") detail:nil action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRAdvancedScreen alloc] init] autorelease]];
        }], nil];
    [sections addObject:[LRSectionSpec header:L(@"Tools") rows:tools footer:nil]];

    NSArray *info = [NSArray arrayWithObjects:
        [LRRow value:L(@"Updates") detail:@LR_VERSION action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRUpdatesScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Diagnostics") detail:nil action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRDiagnosticsScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"About") detail:nil action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRAboutScreen alloc] init] autorelease]];
        }], nil];
    [sections addObject:[LRSectionSpec header:nil rows:info footer:nil]];
    return sections;
}

- (void)pickUserAgent {
    NSArray *agents = [NSArray arrayWithObjects:@"Happ/3.26.1", @"Happ/3.26.3/iOS", @"v2rayN/7.13",
                       @"v2rayNG/1.10.16", @"Hiddify/2.5.7", @"Streisand/1.6", @"Shadowrocket/2.2.65",
                       @"clash-verge/v2.2.3", @"sing-box 1.12.0", nil];
    NSString *current = [DS() stringForKey:@"sub_user_agent"];
    NSMutableArray *options = [NSMutableArray arrayWithArray:agents];
    [options addObject:L(@"Custom...")];
    NSUInteger sel = current ? [agents indexOfObject:current] : 0;
    __block LRSettingsScreen *me = self;
    [self choose:@"User-Agent" options:options selected:sel == NSNotFound ? (NSInteger)[agents count] : (NSInteger)sel
          picked:^(NSInteger i) {
        if (i < (NSInteger)[agents count]) {
            [DS() setValue:[agents objectAtIndex:(NSUInteger)i] forKey:@"sub_user_agent" done:nil];
            return;
        }
        [LRAlert promptTitle:@"User-Agent" message:nil placeholder:@"Happ/3.26.1" text:current
                      button:L(@"Save") done:^(NSString *v) {
            NSString *clean = LRTrim(v);
            if (clean) [DS() setValue:clean forKey:@"sub_user_agent" done:nil];
            [me reloadSections];
        }];
    }];
}

- (void)hwidMenu:(UIView *)anchor {
    __block LRSettingsScreen *me = self;
    LRMenu *menu = [LRMenu menuWithTitle:L(@"Device ID (HWID)")];
    [menu addItem:L(@"Copy") action:^{
        if (!me->_hwid) return;
        [UIPasteboard generalPasteboard].string = me->_hwid;
        [LRToast showSuccess:L(@"HWID copied")];
    }];
    [menu addDestructiveItem:L(@"Issue a new device ID") action:^{
        [LRAlert confirmTitle:L(@"Issue a new device ID")
                      message:L(@"Panels that limit devices will see this phone as a new device.")
                       button:L(@"Issue") destructive:YES action:^{
            LRSettingsScreen *strong = [me retain];
            [[LRDaemonClient shared] resetDeviceHWID:^(NSString *hwid, NSString *error) {
                if (hwid) {
                    [strong->_hwid release];
                    strong->_hwid = [hwid copy];
                    [LRToast showSuccess:L(@"New device ID issued")];
                    [strong reloadSections];
                } else [LRToast showError:error];
                [strong release];
            }];
        }];
    }];
    [menu showFromView:anchor];
}

- (void)exportBackup {
    [[LRDaemonClient shared] exportBackup:^(NSString *reply) {
        if (!LRReplyIsOK(reply)) {
            [LRToast showError:LRErrorFromReply(reply) ? LRErrorFromReply(reply) : L(@"Backup export failed")];
            return;
        }
        LRLog(@"backup", @"backup exported");
        [LRToast showSuccess:L(@"Saved to Documents/legacyray-backup.lray. Copy it with iTunes file sharing.")];
    }];
}
@end

#pragma mark routing

@implementation LRRoutingScreen

- (id)init {
    if ((self = [super init])) self.title = L(@"Routing");
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_rules release];
    [super dealloc];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(reloadSections)
                                                 name:LRDaemonSettingsDidChangeNotification object:nil];
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self loadRules];
}

- (void)loadRules {
    [[LRDaemonClient shared] listRules:^(NSArray *rules) {
        [self->_rules release];
        self->_rules = [rules retain];
        [self reloadSections];
    }];
}

+ (NSString *)typeName:(NSString *)type {
    if ([type isEqualToString:@"domain-suffix"]) return L(@"Head domain");
    if ([type isEqualToString:@"domain-keyword"]) return L(@"Keyword");
    if ([type isEqualToString:@"domain"]) return L(@"Specific domain");
    if ([type isEqualToString:@"ip-cidr"]) return @"IP / CIDR";
    if ([type isEqualToString:@"port"]) return L(@"Port or range");
    if ([type isEqualToString:@"geosite"]) return L(@"geosite category");
    if ([type isEqualToString:@"geoip"]) return L(@"geoip country");
    return type;
}

+ (NSString *)actionName:(NSString *)action {
    if ([action isEqualToString:@"direct"]) return L(@"Direct");
    if ([action isEqualToString:@"block"]) return L(@"Block");
    return L(@"Proxy");
}

- (void)addRules:(NSArray *)specs {
    if (![specs count]) {
        [self loadRules];
        return;
    }
    NSArray *spec = [specs objectAtIndex:0];
    NSArray *rest = [specs subarrayWithRange:NSMakeRange(1, [specs count] - 1)];
    [[LRDaemonClient shared] addRuleAction:[spec objectAtIndex:0] type:[spec objectAtIndex:1]
                                     value:[spec objectAtIndex:2] reply:^(NSString *reply) {
        if (!LRReplyIsOK(reply)) {
            [LRToast showError:LRErrorFromReply(reply) ? LRErrorFromReply(reply) : L(@"Invalid Rule")];
            [self loadRules];
            return;
        }
        [self addRules:rest];
    }];
}

- (void)presets:(UIView *)anchor {
    __block LRRoutingScreen *me = self;
    LRMenu *menu = [LRMenu menuWithTitle:L(@"Presets")];
    [menu addItem:L(@"Russian sites and addresses go direct (geo)") action:^{
        [me addRules:[NSArray arrayWithObjects:
            [NSArray arrayWithObjects:@"direct", @"geosite", @"category-ru", nil],
            [NSArray arrayWithObjects:@"direct", @"geosite", @"private", nil],
            [NSArray arrayWithObjects:@"direct", @"geoip", @"ru", nil],
            [NSArray arrayWithObjects:@"direct", @"geoip", @"private", nil],
            [NSArray arrayWithObjects:@"direct", @"domain-suffix", @"xn--p1ai", nil], nil]];
        [[LRDaemonClient shared] geoUpdate:^(NSArray *lines, NSString *summary, BOOL ok) {
            if (!ok) [LRToast showError:summary ? summary : L(@"Geo data could not be downloaded")];
        }];
    }];
    [menu addItem:L(@"Block ads (geosite)") action:^{
        [me addRules:[NSArray arrayWithObjects:
            [NSArray arrayWithObjects:@"block", @"geosite", @"category-ads-all", nil], nil]];
        [[LRDaemonClient shared] geoUpdate:^(NSArray *lines, NSString *summary, BOOL ok) {
            if (!ok) [LRToast showError:summary ? summary : L(@"Geo data could not be downloaded")];
        }];
    }];
    [menu addItem:L(@"Russian sites go direct") action:^{
        NSMutableArray *specs = [NSMutableArray array];
        for (NSString *d in [NSArray arrayWithObjects:@"ru", @"su", @"xn--p1ai", @"yandex.net", @"vk.com",
                             @"userapi.com", @"gosuslugi.ru", @"mail.ru", nil])
            [specs addObject:[NSArray arrayWithObjects:@"direct", @"domain-suffix", d, nil]];
        [me addRules:specs];
    }];
    [menu addItem:L(@"Block common ad networks") action:^{
        NSMutableArray *specs = [NSMutableArray array];
        for (NSString *d in [NSArray arrayWithObjects:@"doubleclick.net", @"googlesyndication.com",
                             @"googleadservices.com", @"adservice.google.com", @"app-measurement.com",
                             @"an.yandex.ru", @"adfox.ru", @"mc.yandex.ru", nil])
            [specs addObject:[NSArray arrayWithObjects:@"block", @"domain-suffix", d, nil]];
        [me addRules:specs];
    }];
    [menu addItem:L(@"Local services go direct") action:^{
        [me addRules:[NSArray arrayWithObjects:
            [NSArray arrayWithObjects:@"direct", @"domain-suffix", @"local", nil],
            [NSArray arrayWithObjects:@"direct", @"domain-suffix", @"lan", nil], nil]];
    }];
    [menu showFromView:anchor];
}

- (NSArray *)buildSections {
    __block LRRoutingScreen *me = self;
    LRDaemonSettings *ds = DS();
    BOOL enabled = [ds boolForKey:@"rules_enabled" fallback:YES];
    BOOL direct = [[ds stringForKey:@"rules_default"] isEqualToString:@"direct"];
    NSMutableArray *sections = [NSMutableArray array];
    NSArray *defaults = [NSArray arrayWithObjects:L(@"Proxy: through the tunnel"), L(@"Direct: skip the tunnel"), nil];
    [sections addObject:[LRSectionSpec header:nil rows:[NSArray arrayWithObjects:
        [LRRow toggle:L(@"Enable routing") on:enabled changed:^(BOOL on) {
            [DS() setBool:on forKey:@"rules_enabled"];
            LRRoutingChanged();
        }],
        [LRRow value:L(@"Default action") detail:direct ? L(@"Direct") : L(@"Proxy") action:^(LRRow *r, UIView *c) {
            LRChoiceScreen *choice = [[[LRChoiceScreen alloc] initWithTitle:L(@"Default action") options:defaults
                                                                   selected:direct ? 1 : 0 picked:^(NSInteger i) {
                [DS() setValue:i ? @"direct" : @"proxy" forKey:@"rules_default" done:nil];
                LRRoutingChanged();
            }] autorelease];
            choice.footer = L(@"What happens to names no rule matches. Direct turns the rules into a list of what goes through the tunnel.");
            [me openScreen:choice];
        }],
        [LRRow toggle:L(@"Bypass local networks") on:[ds boolForKey:@"bypass_lan" fallback:YES] changed:^(BOOL on) {
            [DS() setBool:on forKey:@"bypass_lan"];
            LRRoutingChanged();
        }], nil]
                                       footer:L(@"When disabled, all supported traffic uses the selected server. Local networks means LAN, link-local and carrier-grade NAT addresses.")]];
    NSString *activeProfile = [LRRoutingProfiles activeName];
    [sections addObject:[LRSectionSpec header:nil rows:[NSArray arrayWithObjects:
        [LRRow value:L(@"Routing profiles") detail:activeProfile ? activeProfile : L(@"None")
              action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRRoutingProfilesScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Split tunneling") detail:direct ? L(@"Only the list") : L(@"All but the list")
              action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRSitesScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Geo data") detail:@"geosite · geoip" action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRGeoScreen alloc] init] autorelease]];
        }], nil]
                                       footer:nil]];
    NSMutableArray *rules = [NSMutableArray array];
    for (LRRule *rule in _rules) {
        LRRow *row = [LRRow value:rule.value detail:[LRRoutingScreen actionName:rule.action]
                           action:^(LRRow *r, UIView *c) {
            LRMenu *menu = [LRMenu menuWithTitle:rule.value];
            [menu addDestructiveItem:L(@"Delete Rule") action:^{
                LRRoutingScreen *strong = [me retain];
                [[LRDaemonClient shared] deleteRuleIndex:rule.index reply:^(NSString *reply) {
                    if (!LRReplyIsOK(reply))
                        [LRToast showError:LRErrorFromReply(reply) ? LRErrorFromReply(reply) : L(@"Could not delete")];
                    else LRRoutingChanged();
                    [strong loadRules];
                    [strong release];
                }];
            }];
            [menu showFromView:c];
        }];
        row.chevron = NO;
        row.subtitle = [NSString stringWithFormat:@"%@ · %@ %llu", [LRRoutingScreen typeName:rule.type],
                        L(@"hits"), rule.hits];
        LRSkin *s = SKIN;
        row.detailColor = [rule.action isEqualToString:@"block"] ? s->bad
            : ([rule.action isEqualToString:@"direct"] ? s->warn : s->good);
        [rules addObject:row];
    }
    [rules addObject:[LRRow button:L(@"Add Rule") style:LRRowStyleAccent action:^(LRRow *r, UIView *c) {
        [me openScreen:[[[LRRuleEditorScreen alloc] init] autorelease]];
    }]];
    [rules addObject:[LRRow button:L(@"Presets") style:LRRowStyleAccent action:^(LRRow *r, UIView *c) {
        [me presets:c];
    }]];
    [sections addObject:[LRSectionSpec header:L(@"Rules") rows:rules
                                       footer:L(@"Block wins over Direct, and Direct over Proxy. Domain rules act on DNS answers; IP and port rules act in the firewall. Disconnect before changing rules; they apply on the next connect.")]];
    return sections;
}
@end

#pragma mark rule editor

@implementation LRRuleEditorScreen

- (id)init {
    if ((self = [super init])) {
        self.title = L(@"Add Rule");
        _action = [@"direct" copy];
        _type = [@"domain-suffix" copy];
    }
    return self;
}

- (void)dealloc {
    [_action release];
    [_type release];
    [_value release];
    [super dealloc];
}

- (NSString *)example {
    if ([_type isEqualToString:@"domain-suffix"]) return @"example.com";
    if ([_type isEqualToString:@"geosite"]) return @"category-ru";
    if ([_type isEqualToString:@"geoip"]) return @"ru";
    if ([_type isEqualToString:@"domain"]) return @"api.example.com";
    if ([_type isEqualToString:@"domain-keyword"]) return @"example";
    if ([_type isEqualToString:@"ip-cidr"]) return @"203.0.113.0/24";
    return @"8000-8999";
}

- (NSArray *)buildSections {
    __block LRRuleEditorScreen *me = self;
    NSArray *actions = [NSArray arrayWithObjects:@"proxy", @"direct", @"block", nil];
    NSArray *actionNotes = [NSArray arrayWithObjects:L(@"Use Proxy"), L(@"Use Direct"), L(@"Use Block"), nil];
    NSMutableArray *actionRows = [NSMutableArray array];
    for (NSUInteger i = 0; i < [actions count]; ++i) {
        NSString *a = [actions objectAtIndex:i];
        LRRow *row = [LRRow check:[LRRoutingScreen actionName:a] on:[_action isEqualToString:a]
                           action:^(LRRow *r, UIView *c) {
            [me->_action release];
            me->_action = [a copy];
            [me reloadSections];
        }];
        row.subtitle = [actionNotes objectAtIndex:i];
        [actionRows addObject:row];
    }
    NSArray *types = [NSArray arrayWithObjects:@"domain-suffix", @"domain", @"domain-keyword", @"ip-cidr",
                      @"port", @"geosite", @"geoip", nil];
    NSMutableArray *typeRows = [NSMutableArray array];
    for (NSString *t in types) {
        LRRow *row = [LRRow check:[LRRoutingScreen typeName:t] on:[_type isEqualToString:t]
                           action:^(LRRow *r, UIView *c) {
            [me->_type release];
            me->_type = [t copy];
            [me reloadSections];
        }];
        if ([t isEqualToString:@"domain-suffix"]) row.subtitle = L(@"abc.com/* and *.abc.com/*");
        else if ([t isEqualToString:@"domain"]) row.subtitle = L(@"xyz.abc.com/* only");
        [typeRows addObject:row];
    }
    LRRow *value = [LRRow value:L(@"Value") detail:_value ? _value : [NSString stringWithFormat:@"%@: %@", L(@"Example"), [self example]]
                         action:^(LRRow *r, UIView *c) {
        [LRAlert promptTitle:[LRRoutingScreen typeName:me->_type] message:nil placeholder:[me example]
                        text:me->_value button:L(@"OK") done:^(NSString *v) {
            [me->_value release];
            me->_value = [[LRTrim(v) stringByReplacingOccurrencesOfString:@" " withString:@""] copy];
            [me reloadSections];
        }];
    }];
    if (!_value) value.detailColor = SKIN->groupMuted;
    LRRow *save = [LRRow button:L(@"Save Rule") style:LRRowStyleAccent action:^(LRRow *r, UIView *c) {
        if (![me->_value length]) {
            [LRToast showError:L(@"Enter a value first")];
            return;
        }
        /* a name goes in as the daemon matches it: a link is cut to its
           host, an idn name becomes punycode */
        NSString *value = me->_value;
        if ([me->_type isEqualToString:@"domain"] || [me->_type isEqualToString:@"domain-suffix"]) {
            LRSiteKind kind;
            NSString *host = [LRRoutingProfiles siteHost:value kind:&kind wildcard:NULL];
            if (host && kind == LRSiteName) value = host;
        }
        LRRuleEditorScreen *strong = [me retain];
        [[LRDaemonClient shared] addRuleAction:me->_action type:me->_type value:value reply:^(NSString *reply) {
            [strong autorelease];
            if (LRReplyIsOK(reply)) {
                LRLog(@"routing", @"rule added");
                LRRoutingChanged();
                [strong close];
            } else {
                [LRToast showError:LRErrorFromReply(reply) ? LRErrorFromReply(reply) : L(@"Invalid Rule")];
            }
        }];
    }];
    return [NSArray arrayWithObjects:
            [LRSectionSpec header:L(@"Action") rows:actionRows footer:nil],
            [LRSectionSpec header:L(@"Match") rows:typeRows footer:nil],
            [LRSectionSpec header:nil rows:[NSArray arrayWithObjects:value, save, nil]
                           footer:L(@"A head domain matches the name and every name under it, a specific domain only itself. Ports are TCP destination ports, one or a range.")],
            nil];
}
@end

#pragma mark advanced

@implementation LRAdvancedScreen

- (id)init {
    if ((self = [super init])) self.title = L(@"Advanced");
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(reloadSections)
                                                 name:LRDaemonSettingsDidChangeNotification object:nil];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [super dealloc];
}

- (LRRow *)promptRow:(NSString *)title key:(NSString *)key fallback:(NSString *)fallback note:(NSString *)note {
    NSString *v = [DS() stringForKey:key];
    return [LRRow value:title detail:v ? v : fallback action:^(LRRow *r, UIView *c) {
        [LRAlert promptTitle:title message:note placeholder:fallback text:v button:L(@"Save") done:^(NSString *nv) {
            NSString *clean = LRTrim(nv);
            if (!clean) return;
            [DS() setValue:clean forKey:key done:^(BOOL ok, NSString *err) {
                if (!ok) [LRToast showError:L(@"Check the value and try again.")];
                else [LRToast show:L(@"Applied on the next connect.")];
            }];
        }];
    }];
}

- (NSArray *)buildSections {
    __block LRAdvancedScreen *me = self;
    LRDaemonSettings *ds = DS();
    NSArray *blocks = [NSArray arrayWithObjects:@"zero", @"nxdomain", @"refused", nil];
    NSString *block = [ds stringForKey:@"block_response"];
    NSArray *backends = [NSArray arrayWithObjects:@"auto", @"c", @"app_proxy", nil];
    NSArray *backendNames = [NSArray arrayWithObjects:L(@"Automatic"), L(@"Firewall (pf / ipfw)"),
                             L(@"Per-app hook (no firewall)"), nil];
    NSString *backend = [ds stringForKey:@"force_backend"];
    NSUInteger backendIndex = backend ? [backends indexOfObject:backend] : 0;
    NSArray *pfModes = [NSArray arrayWithObjects:@"auto", @"0", @"1", @"2", @"3", @"4", @"5", @"6", @"7", nil];
    NSArray *pfNames = [NSArray arrayWithObjects:L(@"Automatic"), @"route-to lo0", @"route-to lo0 (no gw)",
                        @"divert-to", @"divert-to (old)", @"rdr-to", @"rdr-to (old)", @"legacy rdr", @"compat rdr", nil];
    NSString *pf = [ds stringForKey:@"force_pf_mode"];
    NSUInteger pfIndex = pf ? [pfModes indexOfObject:pf] : 0;
    NSArray *dns = [NSArray arrayWithObjects:
        [self promptRow:L(@"DNS server") key:@"dns_upstream" fallback:@"8.8.8.8"
                   note:L(@"An IPv4 address, for example 1.1.1.1. It is asked through the tunnel.")],
        [self promptRow:L(@"Local DNS port") key:@"dns_local_port" fallback:@"10053" note:nil],
        [LRRow value:L(@"Blocked domains answer") detail:block ? block : @"zero" action:^(LRRow *r, UIView *c) {
            NSUInteger sel = block ? [blocks indexOfObject:block] : 0;
            LRChoiceScreen *choice = [[[LRChoiceScreen alloc] initWithTitle:L(@"Blocked domains answer") options:blocks
                selected:sel == NSNotFound ? 0 : (NSInteger)sel picked:^(NSInteger i) {
                [DS() setValue:[blocks objectAtIndex:(NSUInteger)i] forKey:@"block_response" done:nil];
            }] autorelease];
            [me openScreen:choice];
        }], nil];
    NSArray *proxy = [NSArray arrayWithObjects:
        [self promptRow:L(@"SOCKS port") key:@"socks_port" fallback:@"11080" note:nil],
        [LRRow toggle:L(@"Share SOCKS with the local network") on:[ds boolForKey:@"socks_public" fallback:NO]
              changed:^(BOOL on) { [DS() setBool:on forKey:@"socks_public"]; }], nil];
    NSArray *backendRows = [NSArray arrayWithObjects:
        [LRRow value:L(@"Backend") detail:[backendNames objectAtIndex:backendIndex == NSNotFound ? 0 : backendIndex]
              action:^(LRRow *r, UIView *c) {
            LRChoiceScreen *choice = [[[LRChoiceScreen alloc] initWithTitle:L(@"Backend") options:backendNames
                selected:backendIndex == NSNotFound ? 0 : (NSInteger)backendIndex picked:^(NSInteger i) {
                [DS() setValue:[backends objectAtIndex:(NSUInteger)i] forKey:@"force_backend" done:nil];
            }] autorelease];
            choice.footer = L(@"Automatic tries the firewall first. The per-app hook covers apps MobileSubstrate injects into and is the only way on iOS 4, which has no pf.");
            [me openScreen:choice];
        }],
        [LRRow value:L(@"pf variant") detail:[pfNames objectAtIndex:pfIndex == NSNotFound ? 0 : pfIndex]
              action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRChoiceScreen alloc] initWithTitle:L(@"pf variant") options:pfNames
                selected:pfIndex == NSNotFound ? 0 : (NSInteger)pfIndex picked:^(NSInteger i) {
                [DS() setValue:[pfModes objectAtIndex:(NSUInteger)i] forKey:@"force_pf_mode" done:nil];
            }] autorelease]];
        }],
        [LRRow toggle:L(@"Trace every session") on:[ds boolForKey:@"trace" fallback:NO]
              changed:^(BOOL on) { [DS() setBool:on forKey:@"trace"]; }],
        [LRRow toggle:L(@"Take device-gated feeds") on:[ds boolForKey:@"sub_ignore_gating" fallback:NO]
              changed:^(BOOL on) { [DS() setBool:on forKey:@"sub_ignore_gating"]; }], nil];
    return [NSArray arrayWithObjects:
            [LRSectionSpec header:@"DNS" rows:dns footer:nil],
            [LRSectionSpec header:L(@"Local proxy") rows:proxy
                           footer:L(@"Other devices on the Wi-Fi can use this phone's tunnel through the SOCKS port when shared.")],
            [LRSectionSpec header:L(@"Engine") rows:backendRows
                           footer:L(@"Pin a backend or a pf variant only to track down a problem; Automatic walks the whole ladder.")],
            nil];
}
@end
