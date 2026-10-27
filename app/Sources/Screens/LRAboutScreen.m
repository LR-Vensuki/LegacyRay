#import "LRAboutScreen.h"
#import "LRSimpleScreens.h"
#import "LRUpdateChecker.h"
#import "LRVersion.h"
#import "LRDraw.h"

/* the badge at the top of About: the app icon as the home screen shows it */
@interface LRAboutBadge : UIView
@end

/* the shine ios 6 lays over a home screen icon, so the badge here reads like
   the icon that was tapped. the radius stays outside the badge's own corners */
static void LRDrawIconShine(CGContextRef ctx, CGRect r, CGFloat radius) {
    CGContextSaveGState(ctx);
    LRAddRoundRect(ctx, r, radius);
    CGContextClip(ctx);
    CGContextAddEllipseInRect(ctx, CGRectMake(r.origin.x - r.size.width * 0.45f,
                                              r.origin.y - r.size.height * 0.62f,
                                              r.size.width * 1.9f, r.size.height * 1.14f));
    CGContextClip(ctx);
    CGColorSpaceRef space = CGColorSpaceCreateDeviceRGB();
    CGFloat comps[] = { 1, 1, 1, 0.45f, 1, 1, 1, 0.08f };
    CGFloat locs[] = { 0, 1 };
    CGGradientRef g = CGGradientCreateWithColorComponents(space, comps, locs, 2);
    CGContextDrawLinearGradient(ctx, g, CGPointMake(0, CGRectGetMinY(r)),
                                CGPointMake(0, CGRectGetMinY(r) + r.size.height * 0.52f), 0);
    CGGradientRelease(g);
    CGColorSpaceRelease(space);
    CGContextRestoreGState(ctx);
}

@implementation LRAboutBadge
- (void)drawRect:(CGRect)rect {
    LRSkin *s = SKIN;
    CGRect b = self.bounds;
    /* 72 pt on every device: the 72 and 144 px files, never a 57 px one
       stretched */
    UIImage *icon = [UIImage imageNamed:@"Icon-72.png"];
    CGFloat side = 72;
    CGRect ir = CGRectMake(roundf((b.size.width - side) / 2), 16, side, side);
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    /* the icon carries its own rounded corners; the shadow follows them */
    CGContextSaveGState(ctx);
    CGContextSetShadowWithColor(ctx, CGSizeMake(0, 2), 4, [UIColor colorWithWhite:0 alpha:0.4f].CGColor);
    [icon drawInRect:ir];
    CGContextRestoreGState(ctx);
    if (!s->flat) LRDrawIconShine(ctx, ir, 14);
    UIFont *title = s->flat ? [LRSkin lightFont:24] : [LRSkin titleFont:22];
    LRDrawEngraved(@"LegacyRay", CGRectMake(0, 96, b.size.width, 28), title, NSTextAlignmentCenter,
                   s->groupInk, s->flat ? nil : s->groupHeaderShadow, 1);
    NSString *v = [NSString stringWithFormat:L(@"Version %@ (%@)"), @LR_VERSION, @LR_BUILD_NUMBER];
    LRDrawEngraved(v, CGRectMake(0, 126, b.size.width, 18), [LRSkin bodyFont:13], NSTextAlignmentCenter,
                   s->groupMuted, nil, 0);
    LRDrawEngraved(@LR_DEVELOPER, CGRectMake(0, 145, b.size.width, 18), [LRSkin bodyFont:13],
                   NSTextAlignmentCenter, s->groupMuted, nil, 0);
}
@end

@implementation LRAboutScreen

- (id)init {
    if ((self = [super init])) self.title = L(@"About");
    return self;
}

- (void)viewDidLoad {
    LRAboutBadge *badge = [[[LRAboutBadge alloc] initWithFrame:CGRectMake(0, 0, 320, 170)] autorelease];
    badge.backgroundColor = [UIColor clearColor];
    badge.contentMode = UIViewContentModeRedraw;
    [self setTableHeaderView:badge];
    [super viewDidLoad];
}

- (NSArray *)buildSections {
    __block LRAboutScreen *me = self;
    NSArray *info = [NSArray arrayWithObjects:
        [LRRow text:L(@"A full-device VLESS, VMess, Trojan, Shadowsocks, SOCKS and AmneziaWG client for jailbroken iOS 4 to 7.")],
        [LRRow value:L(@"Common questions") detail:nil action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRFAQScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Credits") detail:nil action:^(LRRow *r, UIView *c) {
            [me openScreen:[[[LRCreditsScreen alloc] init] autorelease]];
        }],
        [LRRow value:L(@"Project on GitHub") detail:@LR_GITHUB_REPO action:^(LRRow *r, UIView *c) {
            [LRUpdateChecker openProjectPage];
        }], nil];
    NSString *path = [[NSBundle mainBundle] pathForResource:@"LICENSE" ofType:@"txt"];
    NSString *third = [[NSBundle mainBundle] pathForResource:@"THIRD_PARTY_LICENSES" ofType:@"txt"];
    NSArray *legal = [NSArray arrayWithObjects:
        [LRRow value:L(@"License") detail:@"GPL-2.0" action:^(LRRow *r, UIView *c) {
            NSString *text = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
            [me openScreen:[[[LRTextScreen alloc] initWithTitle:L(@"License") text:text] autorelease]];
        }],
        [LRRow value:L(@"Third-party software") detail:nil action:^(LRRow *r, UIView *c) {
            NSString *text = [NSString stringWithContentsOfFile:third encoding:NSUTF8StringEncoding error:NULL];
            [me openScreen:[[[LRTextScreen alloc] initWithTitle:L(@"Third-party software") text:text] autorelease]];
        }], nil];
    return [NSArray arrayWithObjects:
            [LRSectionSpec header:nil rows:info footer:nil],
            [LRSectionSpec header:L(@"Legal") rows:legal
                           footer:L(@"LegacyRay is made by the LegacyReborn Project. It is a fork of senko by sqmrak and is distributed under the GNU General Public License, version 2.")],
            nil];
}
@end

@implementation LRFAQScreen

- (id)init {
    if ((self = [super init])) self.title = L(@"Common questions");
    return self;
}

- (NSArray *)buildSections {
    NSArray *qa = [NSArray arrayWithObjects:
        L(@"How do I import?"),
        L(@"Tap + (on the main screen or in the server list) and paste from the clipboard, scan a QR code, type or paste manually, add a subscription URL or pick a file. vless://, vmess://, trojan://, ss://, socks5://, happ:// links, subscription URLs, base64 lists, Xray and sing-box JSON, Clash YAML, WireGuard / AmneziaWG profiles and Karing backups (zip or LAN send QR) all work."),
        L(@"Which devices are supported?"),
        L(@"Any jailbroken iPhone, iPod touch or iPad on iOS 4.0 to 7.x. iOS 5 and later redirect the whole device through the pf firewall; on iOS 4 there is no pf, so apps are redirected by the MobileSubstrate hook."),
        L(@"Why can't I connect?"),
        L(@"Open Setup > Diagnostics > Connection quality. It checks the daemon, the network, DNS, the handshake with the server and HTTP through the tunnel, and names the step that fails. The daemon log shows the server's own answer."),
        L(@"Does closing the app stop the VPN?"),
        L(@"No. The tunnel belongs to the background daemon; the app is only its front panel. Reconnect automatically keeps it up across network changes."),
        L(@"How does routing work?"),
        L(@"Rules send domains, addresses and ports through the tunnel (Proxy), around it (Direct) or nowhere (Block). Block wins over Direct and Direct over Proxy. With the default action set to Direct, only what your rules name goes through the tunnel."),
        L(@"What does auto-update do?"),
        L(@"The daemon refreshes every subscription on the schedule you pick, even while the app is closed. Refresh on app open does it each time you open LegacyRay."),
        L(@"What does Stealth mode hide?"),
        L(@"Server addresses, links, device IDs and IP addresses on every screen and in reports, so a screenshot shows nothing private."),
        L(@"Where are the subscription details?"),
        L(@"Long press a subscription's plate in the server list and choose Subscription info: traffic, dates, the provider's page and support links."),
        L(@"How do I delete or reorder items?"),
        L(@"Long press a server or a plate for its menu. Arrange in the ... menu lets you drag subscriptions and manual servers."),
        L(@"Where can I find the logs?"),
        L(@"Setup > Diagnostics: the daemon log, the firewall rules, the activity journal and a privacy-safe report you can mail or save."),
        nil];
    NSMutableArray *sections = [NSMutableArray array];
    for (NSUInteger i = 0; i + 1 < [qa count]; i += 2)
        [sections addObject:[LRSectionSpec header:[qa objectAtIndex:i]
                                             rows:[NSArray arrayWithObject:[LRRow text:[qa objectAtIndex:i + 1]]]
                                           footer:nil]];
    return sections;
}
@end

@implementation LRCreditsScreen

- (id)init {
    if ((self = [super init])) self.title = L(@"Credits");
    return self;
}

- (NSArray *)buildSections {
    LRRow *(^credit)(NSString *, NSString *) = ^LRRow *(NSString *name, NSString *what) {
        LRRow *r = [LRRow value:name detail:nil action:nil];
        r.subtitle = what;
        return r;
    };
    NSArray *base = [NSArray arrayWithObjects:
        credit(@"senko", L(@"by sqmrak: the daemon, the VLESS / Reality / XHTTP / gRPC stack, AmneziaWG, the routing engine. GPL-2.0.")),
        credit(@"vless-core-app", L(@"by notfence: the feature set LegacyRay follows. No code is taken from it.")),
        credit(@"Happ · Amnezia VPN", L(@"The routing profiles, split tunnelling and own-server setup follow their ideas. No code is taken from them.")), nil];
    NSArray *libs = [NSArray arrayWithObjects:
        credit(@"OpenSSL", L(@"TLS and cryptography for the daemon. Apache 2.0.")),
        credit(@"Mbed TLS", L(@"Modern TLS inside old apps (the TLS hook). Apache 2.0.")),
        credit(@"ZBar", L(@"QR code recognition. LGPL-2.1.")),
        credit(@"cJSON", L(@"JSON parsing. MIT.")),
        credit(@"fishhook", L(@"Symbol rebinding for the connect hook. BSD.")),
        credit(@"libssh2", L(@"SSH for setting up your own server. BSD.")),
        credit(@"v2fly domain-list-community · ipverse", L(@"Geosite and geoip data, downloaded when your rules ask for it.")),
        credit(@"Mozilla CA bundle", L(@"Root certificates for old systems. MPL 2.0.")), nil];
    return [NSArray arrayWithObjects:
            [LRSectionSpec header:L(@"Special thanks") rows:base footer:nil],
            [LRSectionSpec header:L(@"Bundled components") rows:libs footer:nil], nil];
}
@end
