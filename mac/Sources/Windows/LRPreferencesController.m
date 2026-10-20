#import "LRPreferencesController.h"
#import "LRAppDelegate.h"
#import "LRForm.h"
#import "LRBlocks.h"
#import "LRDraw.h"
#import "LRAlert.h"
#import "LRToast.h"
#import "LRTunnel.h"
#import "LRCatalog.h"
#import "LRModels.h"
#import "LRDaemonClient.h"
#import "LRDaemonSettings.h"
#import "LRRoutingProfiles.h"
#import "LRReminders.h"
#import "LRActivityLog.h"
#import "LRHelperInstaller.h"
#import "LRImporter.h"
#import "LRNetInfo.h"
#import "LRVersion.h"
#include "senko_paths.h"

static LRDaemonSettings *DS(void) { return [LRDaemonSettings shared]; }

static void LRRoutingChanged(void) {
    if ([[LRTunnel shared] isOn]) [LRToast show:L(@"Reconnect the VPN to apply routing changes.")];
}

#define LR_PANE_WIDTH 640.0f

#pragma mark icons

/* the pane icons that have no system picture: a glossy coloured ball with a
   white glyph, as 10.8 drew them; a flat disc on yosemite */
static NSImage *LRPaneIcon(NSColor *color, void (^glyph)(CGContextRef ctx, CGFloat side)) {
    NSColor *c = [[color copy] autorelease];
    void (^g)(CGContextRef, CGFloat) = [[glyph copy] autorelease];
    BOOL flat = SKIN->flat;
    return LRImageWithSize(NSMakeSize(32, 32), YES, ^(CGContextRef ctx, CGRect r) {
        CGRect disc = CGRectMake(3, 2.5f, 26, 26);
        if (!flat) {
            CGContextSaveGState(ctx);
            CGContextSetShadowWithColor(ctx, CGSizeMake(0, 1.2f), 1.5f,
                                        [[NSColor colorWithCalibratedWhite:0 alpha:0.45f] CGColor]);
            [LRColorMix(c, [NSColor blackColor], 0.25f) setFill];
            CGContextFillEllipseInRect(ctx, disc);
            CGContextRestoreGState(ctx);
            CGContextSaveGState(ctx);
            CGContextAddEllipseInRect(ctx, CGRectInset(disc, 0.5f, 0.5f));
            CGContextClip(ctx);
            LRFillVertical(ctx, disc, LRColorMix(c, [NSColor whiteColor], 0.25f), LRColorMix(c, [NSColor blackColor], 0.2f));
            LRFillRadial(ctx, CGPointMake(16, 27), 0, 13, LRColorAlpha(LRColorMix(c, [NSColor whiteColor], 0.5f), 0.7f),
                         [NSColor colorWithCalibratedWhite:1 alpha:0]);
            /* the gloss cap */
            LRFillVertical(ctx, CGRectMake(6, 3.5f, 20, 11), [NSColor colorWithCalibratedWhite:1 alpha:0.6f],
                           [NSColor colorWithCalibratedWhite:1 alpha:0.05f]);
            CGContextRestoreGState(ctx);
        } else {
            [c setFill];
            CGContextFillEllipseInRect(ctx, disc);
        }
        CGContextSaveGState(ctx);
        if (!flat) CGContextSetShadowWithColor(ctx, CGSizeMake(0, -0.8f), 0.8f,
                                               [[NSColor colorWithCalibratedWhite:0 alpha:0.5f] CGColor]);
        CGContextSetRGBStrokeColor(ctx, 1, 1, 1, 1);
        CGContextSetRGBFillColor(ctx, 1, 1, 1, 1);
        CGContextSetLineCap(ctx, kCGLineCapRound);
        CGContextSetLineJoin(ctx, kCGLineJoinRound);
        g(ctx, 32);
        CGContextRestoreGState(ctx);
    });
}

static NSImage *LRIconConnection(void) {
    return LRPaneIcon([NSColor colorWithCalibratedRed:0.22f green:0.62f blue:0.27f alpha:1], ^(CGContextRef ctx, CGFloat s) {
        CGContextSetLineWidth(ctx, 2.4f);
        CGContextAddArc(ctx, 16, 16, 7, (CGFloat)-M_PI_2 + 0.75f, (CGFloat)-M_PI_2 - 0.75f + (CGFloat)M_PI * 2, 0);
        CGContextStrokePath(ctx);
        CGContextMoveToPoint(ctx, 16, 7.5f);
        CGContextAddLineToPoint(ctx, 16, 14);
        CGContextStrokePath(ctx);
    });
}

static NSImage *LRIconRouting(void) {
    return LRPaneIcon([NSColor colorWithCalibratedRed:0.16f green:0.42f blue:0.85f alpha:1], ^(CGContextRef ctx, CGFloat s) {
        /* one road splitting in two */
        CGContextSetLineWidth(ctx, 2.2f);
        CGContextMoveToPoint(ctx, 16, 25);
        CGContextAddLineToPoint(ctx, 16, 17);
        CGContextAddLineToPoint(ctx, 10, 10);
        CGContextMoveToPoint(ctx, 16, 17);
        CGContextAddLineToPoint(ctx, 22, 10);
        CGContextStrokePath(ctx);
        for (int i = 0; i < 2; ++i) {
            CGFloat x = i ? 22 : 10, dir = i ? 1 : -1;
            CGContextMoveToPoint(ctx, x + dir * 1.5f, 7);
            CGContextAddLineToPoint(ctx, x - dir * 3.8f, 8.8f);
            CGContextAddLineToPoint(ctx, x + dir * 0.4f, 12.6f);
            CGContextClosePath(ctx);
            CGContextFillPath(ctx);
        }
    });
}

static NSImage *LRIconSites(void) {
    return LRPaneIcon([NSColor colorWithCalibratedRed:0.92f green:0.52f blue:0.12f alpha:1], ^(CGContextRef ctx, CGFloat s) {
        CGContextSetLineWidth(ctx, 1.8f);
        for (int i = 0; i < 3; ++i) {
            CGFloat y = 10.5f + i * 5.5f;
            CGContextFillEllipseInRect(ctx, CGRectMake(8.5f, y - 1.6f, 3.2f, 3.2f));
            CGContextMoveToPoint(ctx, 14, y);
            CGContextAddLineToPoint(ctx, 23.5f, y);
        }
        CGContextStrokePath(ctx);
    });
}

static NSImage *LRIconSubscriptions(void) {
    return LRPaneIcon([NSColor colorWithCalibratedRed:0.55f green:0.30f blue:0.80f alpha:1], ^(CGContextRef ctx, CGFloat s) {
        CGContextSetLineWidth(ctx, 2.2f);
        CGContextAddArc(ctx, 16, 16, 6.5f, (CGFloat)M_PI * 0.15f, (CGFloat)M_PI * 1.15f, 0);
        CGContextStrokePath(ctx);
        CGContextAddArc(ctx, 16, 16, 6.5f, (CGFloat)M_PI * 1.15f + 0.6f, (CGFloat)M_PI * 2.15f + 0.6f - 0.6f, 0);
        CGContextStrokePath(ctx);
        CGContextMoveToPoint(ctx, 21.5f, 22);
        CGContextAddLineToPoint(ctx, 25, 18.5f);
        CGContextAddLineToPoint(ctx, 20.5f, 17.5f);
        CGContextClosePath(ctx);
        CGContextFillPath(ctx);
    });
}

#pragma mark login item

static LSSharedFileListItemRef LRLoginItemCopy(LSSharedFileListRef list) CF_RETURNS_RETAINED;
static LSSharedFileListItemRef LRLoginItemCopy(LSSharedFileListRef list) {
    NSURL *me = [NSURL fileURLWithPath:[[NSBundle mainBundle] bundlePath]];
    UInt32 seed = 0;
    NSArray *items = [(NSArray *)LSSharedFileListCopySnapshot(list, &seed) autorelease];
    for (id i in items) {
        LSSharedFileListItemRef item = (LSSharedFileListItemRef)i;
        CFURLRef url = NULL;
        if (LSSharedFileListItemResolve(item, kLSSharedFileListNoUserInteraction | kLSSharedFileListDoNotMountVolumes,
                                        &url, NULL) == noErr && url) {
            BOOL same = [[(NSURL *)url path] isEqualToString:[me path]];
            CFRelease(url);
            if (same) return (LSSharedFileListItemRef)CFRetain(item);
        }
    }
    return NULL;
}

static BOOL LROpensAtLogin(void) {
    LSSharedFileListRef list = LSSharedFileListCreate(NULL, kLSSharedFileListSessionLoginItems, NULL);
    if (!list) return NO;
    LSSharedFileListItemRef item = LRLoginItemCopy(list);
    BOOL on = item != NULL;
    if (item) CFRelease(item);
    CFRelease(list);
    return on;
}

static void LRSetOpensAtLogin(BOOL on) {
    LSSharedFileListRef list = LSSharedFileListCreate(NULL, kLSSharedFileListSessionLoginItems, NULL);
    if (!list) return;
    LSSharedFileListItemRef item = LRLoginItemCopy(list);
    if (on && !item) {
        NSURL *me = [NSURL fileURLWithPath:[[NSBundle mainBundle] bundlePath]];
        LSSharedFileListItemRef added = LSSharedFileListInsertItemURL(list, kLSSharedFileListItemLast, NULL, NULL,
                                                                      (CFURLRef)me, NULL, NULL);
        if (added) CFRelease(added);
    } else if (!on && item) {
        LSSharedFileListItemRemove(list, item);
    }
    if (item) CFRelease(item);
    CFRelease(list);
}

#pragma mark the controller

@implementation LRPreferencesController

- (id)init {
    NSWindow *w = [[[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, LR_PANE_WIDTH, 300)
                                               styleMask:NSTitledWindowMask | NSClosableWindowMask |
                                                         NSMiniaturizableWindowMask
                                                 backing:NSBackingStoreBuffered defer:YES] autorelease];
    [w setReleasedWhenClosed:NO];
    if ((self = [super initWithWindow:w])) {
        NSToolbar *tb = [[[NSToolbar alloc] initWithIdentifier:@"LRPreferences"] autorelease];
        [tb setDelegate:self];
        [tb setAllowsUserCustomization:NO];
        [tb setDisplayMode:NSToolbarDisplayModeIconAndLabel];
        [w setToolbar:tb];
        if ([w respondsToSelector:@selector(setShowsToolbarButton:)]) [w setShowsToolbarButton:NO];
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        [nc addObserver:self selector:@selector(settingsChanged) name:LRDaemonSettingsDidChangeNotification object:nil];
        [nc addObserver:self selector:@selector(settingsChanged) name:LRRoutingProfilesDidChangeNotification object:nil];
        NSString *last = [[NSUserDefaults standardUserDefaults] stringForKey:@"LRPrefsPane"];
        [self selectPane:[[self toolbarAllowedItemIdentifiers:tb] containsObject:last] ? last : @"general"];
        [w center];
        [DS() refresh];
        [self loadRules];
        [[LRDaemonClient shared] deviceHWID:^(NSString *hwid) {
            [_hwid release];
            _hwid = [hwid copy];
            if ([_pane isEqualToString:@"subs"]) [self rebuildPane];
        }];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_rulesTable setDataSource:nil];
    [_rulesTable setDelegate:nil];
    [_sitesTable setDataSource:nil];
    [_sitesTable setDelegate:nil];
    [_pane release];
    [_current release];
    [_rules release];
    [_sites release];
    [_rulesTable release];
    [_sitesTable release];
    [_hwid release];
    [super dealloc];
}

#pragma mark toolbar

- (NSArray *)paneIdentifiers {
    return [NSArray arrayWithObjects:@"general", @"connection", @"routing", @"sites", @"subs", @"network",
            @"advanced", nil];
}

- (NSArray *)toolbarAllowedItemIdentifiers:(NSToolbar *)toolbar {
    return [self paneIdentifiers];
}

- (NSArray *)toolbarDefaultItemIdentifiers:(NSToolbar *)toolbar {
    return [self paneIdentifiers];
}

- (NSArray *)toolbarSelectableItemIdentifiers:(NSToolbar *)toolbar {
    return [self paneIdentifiers];
}

- (NSString *)titleForPane:(NSString *)p {
    if ([p isEqualToString:@"general"]) return L(@"General");
    if ([p isEqualToString:@"connection"]) return L(@"Connection");
    if ([p isEqualToString:@"routing"]) return L(@"Routing");
    if ([p isEqualToString:@"sites"]) return L(@"Sites");
    if ([p isEqualToString:@"subs"]) return L(@"Subscriptions");
    if ([p isEqualToString:@"network"]) return L(@"Network");
    return L(@"Advanced");
}

- (NSImage *)iconForPane:(NSString *)p {
    if ([p isEqualToString:@"general"]) return [NSImage imageNamed:NSImageNamePreferencesGeneral];
    if ([p isEqualToString:@"connection"]) return LRIconConnection();
    if ([p isEqualToString:@"routing"]) return LRIconRouting();
    if ([p isEqualToString:@"sites"]) return LRIconSites();
    if ([p isEqualToString:@"subs"]) return LRIconSubscriptions();
    if ([p isEqualToString:@"network"]) return [NSImage imageNamed:NSImageNameNetwork];
    return [NSImage imageNamed:NSImageNameAdvanced];
}

- (NSToolbarItem *)toolbar:(NSToolbar *)toolbar itemForItemIdentifier:(NSString *)ident
 willBeInsertedIntoToolbar:(BOOL)flag {
    NSToolbarItem *item = [[[NSToolbarItem alloc] initWithItemIdentifier:ident] autorelease];
    [item setLabel:[self titleForPane:ident]];
    [item setImage:[self iconForPane:ident]];
    [item setTarget:self];
    [item setAction:@selector(toolbarPicked:)];
    return item;
}

- (void)toolbarPicked:(NSToolbarItem *)item {
    [self selectPane:[item itemIdentifier]];
}

- (void)selectPane:(NSString *)identifier {
    if ([identifier isEqualToString:_pane] && _current) return;
    [_pane release];
    _pane = [identifier copy];
    [[[self window] toolbar] setSelectedItemIdentifier:identifier];
    [[NSUserDefaults standardUserDefaults] setObject:identifier forKey:@"LRPrefsPane"];
    [[self window] setTitle:[self titleForPane:identifier]];
    [self rebuildPane];
}

/* the window grows or shrinks to the pane, keeping its top edge */
- (void)rebuildPane {
    NSWindow *w = [self window];
    NSView *pane = [self buildPane:_pane];
    NSRect content = [w contentRectForFrameRect:[w frame]];
    NSRect frame = [w frame];
    CGFloat dh = NSHeight([pane frame]) - NSHeight(content);
    frame.origin.y -= dh;
    frame.size.height += dh;
    BOOL animate = _current != nil && [w isVisible] && !_refreshing;
    /* a pane taller than the screen scrolls inside a window that fits */
    NSScreen *screen = [w screen] ? [w screen] : [NSScreen mainScreen];
    CGFloat chrome = NSHeight([w frame]) - NSHeight(content);
    CGFloat room = NSHeight([screen visibleFrame]) - chrome - 20;
    NSView *holder;
    if (NSHeight([pane frame]) > room) {
        NSScrollView *scroll = [[[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, LR_PANE_WIDTH, room)] autorelease];
        [scroll setHasVerticalScroller:YES];
        [scroll setBorderType:NSNoBorder];
        [scroll setDrawsBackground:NO];
        [pane setFrameSize:NSMakeSize(LR_PANE_WIDTH - 16, NSHeight([pane frame]))];
        [scroll setDocumentView:pane];
        holder = scroll;
        frame.origin.y += NSHeight([pane frame]) - room;
        frame.size.height -= NSHeight([pane frame]) - room;
    } else {
        holder = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, LR_PANE_WIDTH, NSHeight([pane frame]))] autorelease];
        [holder addSubview:pane];
        [pane setFrameOrigin:NSZeroPoint];
    }
    /* never above the menu bar */
    CGFloat top = NSMaxY([screen visibleFrame]);
    if (NSMaxY(frame) > top) frame.origin.y = top - NSHeight(frame);
    if (animate) {
        [w setContentView:[[[NSView alloc] initWithFrame:[[w contentView] frame]] autorelease]];
        [w setFrame:frame display:YES animate:YES];
    } else {
        [w setFrame:frame display:NO];
    }
    [w setContentView:holder];
    [_current release];
    _current = [pane retain];
}

- (void)settingsChanged {
    /* a field being typed into keeps its text; the rest follows the daemon */
    id first = [[self window] firstResponder];
    if ([first isKindOfClass:[NSTextView class]] && [(NSTextView *)first isFieldEditor]) return;
    _refreshing = YES;
    [self rebuildPane];
    _refreshing = NO;
}

- (NSView *)buildPane:(NSString *)p {
    if ([p isEqualToString:@"connection"]) return [self connectionPane];
    if ([p isEqualToString:@"routing"]) return [self routingPane];
    if ([p isEqualToString:@"sites"]) return [self sitesPane];
    if ([p isEqualToString:@"subs"]) return [self subscriptionsPane];
    if ([p isEqualToString:@"network"]) return [self networkPane];
    if ([p isEqualToString:@"advanced"]) return [self advancedPane];
    return [self generalPane];
}

- (LRForm *)form {
    return [[[LRForm alloc] initWithWidth:LR_PANE_WIDTH labelWidth:215] autorelease];
}

#pragma mark general

- (NSView *)generalPane {
    LRForm *f = [self form];
    NSArray *themes = [NSArray arrayWithObjects:L(@"Automatic"), L(@"Classic"), L(@"Flat"), nil];
    LRThemeSetting theme = [LRPrefs theme];
    NSInteger ti = theme == LRThemeFlat ? 2 : (theme == LRThemeClassic ? 1 : 0);
    [f addLabel:L(@"Theme") popup:themes selected:ti changed:^(NSInteger i) {
        LRThemeSetting picked[3] = { LRThemeAuto, LRThemeClassic, LRThemeFlat };
        [LRPrefs setTheme:picked[i < 0 || i > 2 ? 0 : i]];
        [[LRAppDelegate shared] performSelector:@selector(rebuildInterface) withObject:nil afterDelay:0.1];
    }];
    [f addNote:L(@"Automatic is denim on OS X 10.8 and 10.9 and flat from Yosemite on. Classic: the black denim of the icon with a copper seam. Flat: white, vibrant and thin, like Yosemite.")];
    NSArray *langs = [NSArray arrayWithObjects:LRLanguageName(LRLanguageAuto), @"English", @"Русский", @"中文", nil];
    [f addLabel:L(@"Language") popup:langs selected:LRLanguageSetting() changed:^(NSInteger i) {
        LRSetLanguageSetting((LRLanguage)i);
    }];
    NSArray *sorts = [NSArray arrayWithObjects:L(@"As added"), L(@"By name"), L(@"By latency"), nil];
    [f addLabel:L(@"Sort servers") popup:sorts selected:[LRPrefs sortMode] changed:^(NSInteger i) {
        [LRPrefs setSortMode:(LRSortMode)i];
    }];
    [f addSeparator];
    id statusPref = [[NSUserDefaults standardUserDefaults] objectForKey:@"LRStatusItem"];
    [f addCheckBox:L(@"Show LegacyRay in the menu bar") on:statusPref ? [statusPref boolValue] : YES changed:^(BOOL on) {
        [[NSUserDefaults standardUserDefaults] setBool:on forKey:@"LRStatusItem"];
        [[NSNotificationCenter defaultCenter] postNotificationName:LRPrefsDidChangeNotification object:nil];
    }];
    [f addCheckBox:L(@"Open LegacyRay at login") on:LROpensAtLogin() changed:^(BOOL on) {
        LRSetOpensAtLogin(on);
    }];
    [f addCheckBox:L(@"Sounds") on:[LRPrefs soundEffects] changed:^(BOOL on) { [LRPrefs setSoundEffects:on]; }];
    [f addSeparator];
    [f addCheckBox:L(@"Stealth mode") on:[LRPrefs stealthMode] changed:^(BOOL on) { [LRPrefs setStealthMode:on]; }];
    [f addCheckBox:L(@"Record app activity") on:[LRPrefs activityLogging] changed:^(BOOL on) {
        [LRPrefs setActivityLogging:on];
    }];
    [f addNote:L(@"Stealth mode hides addresses, links and keys on screen and in reports, for screenshots.")];
    [f addCheckBox:L(@"Check for updates once a day") on:[LRPrefs automaticUpdateChecks] changed:^(BOOL on) {
        [LRPrefs setAutomaticUpdateChecks:on];
    }];
    [f finish];
    return f;
}

#pragma mark connection

- (NSView *)connectionPane {
    LRForm *f = [self form];
    LRDaemonSettings *ds = DS();
    [f addCheckBox:L(@"Reconnect automatically") on:[ds boolForKey:@"auto_reconnect" fallback:YES] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"auto_reconnect"];
    }];
    [f addCheckBox:L(@"Connect at startup") on:[ds boolForKey:@"auto_connect" fallback:NO] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"auto_connect"];
    }];
    [f addCheckBox:L(@"Failover to the next server") on:[ds boolForKey:@"failover" fallback:NO] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"failover"];
    }];
    [f addNote:L(@"The tunnel lives in the system service: it stays up when this window is closed or the app quits, and comes back after a restart of the Mac when Connect at startup is on. Failover walks the same subscription when a server will not come up.")];
    NSInteger attempts = [ds integerForKey:@"reconnect_max_attempts" fallback:5];
    NSArray *attemptValues = [NSArray arrayWithObjects:@"0", @"3", @"5", @"10", @"20", nil];
    NSArray *attemptNames = [NSArray arrayWithObjects:L(@"Until it works"), @"3", @"5", @"10", @"20", nil];
    NSUInteger ai = [attemptValues indexOfObject:[NSString stringWithFormat:@"%ld", (long)attempts]];
    [f addLabel:L(@"Reconnect attempts") popup:attemptNames selected:ai == NSNotFound ? 2 : (NSInteger)ai
        changed:^(NSInteger i) {
        [DS() setValue:[attemptValues objectAtIndex:(NSUInteger)i] forKey:@"reconnect_max_attempts" done:nil];
    }];
    NSArray *pingNames = [NSArray arrayWithObjects:L(@"TCP connect"), L(@"TLS / Reality handshake"),
                          L(@"Real delay (HTTP through the server)"), nil];
    [f addLabel:L(@"Ping type") popup:pingNames selected:[LRPrefs pingType] changed:^(NSInteger i) {
        [LRPrefs setPingType:(LRPingType)i];
        [[LRCatalog shared] forgetPings];
    }];
    [f addSeparator];
    [f addHeader:L(@"Getting past blocking")];
    BOOL frag = [ds boolForKey:@"fragment" fallback:NO];
    [f addCheckBox:L(@"Fragment the TLS handshake") on:frag changed:^(BOOL on) {
        [DS() setBool:on forKey:@"fragment"];
    }];
    NSString *fragSize = [ds stringForKey:@"fragment_size"];
    NSArray *sizeValues = [NSArray arrayWithObjects:@"10-30", @"50-100", @"100-200", @"200-400", nil];
    NSMutableArray *sizeNames = [NSMutableArray array];
    for (NSString *v in sizeValues) [sizeNames addObject:[NSString stringWithFormat:L(@"%@ bytes"), v]];
    NSUInteger si = fragSize ? [sizeValues indexOfObject:fragSize] : 2;
    NSPopUpButton *size = [f addLabel:L(@"Fragment size") popup:sizeNames selected:si == NSNotFound ? 2 : (NSInteger)si
                              changed:^(NSInteger i) {
        [DS() setValue:[sizeValues objectAtIndex:(NSUInteger)i] forKey:@"fragment_size" done:nil];
    }];
    NSInteger fragDelay = [ds integerForKey:@"fragment_delay" fallback:10];
    NSArray *delayValues = [NSArray arrayWithObjects:@"0", @"5", @"10", @"20", @"50", nil];
    NSMutableArray *delayNames = [NSMutableArray array];
    for (NSString *v in delayValues) [delayNames addObject:[NSString stringWithFormat:L(@"%@ ms"), v]];
    NSUInteger di = [delayValues indexOfObject:[NSString stringWithFormat:@"%ld", (long)fragDelay]];
    NSPopUpButton *delay = [f addLabel:L(@"Pause between fragments") popup:delayNames
                              selected:di == NSNotFound ? 2 : (NSInteger)di changed:^(NSInteger i) {
        [DS() setValue:[delayValues objectAtIndex:(NSUInteger)i] forKey:@"fragment_delay" done:nil];
    }];
    [size setEnabled:frag];
    [delay setEnabled:frag];
    [f addNote:L(@"Sends the first packet of every TLS and Reality connection in small pieces, so filters that read the server name out of it see only part of it. Each new connection starts a little slower.")];
    [f addCheckBox:L(@"Prefer ChaCha20") on:[ds boolForKey:@"prefer_chacha" fallback:YES] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"prefer_chacha"];
    }];
    [f addNote:L(@"Asks the server for ChaCha20 first. Macs without AES instructions (Core 2 and older) spend less of the battery on it; newer ones do either fast.")];
    [f addSeparator];
    NSArray *kaNames = [NSArray arrayWithObjects:L(@"As in the profile"), L(@"Only while the screen is on"), L(@"Off"), nil];
    [f addLabel:L(@"AmneziaWG keepalive") popup:kaNames selected:[LRPrefs awgKeepalive] changed:^(NSInteger i) {
        [LRPrefs setAWGKeepalive:(LRAWGKeepaliveMode)i];
    }];
    [f finish];
    return f;
}

#pragma mark routing

- (void)loadRules {
    [[LRDaemonClient shared] listRules:^(NSArray *rules) {
        [_rules release];
        _rules = [rules retain];
        [self rebuildSites];
        [_rulesTable reloadData];
        [_sitesTable reloadData];
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

- (NSTableView *)tableWithColumns:(NSArray *)columns {
    NSTableView *t = [[[NSTableView alloc] initWithFrame:NSMakeRect(0, 0, 400, 200)] autorelease];
    for (NSArray *c in columns) {
        NSTableColumn *col = [[[NSTableColumn alloc] initWithIdentifier:[c objectAtIndex:0]] autorelease];
        [[col headerCell] setStringValue:[c objectAtIndex:1]];
        [col setWidth:[[c objectAtIndex:2] floatValue]];
        [col setEditable:NO];
        [t addTableColumn:col];
    }
    [t setUsesAlternatingRowBackgroundColors:YES];
    [t setColumnAutoresizingStyle:NSTableViewLastColumnOnlyAutoresizingStyle];
    [t setAllowsMultipleSelection:YES];
    [t setDataSource:self];
    [t setDelegate:self];
    return t;
}

- (NSScrollView *)scrollFor:(NSTableView *)t {
    NSScrollView *s = [[[NSScrollView alloc] initWithFrame:NSMakeRect(0, 0, 400, 200)] autorelease];
    [s setDocumentView:t];
    [s setHasVerticalScroller:YES];
    [s setBorderType:NSBezelBorder];
    return s;
}

/* the + / − segmented pair under a list, like system preferences */
- (NSSegmentedControl *)addRemoveControl:(void (^)(NSInteger segment))picked {
    NSSegmentedControl *seg = [[[NSSegmentedControl alloc] initWithFrame:NSMakeRect(0, 0, 60, 23)] autorelease];
    [seg setSegmentCount:2];
    [seg setImage:[NSImage imageNamed:NSImageNameAddTemplate] forSegment:0];
    [seg setImage:[NSImage imageNamed:NSImageNameRemoveTemplate] forSegment:1];
    [seg setWidth:28 forSegment:0];
    [seg setWidth:28 forSegment:1];
    [[seg cell] setTrackingMode:NSSegmentSwitchTrackingMomentary];
    if ([seg respondsToSelector:@selector(setSegmentStyle:)]) [seg setSegmentStyle:NSSegmentStyleSmallSquare];
    void (^cb)(NSInteger) = [[picked copy] autorelease];
    [seg lr_setBlock:^(id sender) { cb([sender selectedSegment]); }];
    return seg;
}

- (void)addRuleSpecs:(NSArray *)specs {
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
        if (![rest count]) LRRoutingChanged();
        [self addRuleSpecs:rest];
    }];
}

- (void)presetsMenuFrom:(NSView *)anchor {
    __block LRPreferencesController *me = self;
    NSMenu *menu = [[[NSMenu alloc] initWithTitle:@""] autorelease];
    void (^geo)(void) = ^{
        [[LRDaemonClient shared] geoUpdate:^(NSArray *lines, NSString *summary, BOOL ok) {
            if (!ok) [LRToast showError:summary ? summary : L(@"Geo data could not be downloaded")];
        }];
    };
    [menu lr_addItem:L(@"Russian sites and addresses go direct (geo)") block:^{
        [me addRuleSpecs:[NSArray arrayWithObjects:
            [NSArray arrayWithObjects:@"direct", @"geosite", @"category-ru", nil],
            [NSArray arrayWithObjects:@"direct", @"geosite", @"private", nil],
            [NSArray arrayWithObjects:@"direct", @"geoip", @"ru", nil],
            [NSArray arrayWithObjects:@"direct", @"geoip", @"private", nil],
            [NSArray arrayWithObjects:@"direct", @"domain-suffix", @"xn--p1ai", nil], nil]];
        geo();
    }];
    [menu lr_addItem:L(@"Block ads (geosite)") block:^{
        [me addRuleSpecs:[NSArray arrayWithObject:[NSArray arrayWithObjects:@"block", @"geosite", @"category-ads-all", nil]]];
        geo();
    }];
    [menu lr_addItem:L(@"Russian sites go direct") block:^{
        NSMutableArray *specs = [NSMutableArray array];
        for (NSString *d in [NSArray arrayWithObjects:@"ru", @"su", @"xn--p1ai", @"yandex.net", @"vk.com",
                             @"userapi.com", @"gosuslugi.ru", @"mail.ru", nil])
            [specs addObject:[NSArray arrayWithObjects:@"direct", @"domain-suffix", d, nil]];
        [me addRuleSpecs:specs];
    }];
    [menu lr_addItem:L(@"Block common ad networks") block:^{
        NSMutableArray *specs = [NSMutableArray array];
        for (NSString *d in [NSArray arrayWithObjects:@"doubleclick.net", @"googlesyndication.com",
                             @"googleadservices.com", @"adservice.google.com", @"app-measurement.com",
                             @"an.yandex.ru", @"adfox.ru", @"mc.yandex.ru", nil])
            [specs addObject:[NSArray arrayWithObjects:@"block", @"domain-suffix", d, nil]];
        [me addRuleSpecs:specs];
    }];
    [menu lr_addItem:L(@"Local services go direct") block:^{
        [me addRuleSpecs:[NSArray arrayWithObjects:
            [NSArray arrayWithObjects:@"direct", @"domain-suffix", @"local", nil],
            [NSArray arrayWithObjects:@"direct", @"domain-suffix", @"lan", nil], nil]];
    }];
    [menu popUpMenuPositioningItem:nil atLocation:NSMakePoint(0, NSHeight([anchor bounds]) + 2) inView:anchor];
}

- (void)addRuleSheet {
    NSView *box = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, 330, 92)] autorelease];
    NSArray *actions = [NSArray arrayWithObjects:@"proxy", @"direct", @"block", nil];
    NSArray *types = [NSArray arrayWithObjects:@"domain-suffix", @"domain", @"domain-keyword", @"ip-cidr",
                      @"port", @"geosite", @"geoip", nil];
    NSMutableArray *actionNames = [NSMutableArray array];
    for (NSString *a in actions) [actionNames addObject:[LRPreferencesController actionName:a]];
    NSMutableArray *typeNames = [NSMutableArray array];
    for (NSString *t in types) [typeNames addObject:[LRPreferencesController typeName:t]];
    NSPopUpButton *action = LRPopUp(actionNames, 1, nil);
    NSPopUpButton *type = LRPopUp(typeNames, 0, nil);
    NSTextField *value = [[[NSTextField alloc] initWithFrame:NSMakeRect(110, 0, 220, 22)] autorelease];
    [[value cell] setPlaceholderString:@"example.com"];
    NSArray *examples = [NSArray arrayWithObjects:@"example.com", @"api.example.com", @"example",
                         @"203.0.113.0/24", @"8000-8999", @"category-ru", @"ru", nil];
    [type lr_setBlock:^(id sender) {
        [[value cell] setPlaceholderString:[examples objectAtIndex:(NSUInteger)[sender indexOfSelectedItem]]];
    }];
    NSTextField *l1 = LRLabel(L(@"Action:"), nil, nil), *l2 = LRLabel(L(@"Match:"), nil, nil),
                *l3 = LRLabel(L(@"Value:"), nil, nil);
    for (NSTextField *l in [NSArray arrayWithObjects:l1, l2, l3, nil]) [l setAlignment:NSRightTextAlignment];
    [l1 setFrame:NSMakeRect(0, 72, 100, 17)];
    [action setFrame:NSMakeRect(107, 66, 200, 26)];
    [l2 setFrame:NSMakeRect(0, 40, 100, 17)];
    [type setFrame:NSMakeRect(107, 34, 200, 26)];
    [l3 setFrame:NSMakeRect(0, 3, 100, 17)];
    for (NSView *v in [NSArray arrayWithObjects:l1, action, l2, type, l3, value, nil]) [box addSubview:v];
    [LRAlert runTitle:L(@"Add Rule")
              message:L(@"A head domain matches the name and every name under it, a specific domain only itself. Ports are TCP destination ports, one or a range.")
              buttons:[NSArray arrayWithObjects:L(@"Add"), L(@"Cancel"), nil]
            accessory:box window:[self window] done:^(NSInteger index) {
        if (index != 0) return;
        NSString *v = [LRTrim([value stringValue]) stringByReplacingOccurrencesOfString:@" " withString:@""];
        if (![v length]) return;
        NSString *t = [types objectAtIndex:(NSUInteger)[type indexOfSelectedItem]];
        if ([t isEqualToString:@"domain"] || [t isEqualToString:@"domain-suffix"]) {
            LRSiteKind kind;
            NSString *host = [LRRoutingProfiles siteHost:v kind:&kind wildcard:NULL];
            if (host && kind == LRSiteName) v = host;
        }
        [self addRuleSpecs:[NSArray arrayWithObject:[NSArray arrayWithObjects:
                            [actions objectAtIndex:(NSUInteger)[action indexOfSelectedItem]], t, v, nil]]];
        LRLog(@"routing", @"rule added");
    }];
}

- (void)deleteSelectedRules {
    NSIndexSet *rows = [_rulesTable selectedRowIndexes];
    if (![rows count]) return;
    NSMutableArray *gone = [NSMutableArray array];
    [rows enumerateIndexesUsingBlock:^(NSUInteger i, BOOL *stop) {
        if (i < [_rules count]) [gone addObject:[_rules objectAtIndex:i]];
    }];
    /* the daemon renumbers after each delete: highest index first */
    [gone sortUsingComparator:^NSComparisonResult(LRRule *a, LRRule *b) {
        return a.index > b.index ? NSOrderedAscending : (a.index < b.index ? NSOrderedDescending : NSOrderedSame);
    }];
    __block void (^step)(NSUInteger) = nil;
    step = [^(NSUInteger i) {
        if (i >= [gone count]) {
            LRRoutingChanged();
            [self loadRules];
            [step autorelease];
            return;
        }
        [[LRDaemonClient shared] deleteRuleIndex:((LRRule *)[gone objectAtIndex:i]).index reply:^(NSString *reply) {
            if (!LRReplyIsOK(reply))
                [LRToast showError:LRErrorFromReply(reply) ? LRErrorFromReply(reply) : L(@"Could not delete")];
            step(i + 1);
        }];
    } copy];
    step(0);
}

- (NSMenu *)profilesMenu {
    __block LRPreferencesController *me = self;
    NSMenu *menu = [[[NSMenu alloc] initWithTitle:@""] autorelease];
    NSString *active = [LRRoutingProfiles activeName];
    for (LRRoutingProfile *p in [LRRoutingProfiles profiles]) {
        NSMenuItem *it = [menu lr_addItem:p.name block:nil];
        [it setState:[p.name isEqualToString:active] ? NSOnState : NSOffState];
        NSMenu *sub = [[[NSMenu alloc] initWithTitle:@""] autorelease];
        [sub lr_addItem:L(@"Apply") block:^{
            [LRToast show:L(@"Applying the routing profile...")];
            [LRRoutingProfiles apply:p progress:^(NSString *line) { [LRToast show:line]; } done:^(BOOL ok, NSString *message) {
                if (message) [LRToast showError:message];
                else [LRToast showSuccess:L(@"Routing profile applied")];
                [me loadRules];
            }];
        }];
        [sub lr_addItem:L(@"Share…") block:^{
            NSString *link = [p happLink];
            if (!link) { [LRToast showError:L(@"The profile could not be encoded")]; return; }
            [[LRAppDelegate shared] shareText:link title:p.name subtitle:[p summary]];
        }];
        [sub lr_addSeparator];
        [sub lr_addItem:L(@"Delete") block:^{ [LRRoutingProfiles remove:p]; }];
        [it setSubmenu:sub];
    }
    if ([menu numberOfItems]) [menu lr_addSeparator];
    [menu lr_addItem:L(@"Paste a happ://routing link") block:^{ [LRImporter pasteFromClipboard]; }];
    [menu lr_addItem:L(@"Save the current rules as a profile…") block:^{
        [LRAlert promptTitle:L(@"Save as a profile") message:nil placeholder:L(@"Name") text:nil
                      button:L(@"Save") done:^(NSString *value) {
            NSString *name = LRTrim(value);
            if (![name length]) return;
            NSMutableArray *specs = [NSMutableArray array];
            for (LRRule *r in me->_rules) {
                if ([r.type isEqualToString:@"port"]) continue;
                [specs addObject:[NSArray arrayWithObjects:r.action, r.type, r.value, nil]];
            }
            LRRoutingProfile *p = [[[LRRoutingProfile alloc] init] autorelease];
            p.name = name;
            p.rules = specs;
            p.defaultAction = [[DS() stringForKey:@"rules_default"] isEqualToString:@"direct"] ? @"direct" : @"proxy";
            [LRRoutingProfiles save:p];
            [LRToast showSuccess:L(@"Profile saved")];
        }];
    }];
    return menu;
}

- (void)geoSheet {
    [LRToast show:L(@"Reading the geo data...")];
    [[LRDaemonClient shared] geoStatus:^(NSArray *lines, NSString *summary, BOOL ok) {
        NSString *text = [lines count] ? [lines componentsJoinedByString:@"\n"] : (summary ? summary : L(@"No geo data yet."));
        [LRAlert runTitle:L(@"Geo data") message:text
                  buttons:[NSArray arrayWithObjects:L(@"Update"), L(@"Close"), nil]
                accessory:nil window:[self window] done:^(NSInteger index) {
            if (index != 0) return;
            [LRToast show:L(@"Downloading geo data... this can take a minute.")];
            [[LRDaemonClient shared] geoUpdate:^(NSArray *l2, NSString *s2, BOOL ok2) {
                if (ok2) [LRToast showSuccess:s2 ? s2 : L(@"Geo data updated")];
                else [LRToast showError:s2 ? s2 : L(@"Geo data could not be downloaded")];
            }];
        }];
    }];
}

- (NSView *)routingPane {
    LRForm *f = [self form];
    LRDaemonSettings *ds = DS();
    __block LRPreferencesController *me = self;
    [f addCheckBox:L(@"Enable routing") on:[ds boolForKey:@"rules_enabled" fallback:YES] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"rules_enabled"];
        LRRoutingChanged();
    }];
    BOOL direct = [[ds stringForKey:@"rules_default"] isEqualToString:@"direct"];
    [f addLabel:L(@"Default action")
          popup:[NSArray arrayWithObjects:L(@"Proxy: through the tunnel"), L(@"Direct: skip the tunnel"), nil]
       selected:direct ? 1 : 0 changed:^(NSInteger i) {
        [DS() setValue:i ? @"direct" : @"proxy" forKey:@"rules_default" done:nil];
        LRRoutingChanged();
    }];
    [f addNote:L(@"What happens to names no rule matches. Direct turns the rules into a list of what goes through the tunnel.")];
    [f addCheckBox:L(@"Bypass local networks") on:[ds boolForKey:@"bypass_lan" fallback:YES] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"bypass_lan"];
        LRRoutingChanged();
    }];
    NSString *active = [LRRoutingProfiles activeName];
    NSPopUpButton *profiles = [[[NSPopUpButton alloc] initWithFrame:NSMakeRect(0, 0, 220, 26) pullsDown:YES] autorelease];
    NSMenu *pm = [self profilesMenu];
    [pm insertItemWithTitle:active ? active : L(@"None") action:NULL keyEquivalent:@"" atIndex:0];
    [profiles setMenu:pm];
    [f addLabel:L(@"Routing profile") view:profiles];
    NSButton *geo = LRPushButton(L(@"Geo Data…"), ^(id s) { [me geoSheet]; });
    [f addLabel:L(@"geosite and geoip") view:geo];
    [f addSeparator];

    [_rulesTable release];
    _rulesTable = [[self tableWithColumns:[NSArray arrayWithObjects:
        [NSArray arrayWithObjects:@"value", L(@"Value"), [NSNumber numberWithFloat:200], nil],
        [NSArray arrayWithObjects:@"type", L(@"Match"), [NSNumber numberWithFloat:130], nil],
        [NSArray arrayWithObjects:@"action", L(@"Action"), [NSNumber numberWithFloat:80], nil],
        [NSArray arrayWithObjects:@"hits", L(@"Hits"), [NSNumber numberWithFloat:50], nil], nil]] retain];
    [f addWideView:[self scrollFor:_rulesTable] height:200];
    NSView *bar = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, LR_PANE_WIDTH - 40, 24)] autorelease];
    NSSegmentedControl *seg = [self addRemoveControl:^(NSInteger s) {
        if (s == 0) [me addRuleSheet]; else [me deleteSelectedRules];
    }];
    [seg setFrameOrigin:NSMakePoint(0, 0)];
    [bar addSubview:seg];
    NSButton *presets = [[[NSButton alloc] initWithFrame:NSMakeRect(66, 0, 110, 23)] autorelease];
    [presets setBezelStyle:NSSmallSquareBezelStyle];
    [presets setTitle:L(@"Presets")];
    [presets setFont:[NSFont systemFontOfSize:11]];
    [presets lr_setBlock:^(id s) { [me presetsMenuFrom:s]; }];
    [bar addSubview:presets];
    [f addWideView:bar height:24];
    [f addNote:L(@"Block wins over Direct, and Direct over Proxy. Domain rules act on DNS answers; IP and port rules act in the firewall. They apply on the next connect.")];
    [f finish];
    /* the note sits under the bar, across the pane */
    return f;
}

#pragma mark sites

- (BOOL)onlyListed {
    return [[DS() stringForKey:@"rules_default"] isEqualToString:@"direct"];
}

- (NSString *)listAction {
    return [self onlyListed] ? @"proxy" : @"direct";
}

- (void)rebuildSites {
    NSMutableArray *out = [NSMutableArray array];
    NSString *want = [self listAction];
    for (LRRule *r in _rules) {
        if (![r.action isEqualToString:want]) continue;
        if ([r.type isEqualToString:@"domain-suffix"] || [r.type isEqualToString:@"domain"] ||
            [r.type isEqualToString:@"ip-cidr"])
            [out addObject:r];
    }
    [_sites release];
    _sites = [out retain];
}

- (void)addSpecs:(NSArray *)specs done:(void (^)(NSUInteger failed))done {
    void (^callback)(NSUInteger) = [[done copy] autorelease];
    __block NSUInteger failed = 0;
    __block NSUInteger i = 0;
    __block void (^step)(void) = nil;
    step = [^{
        if (i >= [specs count]) { callback(failed); [step autorelease]; return; }
        NSArray *spec = [specs objectAtIndex:i++];
        [[LRDaemonClient shared] addRuleAction:[spec objectAtIndex:0] type:[spec objectAtIndex:1]
                                         value:[spec objectAtIndex:2] reply:^(NSString *reply) {
            if (!LRReplyIsOK(reply)) ++failed;
            step();
        }];
    } copy];
    step();
}

- (void)addSiteSpecs:(NSArray *)specs {
    _busy = YES;
    [LRRoutingProfiles changeRules:^(void (^finish)(void)) {
        if (![DS() boolForKey:@"rules_enabled" fallback:YES]) [DS() setBool:YES forKey:@"rules_enabled"];
        [self addSpecs:specs done:^(NSUInteger failed) {
            _busy = NO;
            [self loadRules];
            finish();
            if (failed) [LRToast showError:[NSString stringWithFormat:L(@"%lu sites were not accepted"), (unsigned long)failed]];
            else if ([specs count] == 1)
                [LRToast showSuccess:[NSString stringWithFormat:L(@"%@ added"),
                                      [LRRoutingProfiles patternForRuleType:[[specs objectAtIndex:0] objectAtIndex:1]
                                                                      value:[[specs objectAtIndex:0] objectAtIndex:2]]]];
            else [LRToast showSuccess:[NSString stringWithFormat:L(@"%lu sites added"), (unsigned long)[specs count]]];
        }];
    }];
}

- (void)setOnlyListed:(BOOL)only {
    if (only == [self onlyListed]) return;
    NSArray *sites = [[_sites copy] autorelease];
    NSString *newAction = only ? @"proxy" : @"direct";
    [LRRoutingProfiles changeRules:^(void (^finish)(void)) {
        [[LRDaemonClient shared] setSetting:@"rules_enabled" value:@"1" reply:nil];
        [DS() setValue:only ? @"direct" : @"proxy" forKey:@"rules_default" done:nil];
        NSMutableArray *specs = [NSMutableArray array];
        for (LRRule *r in sites) [specs addObject:[NSArray arrayWithObjects:newAction, r.type, r.value, nil]];
        [self addSpecs:specs done:^(NSUInteger failed) {
            [self loadRules];
            finish();
        }];
    }];
}

- (void)removeSelectedSites {
    NSIndexSet *rows = [_sitesTable selectedRowIndexes];
    NSMutableArray *gone = [NSMutableArray array];
    [rows enumerateIndexesUsingBlock:^(NSUInteger i, BOOL *stop) {
        if (i < [_sites count]) [gone addObject:[_sites objectAtIndex:i]];
    }];
    if (![gone count]) return;
    [gone sortUsingComparator:^NSComparisonResult(LRRule *a, LRRule *b) {
        return a.index > b.index ? NSOrderedAscending : (a.index < b.index ? NSOrderedDescending : NSOrderedSame);
    }];
    [LRRoutingProfiles changeRules:^(void (^finish)(void)) {
        __block void (^step)(NSUInteger) = nil;
        step = [^(NSUInteger i) {
            if (i >= [gone count]) {
                [self loadRules];
                finish();
                [step autorelease];
                return;
            }
            [[LRDaemonClient shared] deleteRuleIndex:((LRRule *)[gone objectAtIndex:i]).index reply:^(NSString *reply) {
                step(i + 1);
            }];
        } copy];
        step(0);
    }];
}

- (void)addSiteSheet {
    NSView *box = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, 320, 56)] autorelease];
    NSTextField *field = [[[NSTextField alloc] initWithFrame:NSMakeRect(0, 34, 320, 22)] autorelease];
    [[field cell] setPlaceholderString:@"xyz.abc.com"];
    id saved = [[NSUserDefaults standardUserDefaults] objectForKey:@"LRSiteMode"];
    NSInteger mode = saved && [saved integerValue] == LRSiteExact ? 1 : 0;
    NSPopUpButton *kind = LRPopUp([NSArray arrayWithObjects:L(@"Head domain: the name and everything under it"),
                                   L(@"Specific domain: only this name"), nil], mode, nil);
    [kind setFrame:NSMakeRect(-3, 0, 326, 26)];
    [box addSubview:field];
    [box addSubview:kind];
    [LRAlert runTitle:L(@"Add a Site")
              message:L(@"A site address or a link to any of its pages. Routing sees the name (DNS, SNI), so a rule always covers every page of it.")
              buttons:[NSArray arrayWithObjects:L(@"Add"), L(@"Cancel"), nil]
            accessory:box window:[self window] done:^(NSInteger index) {
        if (index != 0) return;
        LRSiteMode m = [kind indexOfSelectedItem] == 1 ? LRSiteExact : LRSiteHead;
        NSArray *spec = [LRRoutingProfiles ruleSpecForSite:[field stringValue] mode:m action:[self listAction]];
        if (!spec) {
            [LRToast showError:L(@"This is not a site address")];
            return;
        }
        [[NSUserDefaults standardUserDefaults] setInteger:m forKey:@"LRSiteMode"];
        [self addSiteSpecs:[NSArray arrayWithObject:spec]];
    }];
}

- (void)importSitesFromClipboard {
    NSString *text = LRPasteboardString();
    if (!text) { [LRToast showError:L(@"The clipboard is empty")]; return; }
    NSMutableArray *specs = [NSMutableArray array];
    for (NSString *e in [LRRoutingProfiles sitesFromText:text]) {
        NSArray *spec = [LRRoutingProfiles ruleSpecForEntry:e action:[self listAction]];
        if (spec) [specs addObject:spec];
    }
    if (![specs count]) { [LRToast showError:L(@"No sites found")]; return; }
    [self addSiteSpecs:specs];
}

- (void)importSitesFromFile {
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setAllowedFileTypes:[NSArray arrayWithObjects:@"json", @"txt", @"list", nil]];
    [panel beginSheetModalForWindow:[self window] completionHandler:^(NSInteger result) {
        if (result != NSFileHandlingPanelOKButton) return;
        NSString *text = [NSString stringWithContentsOfURL:[panel URL] encoding:NSUTF8StringEncoding error:NULL];
        NSMutableArray *specs = [NSMutableArray array];
        for (NSString *e in [LRRoutingProfiles sitesFromText:text]) {
            NSArray *spec = [LRRoutingProfiles ruleSpecForEntry:e action:[self listAction]];
            if (spec) [specs addObject:spec];
        }
        if (![specs count]) { [LRToast showError:L(@"No sites found")]; return; }
        [self addSiteSpecs:specs];
    }];
}

- (void)exportSites {
    NSMutableArray *specs = [NSMutableArray array];
    for (LRRule *rule in _sites) [specs addObject:[NSArray arrayWithObjects:rule.type, rule.value, nil]];
    NSString *json = [LRRoutingProfiles amneziaExportForRuleSpecs:specs];
    NSSavePanel *panel = [NSSavePanel savePanel];
    [panel setNameFieldStringValue:@"sites.json"];
    [panel beginSheetModalForWindow:[self window] completionHandler:^(NSInteger result) {
        if (result != NSFileHandlingPanelOKButton) return;
        [json writeToURL:[panel URL] atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }];
}

- (NSView *)sitesPane {
    LRForm *f = [self form];
    __block LRPreferencesController *me = self;
    BOOL only = [self onlyListed];
    [self rebuildSites];
    NSButtonCell *proto = [[[NSButtonCell alloc] init] autorelease];
    [proto setButtonType:NSRadioButton];
    NSMatrix *radio = [[[NSMatrix alloc] initWithFrame:NSMakeRect(0, 0, 360, 40) mode:NSRadioModeMatrix
                                             prototype:proto numberOfRows:2 numberOfColumns:1] autorelease];
    [radio setCellSize:NSMakeSize(360, 18)];
    [radio setIntercellSpacing:NSMakeSize(0, 4)];
    [[radio cellAtRow:0 column:0] setTitle:L(@"All sites through the VPN, except the list")];
    [[radio cellAtRow:1 column:0] setTitle:L(@"Only the listed sites through the VPN")];
    [radio selectCellAtRow:only ? 1 : 0 column:0];
    [radio sizeToCells];
    [radio lr_setBlock:^(id sender) { [me setOnlyListed:[sender selectedRow] == 1]; }];
    [f addLabel:L(@"Mode") view:radio];
    [f addNote:L(@"Changing the list restarts a connected tunnel.")];
    [_sitesTable release];
    _sitesTable = [[self tableWithColumns:[NSArray arrayWithObjects:
        [NSArray arrayWithObjects:@"site", only ? L(@"Through the VPN") : L(@"Around the VPN"),
         [NSNumber numberWithFloat:230], nil],
        [NSArray arrayWithObjects:@"match", L(@"Covers"), [NSNumber numberWithFloat:240], nil], nil]] retain];
    [f addWideView:[self scrollFor:_sitesTable] height:220];
    NSView *bar = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, LR_PANE_WIDTH - 40, 24)] autorelease];
    NSSegmentedControl *seg = [self addRemoveControl:^(NSInteger s) {
        if (s == 0) [me addSiteSheet]; else [me removeSelectedSites];
    }];
    [bar addSubview:seg];
    NSPopUpButton *more = [[[NSPopUpButton alloc] initWithFrame:NSMakeRect(66, 0, 40, 23) pullsDown:YES] autorelease];
    [more setBezelStyle:NSSmallSquareBezelStyle];
    [[more cell] setArrowPosition:NSPopUpArrowAtBottom];
    NSMenu *mm = [[[NSMenu alloc] initWithTitle:@""] autorelease];
    NSMenuItem *gear = [mm lr_addItem:@"" block:nil];
    [gear setImage:[NSImage imageNamed:NSImageNameActionTemplate]];
    [mm lr_addItem:L(@"Import from Clipboard") block:^{ [me importSitesFromClipboard]; }];
    [mm lr_addItem:L(@"Import from a File…") block:^{ [me importSitesFromFile]; }];
    [mm lr_addItem:L(@"Export the List…") block:^{ [me exportSites]; }];
    [more setMenu:mm];
    [bar addSubview:more];
    [f addWideView:bar height:24];
    [f addNote:L(@"Lists exported from Amnezia VPN (JSON) and plain lists with one site per line both import. \"*.abc.com\" in a list is a head domain. Double-click a site to switch it between a head and a specific domain.")];
    [_sitesTable setTarget:self];
    [_sitesTable setDoubleAction:@selector(siteDoubleClicked:)];
    [f finish];
    return f;
}

- (void)siteDoubleClicked:(id)sender {
    NSInteger row = [_sitesTable clickedRow];
    if (row < 0 || row >= (NSInteger)[_sites count]) return;
    LRRule *r = [_sites objectAtIndex:(NSUInteger)row];
    if ([r.type isEqualToString:@"ip-cidr"]) return;
    NSString *type = [r.type isEqualToString:@"domain"] ? @"domain-suffix" : @"domain";
    NSString *value = [type isEqualToString:@"domain-suffix"] ? [LRRoutingProfiles headDomain:r.value] : r.value;
    NSArray *spec = [NSArray arrayWithObjects:r.action, type, value, nil];
    [LRRoutingProfiles changeRules:^(void (^finish)(void)) {
        [[LRDaemonClient shared] deleteRuleIndex:r.index reply:^(NSString *reply) {
            [self addSpecs:[NSArray arrayWithObject:spec] done:^(NSUInteger failed) {
                if (failed) [LRToast showError:L(@"The site was not accepted")];
                [self loadRules];
                finish();
            }];
        }];
    }];
}

#pragma mark tables

- (NSInteger)numberOfRowsInTableView:(NSTableView *)t {
    if (t == _rulesTable) return (NSInteger)[_rules count];
    if (t == _sitesTable) return (NSInteger)[_sites count];
    return 0;
}

- (id)tableView:(NSTableView *)t objectValueForTableColumn:(NSTableColumn *)col row:(NSInteger)row {
    NSString *c = [col identifier];
    if (t == _rulesTable && row < (NSInteger)[_rules count]) {
        LRRule *r = [_rules objectAtIndex:(NSUInteger)row];
        if ([c isEqualToString:@"value"]) return [r.type hasPrefix:@"domain"] ? [LRRoutingProfiles displaySite:r.value] : r.value;
        if ([c isEqualToString:@"type"]) return [LRPreferencesController typeName:r.type];
        if ([c isEqualToString:@"action"]) {
            LRSkin *s = SKIN;
            NSColor *color = [r.action isEqualToString:@"block"] ? s->bad
                : ([r.action isEqualToString:@"direct"] ? s->warn : s->good);
            return [[[NSAttributedString alloc] initWithString:[LRPreferencesController actionName:r.action]
                attributes:[NSDictionary dictionaryWithObject:color forKey:NSForegroundColorAttributeName]] autorelease];
        }
        return [NSString stringWithFormat:@"%llu", r.hits];
    }
    if (t == _sitesTable && row < (NSInteger)[_sites count]) {
        LRRule *r = [_sites objectAtIndex:(NSUInteger)row];
        if ([c isEqualToString:@"site"]) return [LRRoutingProfiles displaySite:r.value];
        if ([r.type isEqualToString:@"ip-cidr"]) return L(@"Addresses");
        NSString *pattern = [LRRoutingProfiles patternForRuleType:r.type value:r.value];
        return [NSString stringWithFormat:@"%@ · %@", [r.type isEqualToString:@"domain"] ? L(@"Specific domain")
                                                                                          : L(@"Head domain"), pattern];
    }
    return nil;
}

#pragma mark subscriptions

- (NSView *)subscriptionsPane {
    LRForm *f = [self form];
    LRDaemonSettings *ds = DS();
    __block LRPreferencesController *me = self;
    /* 0 is automatic: the provider's own interval, twice a day without one */
    NSInteger hours = [ds integerForKey:@"sub_refresh_hours" fallback:0];
    NSArray *hourValues = [NSArray arrayWithObjects:@"0", @"6", @"12", @"24", @"48", @"168", @"-1", nil];
    NSArray *hourNames = [NSArray arrayWithObjects:L(@"Automatic"), L(@"Every 6 hours"), L(@"Every 12 hours"),
                          L(@"Every day"), L(@"Every 2 days"), L(@"Every week"), L(@"Off"), nil];
    NSUInteger hi = [hourValues indexOfObject:[NSString stringWithFormat:@"%ld", (long)hours]];
    [f addLabel:L(@"Auto-update subscriptions") popup:hourNames selected:hi == NSNotFound ? 0 : (NSInteger)hi
        changed:^(NSInteger i) {
        [DS() setValue:[hourValues objectAtIndex:(NSUInteger)i] forKey:@"sub_refresh_hours" done:nil];
    }];
    [f addCheckBox:L(@"Refresh subscriptions when LegacyRay opens") on:[LRPrefs refreshSubscriptionsOnOpen]
           changed:^(BOOL on) { [LRPrefs setRefreshSubscriptionsOnOpen:on]; }];
    [f addCheckBox:L(@"Remind before a subscription ends") on:[LRReminders enabled] changed:^(BOOL on) {
        [LRReminders setEnabled:on];
        if (on) [LRReminders scheduleForSubscriptions:[LRCatalog shared].subscriptions];
    }];
    [f addCheckBox:L(@"Keep renamed subscriptions after updates") on:![ds boolForKey:@"sub_panel_title" fallback:NO]
           changed:^(BOOL on) { [DS() setBool:!on forKey:@"sub_panel_title"]; }];
    [f addSeparator];
    NSArray *agents = [NSArray arrayWithObjects:@"Happ/3.26.1", @"Happ/3.26.3/iOS", @"v2rayN/7.13",
                       @"v2rayNG/1.10.16", @"Hiddify/2.5.7", @"Streisand/1.6", @"Shadowrocket/2.2.65",
                       @"clash-verge/2.3.1", @"sing-box/1.12.0", nil];
    NSComboBox *ua = [[[NSComboBox alloc] initWithFrame:NSMakeRect(0, 0, 240, 24)] autorelease];
    [ua addItemsWithObjectValues:agents];
    NSString *current = [ds stringForKey:@"sub_user_agent"];
    [ua setStringValue:current ? current : @"Happ/3.26.1"];
    [ua setCompletes:YES];
    [ua lr_setBlock:^(id sender) {
        NSString *v = LRTrim([sender stringValue]);
        if (v) [DS() setValue:v forKey:@"sub_user_agent" done:nil];
    }];
    [f addLabel:@"User-Agent" view:ua];
    NSString *xver = [ds stringForKey:@"xray_version"];
    [f addLabel:L(@"Xray version") field:xver ? xver : @"26.7.28" placeholder:@"26.7.28" width:100
         commit:^(NSString *value) {
        NSString *clean = LRTrim(value);
        if (!clean) return;
        [DS() setValue:clean forKey:@"xray_version" done:^(BOOL ok, NSString *err) {
            if (!ok) [LRToast showError:L(@"Use x.y.z; each number must be from 0 to 255.")];
        }];
    }];
    [f addNote:L(@"The version this client reports inside the Reality handshake. Change it only when a server requires a specific client version.")];
    [f addSeparator];
    NSView *hw = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, [f controlWidth], 24)] autorelease];
    NSButton *copy = [[[NSButton alloc] initWithFrame:NSZeroRect] autorelease];
    NSButton *renew = [[[NSButton alloc] initWithFrame:NSZeroRect] autorelease];
    for (NSButton *b in [NSArray arrayWithObjects:copy, renew, nil]) {
        [b setBezelStyle:NSRoundedBezelStyle];
        [[b cell] setControlSize:NSSmallControlSize];
        [b setFont:[NSFont systemFontOfSize:11]];
    }
    [copy setTitle:L(@"Copy")];
    [renew setTitle:L(@"New ID…")];
    [copy sizeToFit];
    [renew sizeToFit];
    CGFloat rw = NSWidth([renew frame]) + 8, cw = NSWidth([copy frame]) + 8;
    [renew setFrame:NSMakeRect([f controlWidth] - rw, 0, rw, 24)];
    [copy setFrame:NSMakeRect([f controlWidth] - rw - cw, 0, cw, 24)];
    NSTextField *id_ = LRLabel(_hwid ? LRStealth(_hwid) : @"—", [NSFont userFixedPitchFontOfSize:11], nil);
    [id_ setSelectable:YES];
    [id_ setFrame:NSMakeRect(0, 4, [f controlWidth] - rw - cw - 6, 16)];
    [hw addSubview:id_];
    [copy lr_setBlock:^(id s) {
        if (!me->_hwid) return;
        LRSetPasteboardString(me->_hwid);
        [LRToast showSuccess:L(@"HWID copied")];
    }];
    [hw addSubview:copy];
    [renew lr_setBlock:^(id s) {
        [LRAlert confirmTitle:L(@"Issue a new device ID")
                      message:L(@"Panels that limit devices will see this Mac as a new device.")
                       button:L(@"Issue") destructive:YES action:^{
            [[LRDaemonClient shared] resetDeviceHWID:^(NSString *hwid, NSString *error) {
                if (!hwid) { [LRToast showError:error ? error : L(@"Could not issue a new ID")]; return; }
                [me->_hwid release];
                me->_hwid = [hwid copy];
                [LRToast showSuccess:L(@"New device ID issued")];
                [me rebuildPane];
            }];
        }];
    }];
    [hw addSubview:renew];
    [f addLabel:L(@"Device ID (HWID)") view:hw];
    [f addNote:L(@"Panels identify this device by its HWID and pick the feed format by the User-Agent.")];
    [f finish];
    return f;
}

#pragma mark network

- (NSView *)networkPane {
    LRForm *f = [self form];
    LRDaemonSettings *ds = DS();
    [f addCheckBox:L(@"Kill switch") on:[ds boolForKey:@"kill_switch" fallback:NO] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"kill_switch"];
        LRRoutingChanged();
    }];
    [f addNote:L(@"The kill switch keeps UDP other than DNS off the network while a tunnel is up, so nothing leaks around it. Queries go through the tunnel to the DNS server.")];
    NSString *dns = [ds stringForKey:@"dns_upstream"];
    NSArray *dnsValues = [NSArray arrayWithObjects:@"1.1.1.1", @"8.8.8.8", @"9.9.9.9", @"77.88.8.8", nil];
    NSMutableArray *dnsNames = [NSMutableArray arrayWithObjects:@"Cloudflare 1.1.1.1", @"Google 8.8.8.8",
                                @"Quad9 9.9.9.9", L(@"Yandex 77.88.8.8"), nil];
    NSUInteger dsel = dns ? [dnsValues indexOfObject:dns] : 1;
    if (dsel == NSNotFound) [dnsNames addObject:dns];
    [dnsNames addObject:L(@"Custom...")];
    NSPopUpButton *dnsPop = [f addLabel:L(@"DNS server") popup:dnsNames
                               selected:dsel == NSNotFound ? (NSInteger)[dnsValues count] : (NSInteger)dsel
                                changed:^(NSInteger i) {
        if (i < (NSInteger)[dnsValues count]) {
            [DS() setValue:[dnsValues objectAtIndex:(NSUInteger)i] forKey:@"dns_upstream" done:nil];
            LRRoutingChanged();
            return;
        }
        if (i == (NSInteger)[dnsNames count] - 1)
            [LRAlert promptTitle:L(@"DNS server") message:L(@"An IPv4 address") placeholder:@"1.1.1.1"
                            text:dns button:L(@"Save") done:^(NSString *v) {
                [DS() setValue:LRTrim(v) forKey:@"dns_upstream" done:^(BOOL ok, NSString *err) {
                    if (!ok) [LRToast showError:L(@"That address was not accepted")];
                    else LRRoutingChanged();
                }];
            }];
    }];
    (void)dnsPop;
    [f addSeparator];
    BOOL lan = [ds boolForKey:@"socks_public" fallback:NO];
    [f addCheckBox:L(@"Share the proxy on the local network") on:lan changed:^(BOOL on) {
        [DS() setBool:on forKey:@"socks_public"];
        [LRToast show:L(@"Takes effect after the daemon restarts (or a reboot).")];
    }];
    NSInteger socksPort = [ds integerForKey:@"socks_port" fallback:11080];
    [f addLabel:L(@"SOCKS port") field:[NSString stringWithFormat:@"%ld", (long)socksPort] placeholder:@"11080"
          width:70 commit:^(NSString *v) {
        if (!LRTrim(v)) return;
        [DS() setValue:LRTrim(v) forKey:@"socks_port" done:^(BOOL ok, NSString *err) {
            if (!ok) [LRToast showError:L(@"Check the value and try again.")];
            else [LRToast show:L(@"Applied on the next connect.")];
        }];
    }];
    NSString *ip = [LRNetInfo localIPv4];
    [f addNote:lan && ip
        ? [NSString stringWithFormat:L(@"Other devices on this network can use SOCKS5 %@:%ld. Anyone on the network can, so turn it off on public networks."), ip, (long)socksPort]
        : [NSString stringWithFormat:L(@"Apps on this Mac that take a proxy can use SOCKS5 127.0.0.1:%ld even with the firewall redirect off."), (long)socksPort]];
    [f addSeparator];
    NSString *dnsPort = [ds stringForKey:@"dns_local_port"];
    [f addLabel:L(@"Local DNS port") field:dnsPort ? dnsPort : @"10053" placeholder:@"10053" width:70
         commit:^(NSString *v) {
        if (!LRTrim(v)) return;
        [DS() setValue:LRTrim(v) forKey:@"dns_local_port" done:^(BOOL ok, NSString *err) {
            if (!ok) [LRToast showError:L(@"Check the value and try again.")];
        }];
    }];
    NSArray *blocks = [NSArray arrayWithObjects:@"zero", @"nxdomain", @"refused", nil];
    NSString *block = [ds stringForKey:@"block_response"];
    NSUInteger bi = block ? [blocks indexOfObject:block] : 0;
    [f addLabel:L(@"Blocked domains answer") popup:blocks selected:bi == NSNotFound ? 0 : (NSInteger)bi
        changed:^(NSInteger i) {
        [DS() setValue:[blocks objectAtIndex:(NSUInteger)i] forKey:@"block_response" done:nil];
    }];
    [f addSeparator];
    /* the daemon's "app_proxy" pin is the system proxy on os x */
    NSArray *backends = [NSArray arrayWithObjects:@"auto", @"c", @"app_proxy", nil];
    NSArray *backendNames = [NSArray arrayWithObjects:L(@"Automatic"), L(@"Firewall (pf)"),
                             L(@"System proxy"), nil];
    NSString *backend = [ds stringForKey:@"force_backend"];
    NSUInteger bki = backend ? [backends indexOfObject:backend] : 0;
    [f addLabel:L(@"Backend") popup:backendNames selected:bki == NSNotFound ? 0 : (NSInteger)bki changed:^(NSInteger i) {
        [DS() setValue:[backends objectAtIndex:(NSUInteger)i] forKey:@"force_backend" done:nil];
    }];
    /* the two forms that turn the mac's own packets around; the rdr forms of
       the iphone only see what comes in on an interface */
    NSArray *pfModes = [NSArray arrayWithObjects:@"auto", @"0", @"1", nil];
    NSArray *pfNames = [NSArray arrayWithObjects:L(@"Automatic"), @"route-to lo0", @"route-to lo0 + nat", nil];
    NSString *pf = [ds stringForKey:@"force_pf_mode"];
    NSUInteger pi = pf ? [pfModes indexOfObject:pf] : 0;
    [f addLabel:L(@"pf variant") popup:pfNames selected:pi == NSNotFound ? 0 : (NSInteger)pi changed:^(NSInteger i) {
        [DS() setValue:[pfModes objectAtIndex:(NSUInteger)i] forKey:@"force_pf_mode" done:nil];
    }];
    [f addCheckBox:L(@"Trace every session") on:[ds boolForKey:@"trace" fallback:NO] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"trace"];
    }];
    [f addCheckBox:L(@"Take device-gated feeds") on:[ds boolForKey:@"sub_ignore_gating" fallback:NO] changed:^(BOOL on) {
        [DS() setBool:on forKey:@"sub_ignore_gating"];
    }];
    [f addNote:L(@"LegacyRay sends the traffic of this Mac to the tunnel with pf, in its own anchor next to the system's. If pf does not let it through, LegacyRay becomes the system proxy instead: that covers the apps that follow the proxy settings. Pin a backend or a pf variant only to track down a problem.")];
    [f finish];
    return f;
}

#pragma mark advanced

- (NSView *)advancedPane {
    LRForm *f = [self form];
    __block LRPreferencesController *me = self;
    LRHelperState state = [LRHelperInstaller state];
    NSString *have = [LRHelperInstaller installedVersion];
    if (!have) have = @"—";
    NSString *status = state == LRHelperReady ? [NSString stringWithFormat:L(@"Installed, version %@"), have]
        : state == LRHelperOutdated ? [NSString stringWithFormat:L(@"Needs an update (%@ on disk, %@ in the app)"),
                                       have, [LRHelperInstaller bundledVersion]]
        : L(@"Not installed");
    [f addLabel:L(@"Network helper") view:LRLabel(status, nil, nil)];
    NSView *keys = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, [f controlWidth], 32)] autorelease];
    NSButton *reinstall = LRPushButton(state == LRHelperMissing ? L(@"Install…") : L(@"Reinstall…"), ^(id s) {
        [LRHelperInstaller installExplaining:NO done:^(BOOL ok, NSString *error) {
            if (ok) {
                [LRToast showSuccess:L(@"The network helper is installed")];
                [[LRTunnel shared] stop];
                [[LRTunnel shared] start];
                [[LRCatalog shared] reload];
            } else if (error) [LRAlert showTitle:L(@"The Helper Was Not Installed") message:error];
            [me rebuildPane];
        }];
    });
    NSButton *remove = LRPushButton(L(@"Uninstall…"), ^(id s) {
        [LRAlert runTitle:L(@"Uninstall the Network Helper")
                  message:L(@"The tunnel goes down and the system service is removed. Keep the servers, subscriptions and settings for a later install, or remove them too?")
                  buttons:[NSArray arrayWithObjects:L(@"Keep Settings"), L(@"Remove Everything"), L(@"Cancel"), nil]
                accessory:nil window:[me window] done:^(NSInteger index) {
            if (index > 1) return;
            [[LRTunnel shared] disconnect];
            [LRHelperInstaller uninstallPurging:index == 1 done:^(BOOL ok, NSString *error) {
                if (ok) [LRToast showSuccess:L(@"The network helper was removed")];
                else if (error) [LRAlert showTitle:L(@"Uninstall Failed") message:error];
                [[LRTunnel shared] pollNow];
                [me rebuildPane];
            }];
        }];
    });
    [reinstall setFrameOrigin:NSMakePoint(-6, 0)];
    [remove setFrameOrigin:NSMakePoint(NSMaxX([reinstall frame]), 0)];
    [remove setEnabled:state != LRHelperMissing];
    [keys addSubview:reinstall];
    [keys addSubview:remove];
    [f addView:keys];
    [f addNote:[NSString stringWithFormat:L(@"legacyrayd runs as a launchd daemon from %s. Its log is %s, its settings %s."),
                SENKO_PREFIX, SENKO_SYSTEM_LOG, SENKO_DAEMON_CFG]];
    [f addSeparator];
    NSView *backup = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, [f controlWidth], 32)] autorelease];
    NSButton *ex = LRPushButton(L(@"Export…"), ^(id s) { [[LRAppDelegate shared] exportBackup:nil]; });
    NSButton *im = LRPushButton(L(@"Restore…"), ^(id s) { [[LRAppDelegate shared] restoreBackup:nil]; });
    [ex setFrameOrigin:NSMakePoint(-6, 0)];
    [im setFrameOrigin:NSMakePoint(NSMaxX([ex frame]), 0)];
    [backup addSubview:ex];
    [backup addSubview:im];
    [f addLabel:L(@"Backup") view:backup];
    [f addNote:L(@"A backup holds every server, subscription, rule and daemon setting. The iPhone app reads it too.")];
    [f addSeparator];
    NSButton *diag = LRPushButton(L(@"Diagnostics…"), ^(id s) { [[LRAppDelegate shared] openDiagnostics:nil]; });
    [diag setFrameOrigin:NSMakePoint(-6, 0)];
    NSView *dv = [[[NSView alloc] initWithFrame:NSMakeRect(0, 0, [f controlWidth], 32)] autorelease];
    [dv addSubview:diag];
    NSButton *upd = LRPushButton(L(@"Check for Updates"), ^(id s) { [[LRAppDelegate shared] checkForUpdates:nil]; });
    [upd setFrameOrigin:NSMakePoint(NSMaxX([diag frame]), 0)];
    [dv addSubview:upd];
    [f addLabel:L(@"Troubleshooting") view:dv];
    [f addNote:[NSString stringWithFormat:@"LegacyRay %s (%s) · OS X %@", LR_VERSION, LR_BUILD_NUMBER, LRMacSystemVersion()]];
    [f finish];
    return f;
}
@end
