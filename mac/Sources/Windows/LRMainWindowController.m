#import "LRMainWindowController.h"
#import "LRAppDelegate.h"
#import "LRHeaderBar.h"
#import "LRBarKey.h"
#import "LRDashboardView.h"
#import "LRBlocks.h"
#import "LRDraw.h"
#import "LRTunnel.h"
#import "LRCatalog.h"
#import "LRAWGProfiles.h"
#import "LRDaemonSettings.h"
#import "LRDaemonClient.h"
#import "LRNetInfo.h"
#import "LRImporter.h"
#import "LRQRCode.h"

/* the line between the list and the dashboard: the dark seam of the denim,
   a light hairline on yosemite */
@interface LRSplitView : NSSplitView
@end

@implementation LRSplitView
- (NSColor *)dividerColor {
    return SKIN->flat ? [NSColor colorWithCalibratedWhite:0.80f alpha:1]
                      : [NSColor colorWithCalibratedWhite:0.10f alpha:1];
}
@end

/* the window's content: header on top, the split under it */
@interface LRMainContentView : NSView
@end

@implementation LRMainContentView
- (BOOL)isFlipped {
    return YES;
}

/* links, text, files and pictures of qr codes dropped anywhere on the window
   import like a paste */
- (void)viewDidMoveToWindow {
    [self registerForDraggedTypes:[NSArray arrayWithObjects:NSFilenamesPboardType, NSURLPboardType,
                                   NSPasteboardTypeString, NSPasteboardTypeTIFF, NSPasteboardTypePNG, nil]];
}

- (NSDragOperation)draggingEntered:(id<NSDraggingInfo>)info {
    return NSDragOperationCopy;
}

- (BOOL)performDragOperation:(id<NSDraggingInfo>)info {
    NSPasteboard *pb = [info draggingPasteboard];
    NSArray *files = [pb propertyListForType:NSFilenamesPboardType];
    if ([files count]) {
        for (NSString *f in files) [LRImporter importFileAtPath:f];
        return YES;
    }
    NSString *text = [pb stringForType:NSPasteboardTypeString];
    if (!text) {
        NSURL *url = [NSURL URLFromPasteboard:pb];
        text = [url absoluteString];
    }
    if (LRTrim(text)) {
        [LRImporter importText:text];
        return YES;
    }
    NSImage *image = [[[NSImage alloc] initWithPasteboard:pb] autorelease];
    if (image) {
        NSArray *codes = LRQRDecodeCGImage([image CGImageForProposedRect:NULL context:nil hints:nil]);
        if ([codes count]) [LRImporter importText:[codes componentsJoinedByString:@"\n"]];
        else [LRToast showError:L(@"No QR code in that picture")];
        return YES;
    }
    return NO;
}
@end

@implementation LRMainWindowController
@synthesize sidebar = _sidebar, dashboard = _dashboard;

- (id)initMainWindow {
    NSUInteger mask = NSTitledWindowMask | NSClosableWindowMask | NSMiniaturizableWindowMask |
                      NSResizableWindowMask;
    NSWindow *w = [[[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 900, 580) styleMask:mask
                                                 backing:NSBackingStoreBuffered defer:YES] autorelease];
    [w setMinSize:NSMakeSize(700, 460)];
    [w setTitle:@"LegacyRay"];
    [w setReleasedWhenClosed:NO];
    [w setCollectionBehavior:NSWindowCollectionBehaviorFullScreenPrimary];
    if ((self = [super initWithWindow:w])) {
        [w setDelegate:self];
        [self build];
        [w center];
        [w setFrameAutosaveName:@"LegacyRayMain"];
        NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
        [nc addObserver:self selector:@selector(refresh) name:LRTunnelDidChangeNotification object:nil];
        [nc addObserver:self selector:@selector(tick) name:LRTunnelTickNotification object:nil];
        [nc addObserver:self selector:@selector(refresh) name:LRCatalogDidChangeNotification object:nil];
        [nc addObserver:self selector:@selector(refresh) name:LRCatalogPingNotification object:nil];
        [nc addObserver:self selector:@selector(refresh) name:LRAWGProfilesDidChangeNotification object:nil];
        [nc addObserver:self selector:@selector(refresh) name:LRPrefsDidChangeNotification object:nil];
        [nc addObserver:self selector:@selector(refreshFootnote) name:LRDaemonSettingsDidChangeNotification object:nil];
        [self refresh];
    }
    return self;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [_header release];
    [_overlay release];
    [_split release];
    [_sidebar release];
    [_dashboard release];
    [_checkKey release];
    [_shownError release];
    [super dealloc];
}

#pragma mark building

- (void)build {
    NSWindow *w = [self window];
    BOOL flat = SKIN->flat;
    _yosemiteChrome = LRMacIsYosemite();
    if (_yosemiteChrome) {
        LRWindowHideTitlebar(w);
        /* the flat finish keeps the system's own title; the denim draws it */
        if (flat && [w respondsToSelector:NSSelectorFromString(@"setTitleVisibility:")]) {
            NSInvocation *inv = [NSInvocation invocationWithMethodSignature:
                                 [w methodSignatureForSelector:NSSelectorFromString(@"setTitleVisibility:")]];
            NSInteger visible = 0;
            [inv setSelector:NSSelectorFromString(@"setTitleVisibility:")];
            [inv setArgument:&visible atIndex:2];
            [inv invokeWithTarget:w];
        }
    } else if (!flat) {
        _overlay = [[LRTitlebarOverlay installInWindow:w] retain];
        [_overlay setTitle:@"LegacyRay"];
    }

    NSRect cb = [[w contentView] bounds];
    LRMainContentView *content = [[[LRMainContentView alloc] initWithFrame:cb] autorelease];
    [w setContentView:content];
    cb = [content bounds];

    CGFloat titleRow = 0;
    if (_yosemiteChrome) {
        NSRect frame = [w frame];
        NSRect layout = [w contentRectForFrameRect:frame];
        /* with the full size content view the content rect is the frame;
           the title bar is 22 points on every release that has one */
        titleRow = NSHeight(frame) - NSHeight(layout);
        if (titleRow < 1) titleRow = 22;
    }
    CGFloat headerH = titleRow + [LRHeaderBar barHeight];
    _header = [[LRHeaderBar alloc] initWithFrame:NSMakeRect(0, 0, NSWidth(cb), headerH)];
    [_header setAutoresizingMask:NSViewWidthSizable | NSViewMaxYMargin];
    [_header setTitle:@"LegacyRay"];
    [_header setTitleRow:titleRow];
    [_header setDrawsTitle:_yosemiteChrome && !flat];
    [content addSubview:_header];

    _split = [[LRSplitView alloc] initWithFrame:NSMakeRect(0, headerH, NSWidth(cb), NSHeight(cb) - headerH)];
    [_split setVertical:YES];
    [_split setDividerStyle:NSSplitViewDividerStyleThin];
    [_split setAutoresizingMask:NSViewWidthSizable | NSViewHeightSizable];
    [_split setDelegate:self];
    _sidebar = [[LRSidebar alloc] initWithOwner:self];
    NSView *side = [_sidebar view];
    [side setFrame:NSMakeRect(0, 0, 270, NSHeight([_split bounds]))];
    _dashboard = [[LRDashboardView alloc] initWithFrame:NSMakeRect(271, 0, NSWidth(cb) - 271,
                                                                   NSHeight([_split bounds]))];
    [_split addSubview:side];
    [_split addSubview:_dashboard];
    [_split setAutosaveName:@"LegacyRaySplit"];
    [_split adjustSubviews];
    [content addSubview:_split];

    [_dashboard.power setTarget:self];
    [_dashboard.power setAction:@selector(powerPressed:)];
    [_dashboard.card setTarget:self];
    [_dashboard.card setAction:@selector(cardClicked:)];
    [_dashboard.card setSwipeAction:@selector(cardSwiped:)];

    [self buildKeys];
}

- (void)buildKeys {
    NSColor *ink = [LRBarKey glyphInk];
    __block LRMainWindowController *me = self;
    LRBarKey *add = [LRBarKey keyWithGlyph:LRGlyphPlus(13, ink) handler:nil];
    [add setDropMenu:[self importMenu]];
    [add setToolTip:L(@"Add servers")];
    LRBarKey *list = [LRBarKey keyWithGlyph:LRGlyphList(16, ink) handler:^(LRBarKey *k) {
        [k setDropMenu:[me->_sidebar listMenu]];
    }];
    [list setDropMenu:[_sidebar listMenu]];
    [list setToolTip:L(@"Servers")];
    [_header setLeftKeys:[NSArray arrayWithObjects:add, list, nil]];

    LRBarKey *gear = [LRBarKey keyWithGlyph:LRGlyphGear(16, ink) handler:^(LRBarKey *k) {
        [[LRAppDelegate shared] openPreferences:nil];
    }];
    [gear setToolTip:L(@"Preferences")];
    [_checkKey release];
    _checkKey = [[LRBarKey keyWithTitle:L(@"Check") handler:^(LRBarKey *k) {
        [[LRAppDelegate shared] openCheck:nil];
    }] retain];
    [_checkKey setToolTip:L(@"Check the connection")];
    [_header setRightKeys:[NSArray arrayWithObjects:gear, _checkKey, nil]];
}

- (NSMenu *)importMenu {
    return [LRImporter menu];
}

#pragma mark split

- (CGFloat)splitView:(NSSplitView *)sv constrainMinCoordinate:(CGFloat)proposed ofSubviewAt:(NSInteger)i {
    return 220;
}

- (CGFloat)splitView:(NSSplitView *)sv constrainMaxCoordinate:(CGFloat)proposed ofSubviewAt:(NSInteger)i {
    return MIN(420, NSWidth([sv bounds]) - 420);
}

- (BOOL)splitView:(NSSplitView *)sv canCollapseSubview:(NSView *)v {
    return NO;
}

/* the window grows the dashboard, not the list */
- (void)splitView:(NSSplitView *)sv resizeSubviewsWithOldSize:(NSSize)old {
    NSArray *subs = [sv subviews];
    if ([subs count] < 2) {
        [sv adjustSubviews];
        return;
    }
    NSView *left = [subs objectAtIndex:0], *right = [subs objectAtIndex:1];
    NSRect b = [sv bounds];
    CGFloat d = [sv dividerThickness];
    CGFloat lw = MIN(MAX(NSWidth([left frame]), 220), MAX(220, NSWidth(b) - 420));
    [left setFrame:NSMakeRect(0, 0, lw, NSHeight(b))];
    [right setFrame:NSMakeRect(lw + d, 0, NSWidth(b) - lw - d, NSHeight(b))];
}

#pragma mark state

- (NSString *)statusTitle {
    LRTunnel *t = [LRTunnel shared];
    if (t.busy && t.state != LRTunnelConnected) return L(@"Connecting…");
    switch (t.state) {
        case LRTunnelOffline: return L(@"Service Stopped");
        case LRTunnelIdle: return L(@"Not Connected");
        case LRTunnelConnecting: return L(@"Connecting…");
        case LRTunnelConnected: return L(@"Connected");
        case LRTunnelError: return L(@"Connection Failed");
    }
    return @"";
}

- (NSString *)currentStationName {
    if ([LRPrefs selectedBackend] == LRBackendAmneziaWG) {
        LRAWGProfile *p = [LRAWGProfiles active];
        return p.name ? p.name : @"AmneziaWG";
    }
    LRCatalog *catalog = [LRCatalog shared];
    LRServer *sv = [catalog selectedServer];
    return sv ? [catalog displayNameForServer:sv] : nil;
}

- (NSString *)idleDetail {
    LRTunnel *t = [LRTunnel shared];
    LRCatalog *catalog = [LRCatalog shared];
    switch (t.state) {
        case LRTunnelOffline: return L(@"The background service is not running.");
        case LRTunnelError: return [t.lastError length] ? t.lastError : L(@"The server did not answer.");
        case LRTunnelConnecting: return [self currentStationName];
        default: break;
    }
    if (t.busy) return [self currentStationName];
    return [catalog isEmpty] && ![LRAWGProfiles hasProfiles] ? L(@"Add a server to begin.")
                                                             : L(@"Click the button to connect.");
}

- (void)refreshCard {
    LRCatalog *catalog = [LRCatalog shared];
    LRSkin *s = SKIN;
    LRServerCard *card = _dashboard.card;
    if ([LRPrefs selectedBackend] == LRBackendAmneziaWG) {
        LRAWGProfile *p = [LRAWGProfiles active];
        card.countryCode = nil;
        card.title = p.name ? p.name : @"AmneziaWG";
        card.detail = p ? [p summary] : L(@"WireGuard profile");
        card.value = nil;
        return;
    }
    LRServer *sv = [catalog selectedServer];
    if (!sv) {
        card.countryCode = nil;
        card.title = [catalog isEmpty] ? L(@"No servers yet") : L(@"Choose a server");
        card.detail = [catalog isEmpty] ? L(@"Click to add a link, a QR code or a subscription")
                                        : L(@"Pick one in the list on the left");
        card.value = nil;
        return;
    }
    card.countryCode = [sv countryCode];
    card.title = [catalog displayNameForServer:sv];
    card.detail = [sv protocolSummary];
    NSNumber *ping = [catalog pingForServer:sv];
    if (ping && [ping intValue] == LR_PING_RUNNING) {
        card.value = L(@"checking");
        card.valueColor = s->groupMuted;
    } else if (ping && [ping intValue] < 0) {
        card.value = L(@"no signal");
        card.valueColor = s->bad;
    } else if (ping) {
        int v = [ping intValue];
        card.value = [NSString stringWithFormat:@"%d %@", v, L(@"ms")];
        card.valueColor = v < 150 ? s->good : (v < 450 ? s->warn : s->bad);
    } else {
        card.value = nil;
    }
}

- (void)refreshFootnote {
    LRDaemonSettings *ds = [LRDaemonSettings shared];
    NSString *net = [LRNetInfo interfaceKind];
    NSString *note = net;
    if (ds.loaded) {
        NSInteger port = [ds integerForKey:@"socks_port" fallback:11080];
        note = [NSString stringWithFormat:@"%@  ·  SOCKS5 127.0.0.1:%ld", net, (long)port];
    }
    if (_systemProxy && [LRTunnel shared].state == LRTunnelConnected)
        note = [NSString stringWithFormat:@"%@  ·  %@", note, L(@"system proxy")];
    _dashboard.footnote = note;
}

/* the daemon walks pf first and only then sets itself as the system proxy;
   the second covers the apps that follow the proxy settings, not the whole
   mac, and the person should know which one they got */
- (void)askConnectionMode {
    LRTunnel *t = [LRTunnel shared];
    if (t.state != LRTunnelConnected) {
        _modeAsked = NO;
        _systemProxy = NO;
        return;
    }
    if (_modeAsked) return;
    _modeAsked = YES;
    [[LRDaemonClient shared] diagnostics:^(NSArray *facts) {
        BOOL proxy = NO;
        for (LRDiagFact *f in facts)
            if ([f.key isEqualToString:@"backend"] &&
                [f.value rangeOfString:@"system proxy"].location != NSNotFound)
                proxy = YES;
        if (!_modeAsked || [LRTunnel shared].state != LRTunnelConnected) return;
        _systemProxy = proxy;
        [self refreshFootnote];
        if (proxy)
            [LRToast show:L(@"The firewall did not let the traffic through, so LegacyRay became the system proxy: apps that follow it go through the tunnel.")];
    }];
}

- (void)refresh {
    LRTunnel *t = [LRTunnel shared];
    LRPowerState ps = LRPowerOff;
    switch (t.state) {
        case LRTunnelConnected: ps = LRPowerOn; break;
        case LRTunnelConnecting: ps = LRPowerTuning; break;
        case LRTunnelError: ps = LRPowerFault; break;
        default: break;
    }
    if (t.busy && ps == LRPowerOff) ps = LRPowerTuning;
    _dashboard.power.powerState = ps;
    _dashboard.status = [self statusTitle];
    if (t.state == LRTunnelError && [t.lastError length] && ![t.lastError isEqualToString:_shownError]) {
        [LRToast showError:t.lastError];
        [_shownError release];
        _shownError = [t.lastError copy];
    }
    if (t.state != LRTunnelError) {
        [_shownError release];
        _shownError = nil;
    }
    [_sidebar setDaemonOffline:t.state == LRTunnelOffline && ![LRCatalog shared].loaded];
    [self askConnectionMode];
    [self refreshCard];
    [self refreshFootnote];
    [self tick];
}

- (void)tick {
    if (![[self window] isVisible]) return;
    LRTunnel *t = [LRTunnel shared];
    NSString *text;
    if (t.state == LRTunnelConnected)
        text = [NSString stringWithFormat:@"%@    ↓ %@  %@    ↑ %@  %@", LRDuration([t liveUptime]),
                LRBytes(t.bytesDown), LRSpeed(t.speedDown), LRBytes(t.bytesUp), LRSpeed(t.speedUp)];
    else
        text = [self idleDetail];
    _dashboard.detail = text;
}

#pragma mark actions

- (void)powerPressed:(id)sender {
    LRTunnel *t = [LRTunnel shared];
    if (t.state == LRTunnelOffline && ![t isOn]) {
        [[LRAppDelegate shared] startDaemon:nil];
        return;
    }
    [t toggle];
}

- (void)cardClicked:(id)sender {
    LRCatalog *catalog = [LRCatalog shared];
    if ([LRPrefs selectedBackend] == LRBackendAmneziaWG) {
        LRAWGProfile *p = [LRAWGProfiles active];
        if (p) [self openAWGProfile:p];
        return;
    }
    if ([catalog isEmpty]) {
        NSMenu *menu = [self importMenu];
        [menu popUpMenuPositioningItem:nil atLocation:NSMakePoint(0, NSHeight([sender bounds]) + 4) inView:sender];
        return;
    }
    LRServer *sv = [catalog selectedServer];
    if (sv) [self openServer:sv];
}

- (void)cardSwiped:(LRServerCard *)card {
    if ([LRPrefs selectedBackend] == LRBackendAmneziaWG) return;
    [[LRTunnel shared] seek:card.swipeDirection];
    [_sidebar selectCurrent];
}

#pragma mark LRSidebarOwner

- (void)showImportMenuFrom:(NSView *)view {
    NSMenu *menu = [self importMenu];
    [menu popUpMenuPositioningItem:nil atLocation:NSMakePoint(0, [view isFlipped] ? NSHeight([view bounds]) + 2 : -2)
                            inView:view];
}

- (void)openServer:(LRServer *)server {
    [[LRAppDelegate shared] showServer:server];
}

- (void)openSubscription:(LRSubscription *)subscription {
    [[LRAppDelegate shared] showSubscription:subscription];
}

- (void)openAWGProfile:(LRAWGProfile *)profile {
    [[LRAppDelegate shared] showAWGProfile:profile];
}

- (void)shareServer:(LRServer *)server {
    [[LRAppDelegate shared] shareServer:server];
}

- (void)openAWGProfiles {
    [[LRAppDelegate shared] openAWGProfiles:nil];
}

- (void)startDaemon {
    [[LRAppDelegate shared] startDaemon:nil];
}

#pragma mark window

/* sheets drop from under the bar, the way they leave a toolbar */
- (NSRect)window:(NSWindow *)window willPositionSheet:(NSWindow *)sheet usingRect:(NSRect)rect {
    NSView *content = [window contentView];
    rect.origin.y = NSHeight([content frame]) - NSHeight([_header frame]);
    rect.size.height = 0;
    return rect;
}

- (void)windowDidBecomeKey:(NSNotification *)n {
    [self refresh];
}

- (void)windowDidDeminiaturize:(NSNotification *)n {
    [self refresh];
}

/* paste anywhere in the window imports */
- (void)paste:(id)sender {
    [LRImporter pasteFromClipboard];
}

- (BOOL)validateMenuItem:(NSMenuItem *)item {
    if ([item action] == @selector(paste:)) return LRPasteboardString() != nil;
    return YES;
}
@end
