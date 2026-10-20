#import "LRAboutWindowController.h"
#import "LRBlocks.h"
#import "LRDraw.h"
#import "LRAlert.h"
#import "LRUpdateChecker.h"
#import "LRVersion.h"

@interface LRAboutView : NSView
@end

@implementation LRAboutView

- (BOOL)isFlipped {
    return YES;
}

- (void)drawRect:(NSRect)dirty {
    CGContextRef ctx = (CGContextRef)[[NSGraphicsContext currentContext] graphicsPort];
    NSRect b = [self bounds];
    LRSkin *s = SKIN;
    CGFloat top = 196;
    if (s->flat) {
        [[NSColor whiteColor] setFill];
        NSRectFill(b);
    } else {
        LRDrawDenim(NSMakeRect(0, 0, NSWidth(b), top), 0.12f);
        LRDrawVignette(ctx, CGRectMake(0, 0, NSWidth(b), top), CGPointMake(NSMidX(b), 80));
        LRDrawStitchLine(ctx, CGPointMake(0, top - 6.5f), CGPointMake(NSWidth(b), top - 6.5f));
        CGContextSetRGBFillColor(ctx, 0, 0, 0, 0.9f);
        CGContextFillRect(ctx, CGRectMake(0, top - 1, NSWidth(b), 1));
        [[NSColor windowBackgroundColor] setFill];
        NSRectFill(NSMakeRect(0, top, NSWidth(b), NSHeight(b) - top));
        LRFillVertical(ctx, CGRectMake(0, top, NSWidth(b), 6), [NSColor colorWithCalibratedWhite:0 alpha:0.25f],
                       [NSColor colorWithCalibratedWhite:0 alpha:0]);
    }
    NSImage *icon = [NSImage imageNamed:@"LegacyRay"];
    if (!icon) icon = [NSApp applicationIconImage];
    NSRect ir = NSMakeRect(round(NSMidX(b) - 64), 14, 128, 128);
    [icon drawInRect:ir fromRect:NSZeroRect operation:NSCompositeSourceOver fraction:1 respectFlipped:YES hints:nil];
    NSRect nr = NSMakeRect(20, 146, NSWidth(b) - 40, 26);
    if (s->flat) LRDrawText(@"LegacyRay", nr, [LRSkin lightFont:22], s->pageInk, NSCenterTextAlignment);
    else LRDrawEngraved(@"LegacyRay", nr, [LRSkin titleFont:21], NSCenterTextAlignment, [NSColor whiteColor],
                        [NSColor colorWithCalibratedWhite:0 alpha:0.8f], -1);
    NSString *version = [NSString stringWithFormat:L(@"Version %s (%s) for OS X"), LR_VERSION, LR_BUILD_NUMBER];
    LRDrawText(version, NSMakeRect(20, top + 14, NSWidth(b) - 40, 17), [NSFont systemFontOfSize:12],
               [NSColor colorWithCalibratedWhite:0.3f alpha:1], NSCenterTextAlignment);
    LRDrawText(@LR_DEVELOPER, NSMakeRect(20, top + 32, NSWidth(b) - 40, 17), [NSFont boldSystemFontOfSize:12],
               [NSColor colorWithCalibratedWhite:0.2f alpha:1], NSCenterTextAlignment);
    NSString *text = L(@"VLESS, Reality, Trojan, Shadowsocks, SOCKS and AmneziaWG for the whole Mac. A fork of senko (GPL-2.0); the network core comes from it, the rest is new. OpenSSL, libssh2, ZBar and cJSON inside. Menu bar icon by Glyphish (glyphish.com), CC BY 3.0.");
    NSMutableParagraphStyle *p = [[[NSMutableParagraphStyle alloc] init] autorelease];
    [p setAlignment:NSCenterTextAlignment];
    [text drawWithRect:NSMakeRect(30, top + 58, NSWidth(b) - 60, 74) options:NSStringDrawingUsesLineFragmentOrigin
            attributes:[NSDictionary dictionaryWithObjectsAndKeys:[NSFont systemFontOfSize:11], NSFontAttributeName,
                        [NSColor colorWithCalibratedWhite:0.4f alpha:1], NSForegroundColorAttributeName,
                        p, NSParagraphStyleAttributeName, nil]];
}
@end

@implementation LRAboutWindowController

- (id)init {
    NSWindow *w = [[[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 380, 380)
                                               styleMask:NSTitledWindowMask | NSClosableWindowMask
                                                 backing:NSBackingStoreBuffered defer:YES] autorelease];
    [w setTitle:L(@"About LegacyRay")];
    [w setReleasedWhenClosed:NO];
    if ((self = [super initWithWindow:w])) {
        LRAboutView *v = [[[LRAboutView alloc] initWithFrame:NSMakeRect(0, 0, 380, 380)] autorelease];
        [w setContentView:v];
        NSButton *github = LRPushButton(@"GitHub", ^(id s) { [LRUpdateChecker openProjectPage]; });
        NSButton *licenses = LRPushButton(L(@"Licenses"), ^(id s) {
            NSString *p = [[NSBundle mainBundle] pathForResource:@"THIRD_PARTY_LICENSES" ofType:@"txt"];
            if (p) [[NSWorkspace sharedWorkspace] openFile:p withApplication:@"TextEdit"];
        });
        [licenses setFrameOrigin:NSMakePoint(190 - NSWidth([licenses frame]) - 2, 334)];
        [github setFrameOrigin:NSMakePoint(192, 334)];
        [v addSubview:licenses];
        [v addSubview:github];
        [w center];
    }
    return self;
}
@end
