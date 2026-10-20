/* the drawing primitives the mac app is built from: the ios ones
   (app/Sources/Skin/LRDraw.m) in core graphics with NSColor, plus the pieces
   only a mac window has (the bar keys, the source list badges). views that
   use them are flipped, so the coordinates read the same as on ios */
#import <Cocoa/Cocoa.h>
#import "LRSkin.h"

typedef enum {
    LRPlateSingle = 0,
    LRPlateTop,
    LRPlateMiddle,
    LRPlateBottom
} LRPlatePosition;

/* paths and fills */
void LRAddRoundRect(CGContextRef ctx, CGRect r, CGFloat radius);
void LRFillVertical(CGContextRef ctx, CGRect r, NSColor *top, NSColor *bottom);
/* colors: NSColor array; locations may be NULL for even spacing */
void LRFillLinear(CGContextRef ctx, CGPoint start, CGPoint end, NSArray *colors, const CGFloat *locations);
void LRFillRadial(CGContextRef ctx, CGPoint center, CGFloat r0, CGFloat r1, NSColor *inner, NSColor *outer);

/* the denim of the icon: a 105 point twill tile from the bundle */
NSImage *LRDenimTile(void);
/* fill with the twill as a pattern anchored to the window, so the title
   bar and the bar under it continue one cloth; shade darkens it */
void LRDrawDenim(NSRect r, CGFloat shade);
/* a soft light in the middle of the dashboard and dark corners */
void LRDrawVignette(CGContextRef ctx, CGRect r, CGPoint focus);

/* copper thread, sewn: a dashed line with the shadow of its holes */
void LRDrawStitchLine(CGContextRef ctx, CGPoint a, CGPoint b);
void LRDrawStitchCircle(CGContextRef ctx, CGPoint c, CGFloat radius);
void LRDrawStitchRoundRect(CGContextRef ctx, CGRect r, CGFloat radius);

/* the card: a white plate on the denim, or a flat card with a hairline */
void LRAddCellPath(CGContextRef ctx, CGRect r, LRPlatePosition position, CGFloat radius);
void LRDrawGroupCell(CGContextRef ctx, CGRect r, LRPlatePosition position, BOOL pressed, BOOL onDark);
void LRDrawChevron(CGContextRef ctx, CGPoint c, CGFloat size, BOOL down, NSColor *color, CGFloat width);
void LRDrawCheckmark(CGContextRef ctx, CGPoint start, NSColor *color);
/* a status lamp */
void LRDrawLED(CGContextRef ctx, CGPoint c, CGFloat radius, NSColor *color, BOOL on);

/* a key on the denim bar: the ios 6 bar button, dark glass in a pressed
   rim; flat: nothing until pressed */
void LRDrawBarKey(CGContextRef ctx, CGRect r, BOOL pressed, BOOL enabled);
/* the count badge of a source list row (mail's unread pill) */
void LRDrawPill(CGContextRef ctx, CGRect r, NSColor *fill);

/* text into the current graphics context */
NSDictionary *LRTextAttributes(NSFont *font, NSColor *color, NSTextAlignment align);
void LRDrawText(NSString *text, NSRect rect, NSFont *font, NSColor *color, NSTextAlignment align);
void LRDrawEngraved(NSString *text, NSRect rect, NSFont *font, NSTextAlignment align,
                    NSColor *color, NSColor *shadow, CGFloat dy);
NSSize LRTextSize(NSString *text, NSFont *font);

/* flags from the bundle: flags/flag-xx.png */
NSImage *LRFlagImage(NSString *code);
/* a round badge with a little glass on it */
void LRDrawFlag(CGContextRef ctx, NSString *code, CGRect rect);

NSColor *LRColorMix(NSColor *a, NSColor *b, CGFloat t);
NSColor *LRColorAlpha(NSColor *c, CGFloat alpha);
void LRFlushSkinCaches(void);

/* glyphs for keys and menus: the system's own template art, inked */
NSImage *LRGlyphPlus(CGFloat side, NSColor *ink);
NSImage *LRGlyphGear(CGFloat side, NSColor *ink);
NSImage *LRGlyphList(CGFloat side, NSColor *ink);
/* the menu bar icon: a ray in a ring; template, so the menu bar inks it */
NSImage *LRStatusItemImage(int state);   /* 0 off, 1 connecting, 2 on, 3 fault */
