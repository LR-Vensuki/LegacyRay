#import "LRDraw.h"
#import "LRCompat.h"

#pragma mark colors

static void LRRGBA(NSColor *color, CGFloat out[4]) {
    NSColor *c = [color colorUsingColorSpaceName:NSCalibratedRGBColorSpace];
    if (!c) {
        out[0] = out[1] = out[2] = 0;
        out[3] = 1;
        return;
    }
    out[0] = [c redComponent];
    out[1] = [c greenComponent];
    out[2] = [c blueComponent];
    out[3] = [c alphaComponent];
}

NSColor *LRColorMix(NSColor *a, NSColor *b, CGFloat t) {
    CGFloat x[4], y[4];
    LRRGBA(a, x);
    LRRGBA(b, y);
    return [NSColor colorWithCalibratedRed:x[0] + (y[0] - x[0]) * t green:x[1] + (y[1] - x[1]) * t
                                      blue:x[2] + (y[2] - x[2]) * t alpha:x[3] + (y[3] - x[3]) * t];
}

NSColor *LRColorAlpha(NSColor *c, CGFloat alpha) {
    CGFloat x[4];
    LRRGBA(c, x);
    return [NSColor colorWithCalibratedRed:x[0] green:x[1] blue:x[2] alpha:alpha];
}

static NSColor *W(CGFloat white, CGFloat alpha) {
    return [NSColor colorWithCalibratedWhite:white alpha:alpha];
}

static void LRSetFill(CGContextRef ctx, NSColor *c) {
    CGFloat v[4];
    LRRGBA(c, v);
    CGContextSetRGBFillColor(ctx, v[0], v[1], v[2], v[3]);
}

static void LRSetStroke(CGContextRef ctx, NSColor *c) {
    CGFloat v[4];
    LRRGBA(c, v);
    CGContextSetRGBStrokeColor(ctx, v[0], v[1], v[2], v[3]);
}

#pragma mark paths and fills

void LRAddRoundRect(CGContextRef ctx, CGRect r, CGFloat radius) {
    radius = MIN(radius, MIN(r.size.width, r.size.height) / 2);
    CGFloat minx = CGRectGetMinX(r), midx = CGRectGetMidX(r), maxx = CGRectGetMaxX(r);
    CGFloat miny = CGRectGetMinY(r), midy = CGRectGetMidY(r), maxy = CGRectGetMaxY(r);
    CGContextMoveToPoint(ctx, minx, midy);
    CGContextAddArcToPoint(ctx, minx, miny, midx, miny, radius);
    CGContextAddArcToPoint(ctx, maxx, miny, maxx, midy, radius);
    CGContextAddArcToPoint(ctx, maxx, maxy, midx, maxy, radius);
    CGContextAddArcToPoint(ctx, minx, maxy, minx, midy, radius);
    CGContextClosePath(ctx);
}

static CGGradientRef LRCreateGradient(NSArray *colors, const CGFloat *locations) {
    CGColorSpaceRef space = CGColorSpaceCreateDeviceRGB();
    size_t n = [colors count];
    CGFloat *comps = malloc(sizeof(CGFloat) * 4 * (n ? n : 1));
    for (size_t i = 0; i < n; ++i) LRRGBA([colors objectAtIndex:i], comps + i * 4);
    CGGradientRef g = CGGradientCreateWithColorComponents(space, comps, locations, n);
    free(comps);
    CGColorSpaceRelease(space);
    return g;
}

void LRFillLinear(CGContextRef ctx, CGPoint start, CGPoint end, NSArray *colors, const CGFloat *locations) {
    CGGradientRef g = LRCreateGradient(colors, locations);
    CGContextDrawLinearGradient(ctx, g, start, end,
                                kCGGradientDrawsBeforeStartLocation | kCGGradientDrawsAfterEndLocation);
    CGGradientRelease(g);
}

void LRFillVertical(CGContextRef ctx, CGRect r, NSColor *top, NSColor *bottom) {
    CGContextSaveGState(ctx);
    CGContextClipToRect(ctx, r);
    LRFillLinear(ctx, CGPointMake(0, CGRectGetMinY(r)), CGPointMake(0, CGRectGetMaxY(r)),
                 [NSArray arrayWithObjects:top, bottom, nil], NULL);
    CGContextRestoreGState(ctx);
}

void LRFillRadial(CGContextRef ctx, CGPoint center, CGFloat r0, CGFloat r1, NSColor *inner, NSColor *outer) {
    CGGradientRef g = LRCreateGradient([NSArray arrayWithObjects:inner, outer, nil], NULL);
    CGContextDrawRadialGradient(ctx, g, center, r0, center, r1, kCGGradientDrawsAfterEndLocation);
    CGGradientRelease(g);
}

#pragma mark caches

static NSMutableDictionary *gCache = nil;

static id LRCached(NSString *key) {
    return [gCache objectForKey:key];
}

static void LRCache(NSString *key, id value) {
    if (!gCache) gCache = [[NSMutableDictionary alloc] init];
    if (value) [gCache setObject:value forKey:key];
}

void LRFlushSkinCaches(void) {
    NSMutableArray *drop = [NSMutableArray array];
    for (NSString *key in gCache)
        if (![key hasPrefix:@"tile."]) [drop addObject:key];
    [gCache removeObjectsForKeys:drop];
}

#pragma mark denim

NSImage *LRDenimTile(void) {
    NSImage *img = LRCached(@"tile.denim");
    if (img) return img;
    NSBundle *b = [NSBundle mainBundle];
    NSString *p1 = [b pathForResource:@"denim" ofType:@"png"];
    NSString *p2 = [b pathForResource:@"denim@2x" ofType:@"png"];
    NSImageRep *r1 = p1 ? [NSImageRep imageRepWithContentsOfFile:p1] : nil;
    if (!r1) return nil;
    NSSize pt = NSMakeSize([r1 pixelsWide], [r1 pixelsHigh]);
    [r1 setSize:pt];
    img = [[[NSImage alloc] initWithSize:pt] autorelease];
    [img addRepresentation:r1];
    /* the retina tile was woven for its own pixel grid; it must stay the
       same 105 points so both reps tile the same cloth */
    NSImageRep *r2 = p2 ? [NSImageRep imageRepWithContentsOfFile:p2] : nil;
    if (r2) {
        [r2 setSize:pt];
        [img addRepresentation:r2];
    }
    LRCache(@"tile.denim", img);
    return img;
}

void LRDrawDenim(NSRect r, CGFloat shade) {
    NSGraphicsContext *gc = [NSGraphicsContext currentContext];
    [gc saveGraphicsState];
    NSImage *tile = LRDenimTile();
    [(tile ? [NSColor colorWithPatternImage:tile] : W(0.10f, 1)) setFill];
    NSRectFillUsingOperation(r, NSCompositeSourceOver);
    if (shade > 0) {
        [W(0, shade) setFill];
        NSRectFillUsingOperation(r, NSCompositeSourceOver);
    }
    [gc restoreGraphicsState];
}

void LRDrawVignette(CGContextRef ctx, CGRect r, CGPoint focus) {
    CGContextSaveGState(ctx);
    CGContextClipToRect(ctx, r);
    CGFloat far = 0;
    CGPoint corners[4] = { { CGRectGetMinX(r), CGRectGetMinY(r) }, { CGRectGetMaxX(r), CGRectGetMinY(r) },
                           { CGRectGetMinX(r), CGRectGetMaxY(r) }, { CGRectGetMaxX(r), CGRectGetMaxY(r) } };
    for (int i = 0; i < 4; ++i)
        far = MAX(far, hypot(corners[i].x - focus.x, corners[i].y - focus.y));
    CGFloat locs[3] = { 0, 0.42f, 1 };
    CGGradientRef g = LRCreateGradient([NSArray arrayWithObjects:W(1, 0.07f), W(0, 0), W(0, 0.55f), nil], locs);
    CGContextDrawRadialGradient(ctx, g, focus, 0, focus, far, kCGGradientDrawsAfterEndLocation);
    CGGradientRelease(g);
    CGContextRestoreGState(ctx);
}

#pragma mark thread

static void LRStitchPasses(CGContextRef ctx, void (^path)(CGFloat dy), CGFloat on, CGFloat off) {
    if (SKIN->flat) return;
    CGFloat dash[2] = { on, off };
    for (int pass = 0; pass < 2; ++pass) {
        CGContextSaveGState(ctx);
        CGContextSetLineDash(ctx, 0, dash, 2);
        CGContextSetLineCap(ctx, kCGLineCapButt);
        if (pass == 0) {
            CGContextSetRGBStrokeColor(ctx, 0, 0, 0, 0.55f);
            CGContextSetLineWidth(ctx, 1.9f);
        } else {
            LRSetStroke(ctx, SKIN->stitch);
            CGContextSetLineWidth(ctx, 1.3f);
        }
        CGContextBeginPath(ctx);
        path(pass == 0 ? 0.8f : 0);
        CGContextStrokePath(ctx);
        CGContextRestoreGState(ctx);
    }
}

void LRDrawStitchLine(CGContextRef ctx, CGPoint a, CGPoint b) {
    LRStitchPasses(ctx, ^(CGFloat dy) {
        CGContextMoveToPoint(ctx, a.x, a.y + dy);
        CGContextAddLineToPoint(ctx, b.x, b.y + dy);
    }, 4.0f, 2.5f);
}

void LRDrawStitchCircle(CGContextRef ctx, CGPoint c, CGFloat radius) {
    CGFloat circ = (CGFloat)M_PI * 2 * radius;
    CGFloat n = MAX(8.0f, roundf(circ / 6.5f));
    CGFloat on = circ / n * 0.64f, off = circ / n - on;
    LRStitchPasses(ctx, ^(CGFloat dy) {
        CGContextAddEllipseInRect(ctx, CGRectMake(c.x - radius, c.y - radius + dy, radius * 2, radius * 2));
    }, on, off);
}

void LRDrawStitchRoundRect(CGContextRef ctx, CGRect r, CGFloat radius) {
    LRStitchPasses(ctx, ^(CGFloat dy) {
        LRAddRoundRect(ctx, CGRectOffset(r, 0, dy), radius);
    }, 4.0f, 2.5f);
}

#pragma mark the card

void LRAddCellPath(CGContextRef ctx, CGRect r, LRPlatePosition position, CGFloat radius) {
    BOOL top = position == LRPlateSingle || position == LRPlateTop;
    BOOL bottom = position == LRPlateSingle || position == LRPlateBottom;
    CGFloat minx = CGRectGetMinX(r), maxx = CGRectGetMaxX(r), midx = CGRectGetMidX(r);
    CGFloat miny = CGRectGetMinY(r), maxy = CGRectGetMaxY(r);
    radius = MIN(radius, r.size.height / 2);
    CGContextMoveToPoint(ctx, minx, top ? miny + radius : miny);
    if (top) {
        CGContextAddArcToPoint(ctx, minx, miny, midx, miny, radius);
        CGContextAddArcToPoint(ctx, maxx, miny, maxx, miny + radius, radius);
    } else {
        CGContextAddLineToPoint(ctx, maxx, miny);
    }
    if (bottom) {
        CGContextAddArcToPoint(ctx, maxx, maxy, midx, maxy, radius);
        CGContextAddArcToPoint(ctx, minx, maxy, minx, maxy - radius, radius);
    } else {
        CGContextAddLineToPoint(ctx, maxx, maxy);
        CGContextAddLineToPoint(ctx, minx, maxy);
    }
    CGContextClosePath(ctx);
}

void LRDrawGroupCell(CGContextRef ctx, CGRect r, LRPlatePosition position, BOOL pressed, BOOL onDark) {
    LRSkin *s = SKIN;
    const CGFloat radius = s->flat ? 12 : 10;
    if (s->flat) {
        LRAddCellPath(ctx, r, position, radius);
        LRSetFill(ctx, pressed ? s->groupPressed : s->groupTop);
        CGContextFillPath(ctx);
        LRAddCellPath(ctx, CGRectInset(r, 0.5f, 0.5f), position, radius);
        LRSetStroke(ctx, s->separator);
        CGContextSetLineWidth(ctx, 1);
        CGContextStrokePath(ctx);
        return;
    }
    CGContextSaveGState(ctx);
    CGRect body = r;
    body.size.height -= 1;
    if (!onDark) {
        LRAddCellPath(ctx, CGRectOffset(body, 0, 1), position, radius);
        CGContextSetRGBFillColor(ctx, 1, 1, 1, 0.8f);
        CGContextFillPath(ctx);
    }
    CGContextSaveGState(ctx);
    LRAddCellPath(ctx, body, position, radius);
    CGContextClip(ctx);
    if (pressed) LRFillVertical(ctx, body, s->groupPressed, s->groupPressedBottom);
    else if (onDark) LRFillVertical(ctx, body, W(0.992f, 1), W(0.906f, 1));
    else LRFillVertical(ctx, body, s->groupTop, s->groupBottom);
    /* the lit top lip */
    CGContextSetRGBFillColor(ctx, 1, 1, 1, pressed ? 0.25f : 0.9f);
    CGContextFillRect(ctx, CGRectMake(body.origin.x, body.origin.y + 1, body.size.width, 1));
    CGContextRestoreGState(ctx);
    LRAddCellPath(ctx, CGRectInset(body, 0.5f, 0.5f), position, radius - 0.5f);
    if (onDark) CGContextSetRGBStrokeColor(ctx, 0, 0, 0, 0.8f);
    else LRSetStroke(ctx, s->groupEdge);
    CGContextSetLineWidth(ctx, 1);
    CGContextStrokePath(ctx);
    CGContextRestoreGState(ctx);
}

void LRDrawChevron(CGContextRef ctx, CGPoint c, CGFloat size, BOOL down, NSColor *color, CGFloat width) {
    CGContextSaveGState(ctx);
    LRSetStroke(ctx, color);
    CGContextSetLineWidth(ctx, width);
    CGContextSetLineCap(ctx, kCGLineCapSquare);
    CGContextSetLineJoin(ctx, kCGLineJoinMiter);
    if (down) {
        CGContextMoveToPoint(ctx, c.x - size, c.y - size * 0.5f);
        CGContextAddLineToPoint(ctx, c.x, c.y + size * 0.5f);
        CGContextAddLineToPoint(ctx, c.x + size, c.y - size * 0.5f);
    } else {
        CGContextMoveToPoint(ctx, c.x - size * 0.5f, c.y - size);
        CGContextAddLineToPoint(ctx, c.x + size * 0.5f, c.y);
        CGContextAddLineToPoint(ctx, c.x - size * 0.5f, c.y + size);
    }
    CGContextStrokePath(ctx);
    CGContextRestoreGState(ctx);
}

void LRDrawCheckmark(CGContextRef ctx, CGPoint p, NSColor *color) {
    CGContextSaveGState(ctx);
    LRSetStroke(ctx, color);
    CGContextSetLineWidth(ctx, SKIN->flat ? 2 : 2.6f);
    CGContextSetLineCap(ctx, kCGLineCapRound);
    CGContextSetLineJoin(ctx, kCGLineJoinRound);
    CGContextMoveToPoint(ctx, p.x, p.y);
    CGContextAddLineToPoint(ctx, p.x + 4, p.y + 4.5f);
    CGContextAddLineToPoint(ctx, p.x + 11, p.y - 6);
    CGContextStrokePath(ctx);
    CGContextRestoreGState(ctx);
}

void LRDrawLED(CGContextRef ctx, CGPoint c, CGFloat r, NSColor *color, BOOL on) {
    CGRect disc = CGRectMake(c.x - r, c.y - r, r * 2, r * 2);
    if (SKIN->flat) {
        LRSetFill(ctx, on ? color : SKIN->ledOff);
        CGContextFillEllipseInRect(ctx, disc);
        return;
    }
    CGContextSaveGState(ctx);
    CGContextSetRGBFillColor(ctx, 1, 1, 1, 0.55f);
    CGContextFillEllipseInRect(ctx, CGRectOffset(disc, 0, 0.8f));
    LRSetFill(ctx, on ? color : W(0.72f, 1));
    CGContextFillEllipseInRect(ctx, disc);
    CGContextAddEllipseInRect(ctx, disc);
    CGContextClip(ctx);
    LRFillRadial(ctx, CGPointMake(c.x - r * 0.3f, c.y - r * 0.4f), 0, r * 1.2f, W(1, 0.6f), W(1, 0));
    CGContextRestoreGState(ctx);
    CGContextSetRGBStrokeColor(ctx, 0, 0, 0, 0.35f);
    CGContextSetLineWidth(ctx, 0.8f);
    CGContextStrokeEllipseInRect(ctx, CGRectInset(disc, 0.4f, 0.4f));
}

#pragma mark keys and badges

void LRDrawBarKey(CGContextRef ctx, CGRect r, BOOL pressed, BOOL enabled) {
    if (SKIN->flat) {
        if (!pressed) return;
        LRAddRoundRect(ctx, r, 5);
        CGContextSetRGBFillColor(ctx, 0, 0, 0, 0.08f);
        CGContextFillPath(ctx);
        return;
    }
    CGContextSaveGState(ctx);
    if (!enabled) CGContextSetAlpha(ctx, 0.5f);
    /* the light the bar throws under the key */
    LRAddRoundRect(ctx, CGRectOffset(r, 0, 1), 5);
    CGContextSetRGBFillColor(ctx, 1, 1, 1, 0.12f);
    CGContextFillPath(ctx);
    /* the rim */
    LRAddRoundRect(ctx, r, 5);
    CGContextSetRGBFillColor(ctx, 0, 0, 0, 0.75f);
    CGContextFillPath(ctx);
    CGRect inner = CGRectInset(r, 1, 1);
    CGContextSaveGState(ctx);
    LRAddRoundRect(ctx, inner, 4);
    CGContextClip(ctx);
    if (pressed)
        LRFillVertical(ctx, inner, W(0.06f, 1), W(0.16f, 1));
    else {
        /* dark glass with denim behind it */
        LRFillVertical(ctx, inner, W(0.36f, 0.9f), W(0.14f, 0.92f));
        CGFloat half = inner.size.height / 2;
        LRFillVertical(ctx, CGRectMake(inner.origin.x, inner.origin.y, inner.size.width, half),
                       W(1, 0.16f), W(1, 0.05f));
    }
    if (pressed) {
        /* the shadow of the rim on a sunk key */
        LRFillVertical(ctx, CGRectMake(inner.origin.x, inner.origin.y, inner.size.width, 4),
                       W(0, 0.5f), W(0, 0));
    }
    CGContextRestoreGState(ctx);
    if (!pressed) {
        CGContextSetRGBStrokeColor(ctx, 1, 1, 1, 0.18f);
        CGContextSetLineWidth(ctx, 1);
        CGContextMoveToPoint(ctx, inner.origin.x + 3, inner.origin.y + 0.5f);
        CGContextAddLineToPoint(ctx, CGRectGetMaxX(inner) - 3, inner.origin.y + 0.5f);
        CGContextStrokePath(ctx);
    }
    CGContextRestoreGState(ctx);
}

void LRDrawPill(CGContextRef ctx, CGRect r, NSColor *fill) {
    CGFloat radius = r.size.height / 2;
    CGContextSaveGState(ctx);
    if (!SKIN->flat) {
        LRAddRoundRect(ctx, CGRectOffset(r, 0, 1), radius);
        CGContextSetRGBFillColor(ctx, 1, 1, 1, 0.55f);
        CGContextFillPath(ctx);
    }
    LRAddRoundRect(ctx, r, radius);
    LRSetFill(ctx, fill);
    CGContextFillPath(ctx);
    if (!SKIN->flat) {
        /* the inner shadow mail's badges have at the top */
        LRAddRoundRect(ctx, r, radius);
        CGContextClip(ctx);
        LRFillVertical(ctx, CGRectMake(r.origin.x, r.origin.y, r.size.width, 3), W(0, 0.18f), W(0, 0));
    }
    CGContextRestoreGState(ctx);
}

#pragma mark text

NSDictionary *LRTextAttributes(NSFont *font, NSColor *color, NSTextAlignment align) {
    NSMutableParagraphStyle *p = [[[NSMutableParagraphStyle alloc] init] autorelease];
    [p setAlignment:align];
    [p setLineBreakMode:NSLineBreakByTruncatingTail];
    return [NSDictionary dictionaryWithObjectsAndKeys:font, NSFontAttributeName,
            color ? color : [NSColor blackColor], NSForegroundColorAttributeName,
            p, NSParagraphStyleAttributeName, nil];
}

void LRDrawText(NSString *text, NSRect rect, NSFont *font, NSColor *color, NSTextAlignment align) {
    if (![text length]) return;
    [text drawWithRect:rect options:NSStringDrawingTruncatesLastVisibleLine | NSStringDrawingUsesLineFragmentOrigin
            attributes:LRTextAttributes(font, color, align)];
}

void LRDrawEngraved(NSString *text, NSRect rect, NSFont *font, NSTextAlignment align,
                    NSColor *color, NSColor *shadow, CGFloat dy) {
    if (![text length]) return;
    if (shadow) LRDrawText(text, NSOffsetRect(rect, 0, dy), font, shadow, align);
    LRDrawText(text, rect, font, color, align);
}

NSSize LRTextSize(NSString *text, NSFont *font) {
    if (![text length]) return NSZeroSize;
    NSSize s = [text sizeWithAttributes:[NSDictionary dictionaryWithObject:font forKey:NSFontAttributeName]];
    return NSMakeSize(ceil(s.width), ceil(s.height));
}

#pragma mark flags

NSImage *LRFlagImage(NSString *code) {
    if ([code length] != 2) return nil;
    NSString *key = [@"tile.flag." stringByAppendingString:[code lowercaseString]];
    NSImage *img = LRCached(key);
    if (img) return img;
    NSString *path = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"flags/flag-%@.png", [code lowercaseString]]];
    img = [[[NSImage alloc] initWithContentsOfFile:path] autorelease];
    if (img) LRCache(key, img);
    return img;
}

static void LRDrawImageInRect(CGContextRef ctx, NSImage *img, CGRect r) {
    NSGraphicsContext *gc = [NSGraphicsContext currentContext];
    BOOL flipped = [gc isFlipped];
    [img drawInRect:NSRectFromCGRect(r) fromRect:NSZeroRect operation:NSCompositeSourceOver
           fraction:1 respectFlipped:YES hints:nil];
    (void)flipped;
    (void)ctx;
}

void LRDrawFlag(CGContextRef ctx, NSString *code, CGRect disc) {
    NSImage *img = LRFlagImage(code);
    if (SKIN->flat) {
        CGContextSaveGState(ctx);
        CGContextAddEllipseInRect(ctx, disc);
        CGContextClip(ctx);
        if (img) LRDrawImageInRect(ctx, img, disc);
        else { LRSetFill(ctx, SKIN->separator); CGContextFillRect(ctx, disc); }
        CGContextRestoreGState(ctx);
        CGContextSetRGBStrokeColor(ctx, 0, 0, 0, 0.12f);
        CGContextSetLineWidth(ctx, 0.5f);
        CGContextStrokeEllipseInRect(ctx, CGRectInset(disc, 0.25f, 0.25f));
        return;
    }
    CGContextSaveGState(ctx);
    CGContextSetRGBFillColor(ctx, 0, 0, 0, 0.25f);
    CGContextFillEllipseInRect(ctx, CGRectOffset(disc, 0, 0.6f));
    CGContextAddEllipseInRect(ctx, disc);
    CGContextClip(ctx);
    if (img) LRDrawImageInRect(ctx, img, disc);
    else LRFillVertical(ctx, disc, W(0.80f, 1), W(0.62f, 1));
    LRFillVertical(ctx, CGRectMake(disc.origin.x, disc.origin.y, disc.size.width, disc.size.height / 2),
                   W(1, 0.35f), W(1, 0.06f));
    CGContextRestoreGState(ctx);
    CGContextSetRGBStrokeColor(ctx, 0, 0, 0, 0.28f);
    CGContextSetLineWidth(ctx, 1);
    CGContextStrokeEllipseInRect(ctx, CGRectInset(disc, 0.5f, 0.5f));
}

#pragma mark glyphs

static NSString *LRInkKey(NSString *name, CGFloat side, NSColor *ink) {
    CGFloat v[4];
    LRRGBA(ink, v);
    return [NSString stringWithFormat:@"glyph.%@.%.1f.%.3f.%.3f.%.3f.%.3f", name, side, v[0], v[1], v[2], v[3]];
}

/* a system template image (black on clear) kept to its own shape, fitted
   into a side x side square and inked. pdf art may grow, bitmaps only shrink */
static NSImage *LRSystemGlyph(NSString *name, CGFloat side, NSColor *ink) {
    NSString *key = LRInkKey(name, side, ink);
    NSImage *img = LRCached(key);
    if (img) return img;
    NSImage *art = [NSImage imageNamed:name];
    NSSize n = art ? [art size] : NSZeroSize;
    if (n.width <= 0 || n.height <= 0) return nil;
    BOOL vector = NO;
    for (NSImageRep *rep in [art representations])
        if ([rep isKindOfClass:[NSPDFImageRep class]]) vector = YES;
    CGFloat k = MIN(side / n.width, side / n.height);
    if (!vector) k = MIN(k, 1);
    NSSize g = NSMakeSize(roundf(n.width * k), roundf(n.height * k));
    NSColor *c = [[ink copy] autorelease];
    img = LRImageWithSize(NSMakeSize(side, side), YES, ^(CGContextRef ctx, CGRect r) {
        CGRect box = CGRectMake(floorf((side - g.width) / 2), floorf((side - g.height) / 2), g.width, g.height);
        [art drawInRect:NSRectFromCGRect(box) fromRect:NSZeroRect operation:NSCompositeSourceOver
               fraction:1 respectFlipped:YES hints:nil];
        /* keep the art's coverage, take the ink's colour */
        CGContextSetBlendMode(ctx, kCGBlendModeSourceIn);
        LRSetFill(ctx, c);
        CGContextFillRect(ctx, r);
    });
    LRCache(key, img);
    return img;
}

NSImage *LRGlyphPlus(CGFloat side, NSColor *ink) {
    return LRSystemGlyph(NSImageNameAddTemplate, side, ink);
}

NSImage *LRGlyphGear(CGFloat side, NSColor *ink) {
    return LRSystemGlyph(NSImageNameActionTemplate, side, ink);
}

NSImage *LRGlyphList(CGFloat side, NSColor *ink) {
    return LRSystemGlyph(NSImageNameListViewTemplate, side, ink);
}

/* the globe from glyphish (glyphish.com, cc by 3.0, credited in about).
   off and connecting are the globe faded, on is the globe whole, a fault
   takes a bite out of its corner and puts a dot in it */
NSImage *LRStatusItemImage(int state) {
    NSString *key = [NSString stringWithFormat:@"tile.status.%d", state];
    NSImage *img = LRCached(key);
    if (img) return img;
    static NSImage *globe = nil;
    if (!globe) {
        NSString *path = [[NSBundle mainBundle] pathForResource:@"status-globe" ofType:@"png"];
        globe = path ? [[NSImage alloc] initWithContentsOfFile:path] : nil;
    }
    NSImage *art = globe;
    img = LRImageWithSize(NSMakeSize(18, 18), YES, ^(CGContextRef ctx, CGRect r) {
        CGFloat alpha = state == 0 ? 0.4f : state == 1 ? 0.6f : 1;
        if (art) {
            [[NSGraphicsContext currentContext] setImageInterpolation:NSImageInterpolationHigh];
            [art drawInRect:NSMakeRect(1, 1, 16, 16) fromRect:NSZeroRect operation:NSCompositeSourceOver
                   fraction:alpha respectFlipped:YES hints:nil];
        } else {
            /* a bundle without the art still shows something to click */
            CGContextSetRGBStrokeColor(ctx, 0, 0, 0, alpha);
            CGContextSetLineWidth(ctx, 1.5f);
            CGContextStrokeEllipseInRect(ctx, CGRectMake(2, 2, 14, 14));
        }
        if (state == 3) {
            CGContextSetBlendMode(ctx, kCGBlendModeClear);
            CGContextFillEllipseInRect(ctx, CGRectMake(11, 0, 7, 7));
            CGContextSetBlendMode(ctx, kCGBlendModeNormal);
            CGContextSetRGBFillColor(ctx, 0, 0, 0, 1);
            CGContextFillEllipseInRect(ctx, CGRectMake(12.5f, 1.5f, 4, 4));
        }
    });
    [img setTemplate:YES];
    LRCache(key, img);
    return img;
}
