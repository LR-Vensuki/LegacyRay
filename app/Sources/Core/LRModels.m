#import "LRModels.h"

@implementation LRServer
@synthesize index = _index, selected = _selected, group = _group, proto = _proto,
            net = _net, security = _security, supported = _supported, host = _host,
            port = _port, remark = _remark;

- (void)dealloc {
    [_proto release];
    [_net release];
    [_security release];
    [_host release];
    [_remark release];
    [super dealloc];
}

/* a pair of regional indicator symbols (U+1F1E6..U+1F1FF) spells a flag. in
   utf-16 each one is the surrogate pair D83C DDE6..DDFF */
static NSString *LRFlagCodeInText(NSString *text, NSRange *outRange) {
    NSUInteger n = [text length];
    for (NSUInteger i = 0; i + 3 < n; ++i) {
        unichar a = [text characterAtIndex:i], b = [text characterAtIndex:i + 1];
        unichar c = [text characterAtIndex:i + 2], d = [text characterAtIndex:i + 3];
        if (a == 0xD83C && b >= 0xDDE6 && b <= 0xDDFF &&
            c == 0xD83C && d >= 0xDDE6 && d <= 0xDDFF) {
            if (outRange) *outRange = NSMakeRange(i, 4);
            unichar code[2] = { (unichar)('a' + (b - 0xDDE6)), (unichar)('a' + (d - 0xDDE6)) };
            return [NSString stringWithCharacters:code length:2];
        }
    }
    return nil;
}

- (NSString *)countryCode {
    NSString *code = LRFlagCodeInText(_remark ? _remark : @"", NULL);
    if (code) return [code isEqualToString:@"uk"] ? @"gb" : code;
    /* "NL-3 Amsterdam", "[DE] Frankfurt", "US | New York" */
    NSString *r = [_remark stringByTrimmingCharactersInSet:
                   [NSCharacterSet characterSetWithCharactersInString:@" [](){}|-_"]];
    if ([r length] >= 2) {
        NSString *head = [r substringToIndex:2];
        BOOL upper = YES;
        for (NSUInteger i = 0; i < 2; ++i) {
            unichar ch = [head characterAtIndex:i];
            if (ch < 'A' || ch > 'Z') upper = NO;
        }
        if (upper && ([r length] == 2 || ![[NSCharacterSet letterCharacterSet]
                                          characterIsMember:[r characterAtIndex:2]])) {
            NSString *lower = [head lowercaseString];
            return [lower isEqualToString:@"uk"] ? @"gb" : lower;
        }
    }
    return nil;
}

- (NSString *)displayName {
    NSMutableString *name = [NSMutableString stringWithString:_remark ? _remark : @""];
    NSRange flag;
    while (LRFlagCodeInText(name, &flag)) [name deleteCharactersInRange:flag];
    /* variation selectors and other emoji leftovers */
    NSMutableString *clean = [NSMutableString string];
    for (NSUInteger i = 0; i < [name length]; ++i) {
        unichar ch = [name characterAtIndex:i];
        if (ch == 0xFE0F || ch == 0x200D) continue;
        [clean appendFormat:@"%C", ch];
    }
    NSString *out = [clean stringByReplacingOccurrencesOfString:@"_" withString:@" "];
    while ([out rangeOfString:@"  "].location != NSNotFound)
        out = [out stringByReplacingOccurrencesOfString:@"  " withString:@" "];
    out = [out stringByTrimmingCharactersInSet:
           [NSCharacterSet characterSetWithCharactersInString:@" -|·"]];
    if ([out length]) return out;
    if ([_host length]) return [NSString stringWithFormat:@"%@:%d", _host, _port];
    return @"—";
}

- (NSString *)protocolSummary {
    NSMutableArray *parts = [NSMutableArray array];
    NSString *proto = [_proto length] ? [_proto uppercaseString] : @"VLESS";
    if ([proto isEqualToString:@"SS"]) proto = @"SHADOWSOCKS";
    [parts addObject:proto];
    if ([_security length] && ![_security isEqualToString:@"none"] &&
        ![_security isEqualToString:@"unknown"] && ![proto isEqualToString:@"SHADOWSOCKS"])
        [parts addObject:[_security uppercaseString]];
    if ([_net length] && ![_net isEqualToString:@"tcp"] &&
        ([proto isEqualToString:@"VLESS"] || [proto isEqualToString:@"VMESS"] ||
         [proto isEqualToString:@"TROJAN"]))
        [parts addObject:[_net uppercaseString]];
    return [parts componentsJoinedByString:@" · "];
}
@end

@implementation LRSubscription
@synthesize index = _index, name = _name, url = _url, header = _header, expire = _expire,
            upload = _upload, download = _download, total = _total, summary = _summary,
            supportURL = _supportURL, updateIntervalHours = _updateIntervalHours,
            refillDate = _refillDate, webPageURL = _webPageURL,
            routingLink = _routingLink;

- (void)dealloc {
    [_name release];
    [_url release];
    [_header release];
    [_summary release];
    [_supportURL release];
    [_webPageURL release];
    [_routingLink release];
    [super dealloc];
}

- (unsigned long long)used {
    return _upload + _download;
}

- (double)usageFraction {
    if (_total == 0) return -1.0;
    double f = (double)[self used] / (double)_total;
    return f < 0 ? 0 : (f > 1 ? 1 : f);
}

- (NSInteger)daysLeft {
    if (_expire == 0) return NSIntegerMax;
    double left = (double)_expire - [[NSDate date] timeIntervalSince1970];
    return (NSInteger)ceil(left / 86400.0);
}
@end

@implementation LRRule
@synthesize index = _index, action = _action, type = _type, value = _value, hits = _hits;
- (void)dealloc {
    [_action release];
    [_type release];
    [_value release];
    [super dealloc];
}
@end

@implementation LRDiagFact
@synthesize key = _key, value = _value;
- (void)dealloc {
    [_key release];
    [_value release];
    [super dealloc];
}
@end

@implementation LRCheckStage
@synthesize name = _name, ms = _ms, ok = _ok;
- (void)dealloc {
    [_name release];
    [super dealloc];
}
@end
