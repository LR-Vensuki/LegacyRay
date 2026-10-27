#import "LRLocalization.h"

NSString * const LRLanguageDidChangeNotification = @"LRLanguageDidChangeNotification";
static NSString * const kLanguageKey = @"LRLanguage";

LRLanguage LRLanguageSetting(void) {
    NSInteger v = [[NSUserDefaults standardUserDefaults] integerForKey:kLanguageKey];
    if (v < LRLanguageAuto || v > LRLanguageChinese) v = LRLanguageAuto;
    return (LRLanguage)v;
}

void LRSetLanguageSetting(LRLanguage language) {
    [[NSUserDefaults standardUserDefaults] setInteger:language forKey:kLanguageKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:LRLanguageDidChangeNotification
                                                        object:nil];
}

LRLanguage LRCurrentLanguage(void) {
    LRLanguage setting = LRLanguageSetting();
    if (setting != LRLanguageAuto) return setting;
    NSArray *preferred = [NSLocale preferredLanguages];
    NSString *first = [preferred count] ? [[preferred objectAtIndex:0] lowercaseString] : @"en";
    if ([first hasPrefix:@"ru"] || [first hasPrefix:@"uk"] || [first hasPrefix:@"be"] ||
        [first hasPrefix:@"kk"])
        return LRLanguageRussian;
    if ([first hasPrefix:@"zh"]) return LRLanguageChinese;
    return LRLanguageEnglish;
}

NSString *LRLanguageName(LRLanguage language) {
    switch (language) {
        case LRLanguageEnglish: return @"English";
        case LRLanguageRussian: return @"Русский";
        case LRLanguageChinese: return @"中文";
        case LRLanguageAuto: break;
    }
    return LRLocalized(@"System");
}

NSString *LRLocalized(NSString *english) {
    if (![english length]) return english;
    LRLanguage language = LRCurrentLanguage();
    if (language == LRLanguageEnglish) return english;
    NSString *hit = LRStringsLookup(english, language);
    return hit ? hit : english;
}

NSString *LRCheckReasonText(NSString *english) {
    if (![english length] || LRCurrentLanguage() == LRLanguageEnglish) return english;
    NSString *hit = LRStringsLookup(english, LRCurrentLanguage());
    if (hit) return hit;
    NSUInteger n = [english length];
    for (NSUInteger i = 0; i < n; ++i) {
        unichar ch = [english characterAtIndex:i];
        if (ch < '0' || ch > '9') continue;
        if (i > 0) {
            unichar prev = [english characterAtIndex:i - 1];
            if ((prev >= '0' && prev <= '9') || (prev >= 'A' && prev <= 'Z') ||
                (prev >= 'a' && prev <= 'z')) continue;
        }
        NSUInteger end = i;
        while (end < n && [english characterAtIndex:end] >= '0' &&
               [english characterAtIndex:end] <= '9') ++end;
        NSString *number = [english substringWithRange:NSMakeRange(i, end - i)];
        NSString *key = [NSString stringWithFormat:@"%@%%@%@",
                         [english substringToIndex:i], [english substringFromIndex:end]];
        hit = LRStringsLookup(key, LRCurrentLanguage());
        return hit ? [hit stringByReplacingOccurrencesOfString:@"%@" withString:number]
                   : english;
    }
    return english;
}

NSString *LRPlural(NSInteger n, NSString *one, NSString *few, NSString *many) {
    NSInteger a = n < 0 ? -n : n;
    if (LRCurrentLanguage() != LRLanguageRussian) return a == 1 ? one : many;
    NSInteger mod10 = a % 10, mod100 = a % 100;
    if (mod10 == 1 && mod100 != 11) return one;
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return few;
    return many;
}
