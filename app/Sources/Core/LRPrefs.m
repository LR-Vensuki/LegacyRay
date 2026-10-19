#import "LRPrefs.h"
#include "senko_paths.h"
#import "LRAWGProfiles.h"

NSString * const LRPrefsDidChangeNotification = @"LRPrefsDidChangeNotification";

static NSUserDefaults *D(void) { return [NSUserDefaults standardUserDefaults]; }

static void LRChanged(void) {
    [D() synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:LRPrefsDidChangeNotification
                                                        object:nil];
}

static BOOL LRBool(NSString *key, BOOL fallback) {
    id v = [D() objectForKey:key];
    return v ? [v boolValue] : fallback;
}

@implementation LRPrefs

+ (LRThemeSetting)theme {
    NSInteger v = [D() integerForKey:@"LRTheme"];
    if (v == LRThemeOldNight || v == LRThemeOldTimed) return LRThemeClassic;
    return (v == LRThemeClassic || v == LRThemeFlat) ? (LRThemeSetting)v : LRThemeAuto;
}

+ (BOOL)systemIsFlat {
    static int cached = -1;
#if defined(LR_MACOS)
    /* os x went flat with yosemite */
    if (cached < 0) cached = LRMacSystemAtLeast(10, 10) ? 1 : 0;
#else
    if (cached < 0) cached = LR_SYSTEM_AT_LEAST(@"7.0") ? 1 : 0;
#endif
    return cached == 1;
}

+ (BOOL)flatSkinActive {
    LRThemeSetting t = [self theme];
    if (t == LRThemeFlat) return YES;
    if (t == LRThemeAuto) return [self systemIsFlat];
    return NO;
}

+ (void)setTheme:(LRThemeSetting)theme {
    [D() setInteger:theme forKey:@"LRTheme"];
    LRChanged();
}

+ (BOOL)stealthMode { return LRBool(@"LRStealth", NO); }
+ (void)setStealthMode:(BOOL)on { [D() setBool:on forKey:@"LRStealth"]; LRChanged(); }

+ (LRPingType)pingType {
    NSInteger v = [D() integerForKey:@"LRPingType"];
    return (v >= LRPingTCP && v <= LRPingProxyGET) ? (LRPingType)v : LRPingTCP;
}
+ (void)setPingType:(LRPingType)type { [D() setInteger:type forKey:@"LRPingType"]; LRChanged(); }

+ (NSString *)pingModeName {
    switch ([self pingType]) {
        case LRPingHandshake: return @"handshake";
        case LRPingProxyGET: return @"proxy";
        case LRPingTCP: break;
    }
    return @"tcp";
}

+ (LRSortMode)sortMode {
    NSInteger v = [D() integerForKey:@"LRSort"];
    return (v >= LRSortManual && v <= LRSortPing) ? (LRSortMode)v : LRSortManual;
}
+ (void)setSortMode:(LRSortMode)mode { [D() setInteger:mode forKey:@"LRSort"]; LRChanged(); }

+ (BOOL)refreshSubscriptionsOnOpen { return LRBool(@"LRRefreshOnOpen", YES); }
+ (void)setRefreshSubscriptionsOnOpen:(BOOL)on { [D() setBool:on forKey:@"LRRefreshOnOpen"]; LRChanged(); }

+ (BOOL)automaticUpdateChecks { return LRBool(@"LRUpdateChecks", YES); }
+ (void)setAutomaticUpdateChecks:(BOOL)on { [D() setBool:on forKey:@"LRUpdateChecks"]; LRChanged(); }
+ (NSDate *)lastUpdateCheck { return [D() objectForKey:@"LRLastUpdateCheck"]; }
+ (void)setLastUpdateCheck:(NSDate *)date {
    [D() setObject:date forKey:@"LRLastUpdateCheck"];
    [D() synchronize];
}

+ (BOOL)preferGitHubLegacy { return LRBool(@"LRGitHubLegacy", NO); }
+ (void)setPreferGitHubLegacy:(BOOL)on { [D() setBool:on forKey:@"LRGitHubLegacy"]; LRChanged(); }

+ (BOOL)activityLogging { return LRBool(@"LRActivity", YES); }
+ (void)setActivityLogging:(BOOL)on { [D() setBool:on forKey:@"LRActivity"]; LRChanged(); }

+ (BOOL)soundEffects { return LRBool(@"LRSounds", YES); }
+ (void)setSoundEffects:(BOOL)on { [D() setBool:on forKey:@"LRSounds"]; LRChanged(); }

+ (BOOL)sectionCollapsed:(NSString *)key {
    if (![key length]) return NO;
    return [[D() arrayForKey:@"LRCollapsed"] containsObject:key];
}

+ (void)setSection:(NSString *)key collapsed:(BOOL)collapsed {
    if (![key length]) return;
    NSMutableArray *list = [NSMutableArray arrayWithArray:[D() arrayForKey:@"LRCollapsed"]];
    [list removeObject:key];
    if (collapsed) [list addObject:key];
    [D() setObject:list forKey:@"LRCollapsed"];
    [D() synchronize];
}

+ (LRBackend)selectedBackend {
    return [D() integerForKey:@"LRBackend"] == LRBackendAmneziaWG && [self hasAWGProfile]
        ? LRBackendAmneziaWG : LRBackendServer;
}
+ (void)setSelectedBackend:(LRBackend)backend {
    [D() setInteger:backend forKey:@"LRBackend"];
    [D() synchronize];
}

+ (NSString *)awgProfilePath {
    return [[LRAWGProfiles active] path];
}

+ (BOOL)hasAWGProfile {
    return [LRAWGProfiles hasProfiles];
}

#define LR_POWER_CONF @SENKO_POWER_CONF
#define LR_TLS_VERBOSE @SENKO_DATA_DIR "/tlsfix-verbose"

+ (LRAWGKeepaliveMode)awgKeepalive {
    NSInteger v = [D() integerForKey:@"LRAWGKeepalive"];
    return v >= LRAWGKeepaliveConfig && v <= LRAWGKeepaliveOff ? (LRAWGKeepaliveMode)v : LRAWGKeepaliveConfig;
}

+ (void)setAWGKeepalive:(LRAWGKeepaliveMode)mode {
    [D() setInteger:mode forKey:@"LRAWGKeepalive"];
    [D() synchronize];
    NSString *word = mode == LRAWGKeepaliveOff ? @"off" : mode == LRAWGKeepaliveScreen ? @"screen" : @"config";
    [[NSString stringWithFormat:@"awg_keepalive=%@\n", word] writeToFile:LR_POWER_CONF atomically:YES
                                                                  encoding:NSUTF8StringEncoding error:NULL];
    LRChanged();
}

+ (BOOL)tlsHookVerbose {
    return [[NSFileManager defaultManager] fileExistsAtPath:LR_TLS_VERBOSE];
}

+ (void)setTLSHookVerbose:(BOOL)on {
    if (on) [@"1\n" writeToFile:LR_TLS_VERBOSE atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    else [[NSFileManager defaultManager] removeItemAtPath:LR_TLS_VERBOSE error:NULL];
    LRChanged();
}

+ (BOOL)consumeFirstLaunch {
    if ([D() boolForKey:@"LRLaunchedBefore"]) return NO;
    [D() setBool:YES forKey:@"LRLaunchedBefore"];
    [D() synchronize];
    return YES;
}
@end

NSString *LRStealth(NSString *text) {
    if (![LRPrefs stealthMode] || ![text length]) return text;
    NSUInteger n = [text length];
    if (n <= 4) return @"••••";
    /* keep the scheme so a link still reads as a link */
    NSRange scheme = [text rangeOfString:@"://"];
    NSString *head = scheme.location != NSNotFound && scheme.location < 12
        ? [text substringToIndex:scheme.location + 3] : [text substringToIndex:2];
    return [head stringByAppendingString:@"••••••"];
}
