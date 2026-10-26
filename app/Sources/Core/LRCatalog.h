/* the station log: servers grouped into sections (one per subscription plus
   the manual one), in the daemon's section order, with the latency readings
   the app took. screens observe LRCatalogDidChangeNotification for structure
   changes and LRCatalogPingNotification for new readings */
#import <Foundation/Foundation.h>
#import "LRModels.h"

extern NSString * const LRCatalogDidChangeNotification;
extern NSString * const LRCatalogPingNotification;

/* reading placeholders in the ping table */
#define LR_PING_FAILED   (-1)
#define LR_PING_RUNNING  (-3)

@interface LRSection : NSObject {
    int _sectionId;
    LRSubscription *_subscription;
    NSString *_title;
    NSString *_countryCode;
    NSArray *_servers;
    NSArray *_shownNames;
}
/* the subscription index, -1 for manual servers */
@property (nonatomic, assign) int sectionId;
@property (nonatomic, retain) LRSubscription *subscription;
@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *countryCode;
@property (nonatomic, retain) NSArray *servers;
/* per row display names with the banner every row shares cut off */
@property (nonatomic, retain) NSArray *shownNames;
- (BOOL)isManual;
- (BOOL)collapsed;
- (NSString *)collapseKey;
- (NSString *)nameForServer:(LRServer *)server;
@end

@interface LRCatalog : NSObject {
    NSArray *_servers;
    NSArray *_subscriptions;
    NSArray *_order;
    NSArray *_sections;
    NSMutableDictionary *_pings;
    BOOL _loaded;
    BOOL _loading;
    int _selectedIndex;
    BOOL _adoptDaemonSelection;
    NSUInteger _pingGeneration;
    NSMutableArray *_pingQueue;
    NSUInteger _pingInFlight;
    NSString *_lastError;
    NSArray *_bestCandidates;
    void (^_bestDone)(LRServer *best, int ms);
}
@property (nonatomic, readonly) NSArray *servers;
@property (nonatomic, readonly) NSArray *subscriptions;
@property (nonatomic, readonly) NSArray *sections;
@property (nonatomic, readonly) BOOL loaded;
@property (nonatomic, readonly) BOOL loading;
@property (nonatomic, copy) NSString *lastError;
/* the server the power button connects, -1 when nothing is selected */
@property (nonatomic, assign) int selectedIndex;

+ (LRCatalog *)shared;

- (void)reload;
- (void)reload:(void (^)(BOOL ok))done;
- (void)rebuildSections;

- (LRServer *)serverWithIndex:(int)index;
- (LRSubscription *)subscriptionWithIndex:(int)index;
- (LRSection *)sectionForServer:(LRServer *)server;
- (LRServer *)selectedServer;
/* reload and take the daemon's selection: the tunnel came up on a server
   chosen somewhere else (the terminal, another copy of the app) */
- (void)adoptDaemonSelection;
- (NSString *)displayNameForServer:(LRServer *)server;
/* the next / previous server after the selected one, wrapping across sections */
- (LRServer *)serverAfterSelected:(NSInteger)step;
- (BOOL)isEmpty;

/* latency */
- (NSNumber *)pingForServer:(LRServer *)server;
- (void)pingServers:(NSArray *)servers;
- (void)pingAll;
- (void)cancelPings;
- (BOOL)pinging;
- (void)forgetPings;
/* measure the given servers with the current ping type and answer with the
   fastest that replied (nil when none did). one pick at a time */
- (void)pickFastestOf:(NSArray *)servers done:(void (^)(LRServer *best, int ms))done;

- (void)setSection:(LRSection *)section collapsed:(BOOL)collapsed;
- (void)moveSection:(LRSection *)section toPosition:(NSUInteger)position;
- (void)refreshAllSubscriptions:(void (^)(NSUInteger ok, NSUInteger failed))done;
@end
