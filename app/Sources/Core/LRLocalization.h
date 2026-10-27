/* strings are written in english in the code and looked up in the tables in
   LRStrings.m. a missing translation falls back to the english text, so a
   new string is never blank, only untranslated */
#import <Foundation/Foundation.h>

typedef enum {
    LRLanguageAuto = 0,
    LRLanguageEnglish,
    LRLanguageRussian,
    LRLanguageChinese
} LRLanguage;

extern NSString * const LRLanguageDidChangeNotification;

NSString *LRLocalized(NSString *english);
#define L(s) LRLocalized(s)

/* the language in effect: the setting, or the system language when Auto */
LRLanguage LRCurrentLanguage(void);
LRLanguage LRLanguageSetting(void);
void LRSetLanguageSetting(LRLanguage language);
NSString *LRLanguageName(LRLanguage language);

/* a sentence the daemon wrote about a failed check, translated. its one
   standalone number (a port, an http status, a clock difference) is %@ in the
   table */
NSString *LRCheckReasonText(NSString *english);

/* russian needs three plural forms; english and chinese use the first two */
NSString *LRPlural(NSInteger n, NSString *one, NSString *few, NSString *many);

/* the table lookup, implemented in LRStrings.m */
NSString *LRStringsLookup(NSString *english, LRLanguage language);
