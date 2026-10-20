# LegacyRay.app for os x 10.8 and later, x86_64, built on linux with the
# theos toolchain against the 10.8 sdk from xcode 4.6.3 (see mac/README.md).
#
#   make -C mac            the app, with the daemon and helpers inside it
#   make -C mac zip        packages/LegacyRay-<version>-mac.zip
#   make -C mac clean
#
# manual retain/release, like the ios app: the shared core in
# app/Sources/Core is compiled into both, with this directory's prefix
include ../make/config.mk

LR_MAC_SDK ?= $(THEOS)/sdks/MacOSX10.8.sdk
LR_MAC_MIN ?= 10.8
ifeq ($(wildcard $(LR_MAC_SDK)),)
$(error no os x sdk at $(LR_MAC_SDK): extract MacOSX10.8.sdk from Xcode 4.6.3, see mac/README.md)
endif

MAC_CC   := $(LR_TC)/clang -target x86_64-apple-macosx$(LR_MAC_MIN) -B $(LR_TC)
MAC_ARCH := -arch x86_64 -mmacosx-version-min=$(LR_MAC_MIN) -isysroot $(LR_MAC_SDK)

APP_NAME := LegacyRay
VERSION  := $(shell sed -n 's/^\#define LR_VERSION "\(.*\)"/\1/p' ../app/Sources/LRVersion.h)
BUILD    ?= build
OBJDIR   := $(BUILD)/obj
APP      := $(BUILD)/$(APP_NAME).app
CONTENTS := $(APP)/Contents
BIN      := $(CONTENTS)/MacOS/$(APP_NAME)

CORE     := ../app/Sources/Core
# the core the ios app runs on, minus what only has a uikit face: those are
# reimplemented here with the same headers
CORE_M   := LRDaemonClient LRTunnel LRCatalog LRModels LRStatusStream LRJSON LRLocalization \
            LRActivityLog LRAWGProfiles LRRoutingProfiles LRConnectionCheck LRDaemonSettings \
            LRKaring LRZip LRSSH LRPrefs LRSound LRUpdateChecker
CORE_SRC := $(addprefix $(CORE)/,$(addsuffix .m,$(CORE_M))) $(CORE)/lr_site.c $(CORE)/lr_qr.c

MAC_DIRS := Sources Sources/Skin Sources/Views Sources/Windows Sources/Panes
MAC_SRC  := $(foreach d,$(MAC_DIRS),$(wildcard $(d)/*.m))
C_SRC    := ../daemon/core/b64.c ../daemon/core/control.c ../daemon/core/amnezia_bundle.c \
            ../daemon/core/third_party/cJSON.c

ZBAR     := ../app/third_party/zbar
ZBAR_SRC := $(addprefix $(ZBAR)/zbar/,config.c error.c symbol.c image.c refcnt.c \
            img_scanner.c scanner.c decoder.c misc.c decoder/qr_finder.c \
            qrcode/qrdec.c qrcode/qrdectxt.c qrcode/rs.c qrcode/isaac.c \
            qrcode/bch15_5.c qrcode/binarize.c qrcode/util.c)

objname   = $(OBJDIR)/$(subst /,_,$(subst ../,up_,$(basename $(1)))).o
OBJC_OBJ := $(foreach s,$(MAC_SRC) $(filter %.m,$(CORE_SRC)),$(call objname,$(s)))
C_OBJ    := $(foreach s,$(C_SRC) $(filter %.c,$(CORE_SRC)),$(call objname,$(s)))
ZBAR_OBJ := $(foreach s,$(ZBAR_SRC),$(call objname,$(s)))
ALL_OBJ  := $(OBJC_OBJ) $(C_OBJ) $(ZBAR_OBJ)

INCLUDES := $(addprefix -I,$(MAC_DIRS)) -I../app/Sources -I$(CORE) -I../daemon/core \
            -I../daemon/core/third_party -I../common -I$(ZBAR)/include
WARN     := -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
            -Wno-deprecated-declarations
CFLAGS   := $(MAC_ARCH) -O2 -g0 $(WARN) -DLR_MACOS=1 $(INCLUDES)
OBJCFLAGS := $(CFLAGS) -fno-objc-arc -fblocks -include Sources/LRPrefix.h
ZBARFLAGS := $(MAC_ARCH) -O2 -w -DSENKO_ZBAR_IOS -I$(ZBAR)/include \
             -I$(ZBAR)/zbar -I$(ZBAR)/zbar/decoder -I$(ZBAR)/zbar/qrcode

LDFLAGS  := $(MAC_ARCH) -Wl,-dead_strip \
            -framework Cocoa -framework QuartzCore -framework Security \
            -framework SystemConfiguration -framework AudioToolbox -framework CoreServices \
            -lz -liconv

HELPERS  := ../daemon/build/mac/legacyrayd ../daemon/build/mac/legacyrayctl \
            ../daemon/build/mac/legacyray-kick ../daemon/build/mac/legacyrayawgd \
            ../daemon/build/mac/legacyray-ssh

INSTALLER := $(BUILD)/legacyray-install

.PHONY: all clean helpers zip objs
all: $(BIN)

objs: $(ALL_OBJ)

helpers:
	$(MAKE) -C ../daemon -f Makefile.mac

$(HELPERS): helpers

$(INSTALLER): helper/legacyray-install.c
	@mkdir -p $(BUILD)
	@echo "  c     $<"
	@$(MAC_CC) $(MAC_ARCH) -O2 -Wall -Wextra $< -o $@
	@$(LR_STRIP) -x $@

define compile_objc
$(call objname,$(1)): $(1) $(wildcard Sources/*.h Sources/*/*.h Sources/*.inc $(CORE)/*.h)
	@mkdir -p $(OBJDIR)
	@echo "  objc  $(1)"
	@$(MAC_CC) $(OBJCFLAGS) -c $(1) -o $$@
endef
define compile_c
$(call objname,$(1)): $(1)
	@mkdir -p $(OBJDIR)
	@echo "  c     $(1)"
	@$(MAC_CC) $(CFLAGS) -std=gnu99 -c $(1) -o $$@
endef
define compile_zbar
$(call objname,$(1)): $(1)
	@mkdir -p $(OBJDIR)
	@$(MAC_CC) $(ZBARFLAGS) -c $(1) -o $$@
endef
$(foreach s,$(MAC_SRC) $(filter %.m,$(CORE_SRC)),$(eval $(call compile_objc,$(s))))
$(foreach s,$(C_SRC) $(filter %.c,$(CORE_SRC)),$(eval $(call compile_c,$(s))))
$(foreach s,$(ZBAR_SRC),$(eval $(call compile_zbar,$(s))))

RESOURCES := Resources/LegacyRay.icns Resources/install-helper.sh Resources/uninstall-helper.sh \
             Resources/com.legacyray.daemon.plist Resources/status-globe.png ../app/Resources/denim.png \
             ../app/Resources/denim@2x.png ../app/Resources/click.wav ../app/Resources/clunk.wav \
             ../app/Resources/tick.wav ../app/Resources/THIRD_PARTY_LICENSES.txt ../LICENSE

$(BIN): $(ALL_OBJ) $(HELPERS) $(INSTALLER) $(RESOURCES) ../tweaks/tlsfix/cacert.pem Resources/Info.plist $(wildcard ../app/Resources/server/*.sh)
	@mkdir -p $(CONTENTS)/MacOS $(CONTENTS)/Resources/flags $(CONTENTS)/Resources/server \
	          $(CONTENTS)/Helpers
	@echo "  link  $(APP_NAME)"
	@$(MAC_CC) $(ALL_OBJ) -o $@ $(LDFLAGS)
	@$(LR_STRIP) -x $@
	@sed 's/@VERSION@/$(VERSION)/g' Resources/Info.plist > $(CONTENTS)/Info.plist
	@printf 'APPL????' > $(CONTENTS)/PkgInfo
	@cp $(RESOURCES) $(CONTENTS)/Resources/
	@cp ../app/Resources/flags/*.png $(CONTENTS)/Resources/flags/
	@cp ../app/Resources/server/*.sh $(CONTENTS)/Resources/server/
	@cp $(HELPERS) $(INSTALLER) $(CONTENTS)/Helpers/
	@cp ../tweaks/tlsfix/cacert.pem $(CONTENTS)/Helpers/cacert.pem
	@printf '%s\n' "$(VERSION)" > $(CONTENTS)/Helpers/VERSION
	@chmod 755 $(CONTENTS)/Helpers/* $(CONTENTS)/Resources/*.sh
	@chmod 644 $(CONTENTS)/Helpers/VERSION $(CONTENTS)/Helpers/cacert.pem
	@echo "  built $(APP)"

zip: $(BIN)
	@mkdir -p ../packages
	@rm -f ../packages/$(APP_NAME)-$(VERSION)-mac.zip
	cd $(BUILD) && zip -qry ../../packages/$(APP_NAME)-$(VERSION)-mac.zip $(APP_NAME).app
	@echo "==> packages/$(APP_NAME)-$(VERSION)-mac.zip"

clean:
	rm -rf $(BUILD)
