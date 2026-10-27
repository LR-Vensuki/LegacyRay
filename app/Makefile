# LegacyRay.app for armv7, ios 4-7. manual retain/release throughout: ARC
# needs ios 5 for weak references and libarclite is not part of the theos
# toolchain, so the whole app stays MRC to keep one memory model.
include ../make/config.mk

APP_NAME := LegacyRay
BUILD    ?= build
OBJDIR   := $(BUILD)/obj
APP      := $(BUILD)/$(APP_NAME).app
BIN      := $(APP)/$(APP_NAME)

ZBAR     := third_party/zbar
SRC_DIRS := Sources Sources/Core Sources/Skin Sources/Controls Sources/Screens Sources/iPad
OBJC_SRC := $(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.m))
C_SRC    := $(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.c)) \
            ../daemon/core/b64.c ../daemon/core/control.c \
            ../daemon/core/amnezia_bundle.c ../daemon/core/amnezia_qr.c ../daemon/core/third_party/cJSON.c
ZBAR_SRC := $(addprefix $(ZBAR)/zbar/,config.c error.c symbol.c image.c refcnt.c \
            img_scanner.c scanner.c decoder.c misc.c decoder/qr_finder.c \
            qrcode/qrdec.c qrcode/qrdectxt.c qrcode/rs.c qrcode/isaac.c \
            qrcode/bch15_5.c qrcode/binarize.c qrcode/util.c)

objname   = $(OBJDIR)/$(subst /,_,$(subst ../,up_,$(basename $(1)))).o
OBJC_OBJ := $(foreach s,$(OBJC_SRC),$(call objname,$(s)))
C_OBJ    := $(foreach s,$(C_SRC),$(call objname,$(s)))
ZBAR_OBJ := $(foreach s,$(ZBAR_SRC),$(call objname,$(s)))
ALL_OBJ  := $(OBJC_OBJ) $(C_OBJ) $(ZBAR_OBJ)

INCLUDES := $(addprefix -I,$(SRC_DIRS)) -I../daemon/core -I../daemon/core/third_party \
            -I../common -I$(ZBAR)/include
WARN     := -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
CFLAGS   := $(LR_ARCH) $(LR_SYSROOT) -O2 -g0 $(WARN) $(INCLUDES)
OBJCFLAGS := $(CFLAGS) -fno-objc-arc -fblocks -include Sources/LRPrefix.h
ZBARFLAGS := $(LR_ARCH) $(LR_SYSROOT) -O2 -w -DSENKO_ZBAR_IOS -I$(ZBAR)/include \
             -I$(ZBAR)/zbar -I$(ZBAR)/zbar/decoder -I$(ZBAR)/zbar/qrcode

# camera and media frameworks are weak: the code checks for them at runtime
LDFLAGS  := $(LR_ARCH) $(LR_SYSROOT) -Wl,-dead_strip \
            -framework UIKit -framework Foundation -framework CoreGraphics \
            -framework QuartzCore -framework CFNetwork -framework SystemConfiguration \
            -framework AudioToolbox -framework MessageUI \
            -weak_framework AVFoundation -weak_framework CoreMedia \
            -weak_framework CoreVideo -lz -liconv

RESOURCES := Resources/Info.plist $(wildcard Resources/*.png) $(wildcard Resources/*.txt) \
             $(wildcard Resources/*.wav)

.PHONY: all clean
all: $(BIN)

define compile_objc
$(call objname,$(1)): $(1) $(wildcard Sources/*.h Sources/*/*.h Sources/*/*.inc)
	@mkdir -p $(OBJDIR)
	@echo "  objc  $(1)"
	@$(LR_CC) $(OBJCFLAGS) -c $(1) -o $$@
endef
define compile_c
$(call objname,$(1)): $(1)
	@mkdir -p $(OBJDIR)
	@echo "  c     $(1)"
	@$(LR_CC) $(CFLAGS) -std=gnu99 -c $(1) -o $$@
endef
define compile_zbar
$(call objname,$(1)): $(1)
	@mkdir -p $(OBJDIR)
	@$(LR_CC) $(ZBARFLAGS) -c $(1) -o $$@
endef
$(foreach s,$(OBJC_SRC),$(eval $(call compile_objc,$(s))))
$(foreach s,$(C_SRC),$(eval $(call compile_c,$(s))))
$(foreach s,$(ZBAR_SRC),$(eval $(call compile_zbar,$(s))))

$(BIN): $(ALL_OBJ) $(RESOURCES) Resources/entitlements.plist $(wildcard Resources/server/*.sh)
	@mkdir -p $(APP)/flags $(APP)/server
	@echo "  link  $(APP_NAME)"
	@$(LR_CC) $(ALL_OBJ) -o $@ $(LDFLAGS)
	@$(LR_STRIP) -x $@
	@python3 ../scripts/set_sdk_version.py $@ 7.0
	@$(LR_LDID) -SResources/entitlements.plist $@
	@cp $(RESOURCES) $(APP)/
	@cp Resources/flags/*.png $(APP)/flags/
	@cp Resources/server/*.sh $(APP)/server/
	@printf 'APPL????' > $(APP)/PkgInfo
	@echo "  built $(APP)"

clean:
	rm -rf $(BUILD)
