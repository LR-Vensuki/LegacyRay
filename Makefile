# LegacyRay: the whole package, built with the theos toolchain.
#
#   make deps       fetch and build static openssl + mbedtls (once)
#   make            daemon, tweaks and the app
#   make package    packages/com.legacyray.app_<version>_iphoneos-arm.deb
#                   (LR_ENGINE=<path> also ships the rust engine)
#   make install    copy the .deb to THEOS_DEVICE_IP and dpkg -i it
#   make test       the host test suite (needs `make deps HOST=1` first)
#   make xcode      regenerate xcode/LegacyRay.xcodeproj
#   make clean
#
# see make/config.mk for the toolchain variables (THEOS, LR_SDK, ...)
include make/config.mk

VERSION := $(shell sed -n 's/^\#define LR_VERSION "\(.*\)"/\1/p' app/Sources/LRVersion.h)
PLIST_VERSION := $(shell sed -n '/CFBundleShortVersionString/{n;s/.*<string>\(.*\)<\/string>.*/\1/p;}' app/Resources/Info.plist)
CONTROL_VERSION := $(shell sed -n 's/^Version: //p' layout/DEBIAN/control)
PACKAGE := com.legacyray.app
DEB := packages/$(PACKAGE)_$(VERSION)_iphoneos-arm.deb
STAGE := .stage

# the rust engine (an armv7 build of shoes) is optional: without it the
# daemon runs its built-in core. point LR_ENGINE at the binary to ship it
LR_ENGINE ?=

# theos' own packer runs on linux and os x alike and always writes root:wheel
LR_DEB_TOOL ?= $(if $(wildcard $(THEOS)/bin/dm.pl),$(THEOS)/bin/dm.pl,dpkg-deb --root-owner-group)

THEOS_DEVICE_IP ?=
THEOS_DEVICE_PORT ?= 22
THEOS_DEVICE_USER ?= root

.PHONY: all deps daemon tweaks app package install test xcode clean check-version resources

all: check-version daemon tweaks app

check-version:
	@if [ "$(VERSION)" != "$(PLIST_VERSION)" ] || [ "$(VERSION)" != "$(CONTROL_VERSION)" ]; then \
		echo "version mismatch: LRVersion.h=$(VERSION) Info.plist=$(PLIST_VERSION) control=$(CONTROL_VERSION)"; \
		exit 1; fi

deps:
	./scripts/build_deps.sh $(if $(HOST),host,)

daemon:
	$(MAKE) -C daemon -f Makefile.ios

tweaks:
	$(MAKE) -C tweaks/tlsfix
	$(MAKE) -C tweaks/status

app:
	$(MAKE) -C app

resources:
	python3 scripts/make_resources.py

package: all
	@rm -rf $(STAGE)
	@mkdir -p $(STAGE) packages
	cp -R layout/. $(STAGE)/
	@find $(STAGE) -name '.gitkeep' -delete
	mkdir -p $(STAGE)/usr/bin $(STAGE)/usr/lib/legacyraytlsfix/roots $(STAGE)/Applications \
	         $(STAGE)/usr/share/doc/legacyray
	cp daemon/build/ios/legacyrayd daemon/build/ios/legacyrayctl daemon/build/ios/legacyray-kick \
	   daemon/build/ios/legacyrayawgd daemon/build/ios/legacyray-ssh $(STAGE)/usr/bin/
	cp tweaks/tlsfix/build/legacyraytlsfix.dylib tweaks/status/build/legacyraystatus.dylib $(STAGE)/usr/lib/
	cp tweaks/status/legacyraystatus.plist $(STAGE)/usr/lib/legacyraystatus.plist
	cp tweaks/tlsfix/substrate-filter.plist tweaks/tlsfix/cacert.pem $(STAGE)/usr/lib/legacyraytlsfix/
	cp tweaks/tlsfix/roots/*.pem $(STAGE)/usr/lib/legacyraytlsfix/roots/
	cp -R app/build/LegacyRay.app $(STAGE)/Applications/
	cp LICENSE $(STAGE)/usr/share/doc/legacyray/LICENSE
	cp app/Resources/THIRD_PARTY_LICENSES.txt $(STAGE)/usr/share/doc/legacyray/
	$(if $(LR_ENGINE),cp $(LR_ENGINE) $(STAGE)/usr/lib/legacyray-engine)
	find $(STAGE) -type d -exec chmod 755 {} +
	find $(STAGE) -type f -exec chmod 644 {} +
	chmod 755 $(STAGE)/DEBIAN/postinst $(STAGE)/DEBIAN/prerm $(STAGE)/DEBIAN/postrm
	chmod 755 $(STAGE)/usr/bin/* $(STAGE)/usr/lib/*.dylib $(STAGE)/Applications/LegacyRay.app \
	          $(STAGE)/Applications/LegacyRay.app/LegacyRay
	chmod 4755 $(STAGE)/usr/bin/legacyray-kick
	@# the daemon starts the engine only when it may execute it
	[ ! -e $(STAGE)/usr/lib/legacyray-engine ] || chmod 755 $(STAGE)/usr/lib/legacyray-engine
	find $(STAGE)/Applications/LegacyRay.app -type f ! -name LegacyRay -exec chmod 644 {} +
	find $(STAGE)/usr/lib/legacyraytlsfix -type f -exec chmod 644 {} +
	@printf 'Installed-Size: %s\n' "$$(du -sk $(STAGE) | cut -f1)" >> $(STAGE)/DEBIAN/control
	$(LR_DEB_TOOL) -Z$(LR_DEB_COMPRESSION) -b $(STAGE) $(DEB)
	@rm -rf $(STAGE)
	@echo "==> $(DEB)"

install: package
	@if [ -z "$(THEOS_DEVICE_IP)" ]; then echo "set THEOS_DEVICE_IP=<device ip>"; exit 1; fi
	scp -P $(THEOS_DEVICE_PORT) $(DEB) $(THEOS_DEVICE_USER)@$(THEOS_DEVICE_IP):/var/mobile/
	ssh -p $(THEOS_DEVICE_PORT) $(THEOS_DEVICE_USER)@$(THEOS_DEVICE_IP) \
		"dpkg -i /var/mobile/$(notdir $(DEB)) && rm -f /var/mobile/$(notdir $(DEB))"

test:
	LIBRARY_PATH=$(LR_DEPS)/openssl-host/lib C_INCLUDE_PATH=$(LR_DEPS)/openssl-host/include \
		$(MAKE) -C tests test TLS_LDFLAGS="-lssl -lcrypto -ldl -pthread"

xcode:
	python3 scripts/gen_xcodeproj.py

clean:
	$(MAKE) -C daemon -f Makefile.ios clean
	$(MAKE) -C tweaks/tlsfix clean
	$(MAKE) -C tweaks/status clean
	$(MAKE) -C app clean
	rm -rf $(STAGE)

CYDIA_REPO = $(HOME)/Theos-Projects/cydia-repo

publish:: package
	@python3 $(CYDIA_REPO)/tools/repo.py publish $(CURDIR) $(if $(MSG),-m "$(MSG)")
