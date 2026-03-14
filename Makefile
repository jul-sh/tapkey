APP_NAME = Tapkey
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/tapkey
IDENTITY ?= Developer ID Application

.PHONY: all build sign install verify clean

all: build sign

build:
	@mkdir -p $(BUNDLE)/Contents/MacOS
	@cp Info.plist $(BUNDLE)/Contents/Info.plist
	swiftc -O -target arm64-apple-macos15.0 \
		-framework AuthenticationServices -framework AppKit \
		Sources/Tapkey.swift -o $(BIN)
	@echo "Built $(BUNDLE)"

sign:
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements tapkey.entitlements $(BUNDLE)
	@echo "Signed $(BUNDLE)"

INSTALL_DIR = $(HOME)/.local/share/tapkey
INSTALL_BUNDLE = $(INSTALL_DIR)/$(BUNDLE)
INSTALL_BIN = $(INSTALL_BUNDLE)/Contents/MacOS/tapkey

install: all
	@mkdir -p $(HOME)/.local/bin
	@rm -rf $(INSTALL_BUNDLE)
	@mkdir -p $(INSTALL_DIR)
	@cp -R $(BUNDLE) $(INSTALL_BUNDLE)
	@ln -sf $(INSTALL_BIN) $(HOME)/.local/bin/tapkey
	@echo "Installed: $(INSTALL_BUNDLE)"
	@echo "Symlinked: ~/.local/bin/tapkey -> $(INSTALL_BIN)"

verify:
	codesign -dvv $(BUNDLE) 2>&1
	@echo ""
	codesign -d --entitlements :- $(BUNDLE)

clean:
	rm -rf $(BUNDLE)
