APP_NAME = Tapkey
BUNDLE = $(APP_NAME).app
BIN = $(BUNDLE)/Contents/MacOS/tapkey
IDENTITY ?= Developer ID Application
NIX := ./run-in-nix.sh -c

.PHONY: all build build-wasm build-ffi sign install verify clean test test-core test-web verify-core-parity

all: build sign

build:
	$(NIX) "cargo build --release -p tapkey"
	@mkdir -p $(BUNDLE)/Contents/MacOS
	@cp mac/Info.plist $(BUNDLE)/Contents/Info.plist
	@cp target/release/tapkey $(BIN)
	@echo "Built $(BUNDLE)"

build-wasm:
	$(NIX) "wasm-pack build --target web web/wasm --out-dir ../pkg"
	@echo "Built web/pkg/"

sign:
	codesign --force --options runtime --timestamp \
		--sign "$(IDENTITY)" \
		--entitlements mac/tapkey.entitlements $(BUNDLE)
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

test: test-core test-web
	@echo "All tests passed."

test-core:
	$(NIX) "cargo test -p tapkey-core"
	@echo "Core tests passed."

test-web:
	$(NIX) "wasm-pack test --node web/wasm"
	@echo "Web (WASM) tests passed."

verify-core-parity: test-core test-web
	@echo "Core parity verified: Rust and WASM produce identical outputs."

clean:
	rm -rf $(BUNDLE)
	rm -rf target
	rm -rf web/pkg
