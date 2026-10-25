# php2shell-audit - exposure scanner and threat hunter for CVE-2026-109618/9
#
# Zero third-party dependencies: a plain Go toolchain is all that is required.

GO      ?= go
BIN     ?= bin/p2s
PREFIX  ?= /usr/local
PKG     := github.com/darkLabz001/php2shell-audit
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/buildinfo.Version=$(VERSION) \
	-X $(PKG)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(PKG)/internal/buildinfo.Date=$(DATE)

GOFLAGS ?=

.DEFAULT_GOAL := all

.PHONY: all
all: lint test build ## Run the linters, the tests and build the binary

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary into ./bin
	@mkdir -p $(dir $(BIN))
	$(GO) build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/p2s
	@echo "built $(BIN)"

.PHONY: install
install: build ## Install the binary into $(PREFIX)/bin
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 $(BIN) "$(DESTDIR)$(PREFIX)/bin/p2s"
	@echo "installed $(DESTDIR)$(PREFIX)/bin/p2s"

.PHONY: tui
tui: build ## Open the interactive cyberpunk console
	$(BIN) tui

.PHONY: install-alias
install-alias: build ## Install to ~/.local/bin and alias "php" to the TUI
	install -d "$(HOME)/.local/bin"
	install -m 0755 $(BIN) "$(HOME)/.local/bin/p2s"
	@rc="$(HOME)/.bash_aliases"; touch "$$rc"; \
	if grep -q "php2shell-audit interactive alias" "$$rc" 2>/dev/null; then \
		echo "php alias already present in $$rc"; \
	else \
		printf '\n# php2shell-audit interactive alias\n# Remove this block to let the real PHP CLI answer again.\nalias php="p2s tui"\n' >> "$$rc"; \
		echo "added 'alias php=\"p2s tui\"' to $$rc"; \
	fi
	@echo "open a new shell or run: source ~/.bash_aliases"

.PHONY: uninstall
uninstall: ## Remove the installed binary
	rm -f "$(DESTDIR)$(PREFIX)/bin/p2s"
.PHONY: test
test: ## Run the test suite
	$(GO) test ./...

.PHONY: race
race: ## Run the test suite under the race detector
	$(GO) test -race ./...

.PHONY: lint
lint: ## Run go vet and check formatting
	$(GO) vet ./...
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; fi

.PHONY: fmt
fmt: ## Format the source tree
	gofmt -w .

.PHONY: demo
demo: build ## Build and run the bundled detection demo
	$(BIN) scan --local
	$(BIN) hunt --logs testdata/logs --web-root testdata/webroot \
		--session-path testdata/sessions --all-files
	$(BIN) rules --format all --output out/detections
	@echo "detection content written to out/detections"

.PHONY: clean
clean: ## Remove build and demo artefacts
	rm -rf bin out

.PHONY: clean-testcache
clean-testcache: ## Clear the Go test cache
	$(GO) clean -testcache
