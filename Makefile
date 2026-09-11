# NetNinja — build, test and package the two Linux binaries the deploy scripts
# upload. Run everything from the repository root:
#
#   make            linux binaries into dist/ (dist/proxy_linux, dist/keepalive_linux)
#   make host       the same two binaries for the machine you are on (quick run)
#   make test       offline unit tests
#   make selftest   offline test of the Thai pool supervisor — no tunnels needed
#   make check      gofmt + vet + test
#   make clean      drop dist/
#
# Override the target platform when needed:  make GOOS=linux GOARCH=arm64
#
# The build stamp is compiled in (-X main.buildTime), which is what /geo-check
# and the dashboard print, so a deployed binary can be identified at a glance.
# -trimpath keeps local paths out of the binary: this repository is public.

GOOS   ?= linux
GOARCH ?= amd64
DIST   ?= dist

STAMP   ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -X main.buildTime=$(STAMP)

PROXY_SRC := $(wildcard cmd/proxy/*.go) go.mod go.sum
KEEP_SRC  := $(wildcard cmd/keepalive/*.go) go.mod go.sum

.PHONY: all build host test selftest check fmt vet clean

all: build

build: $(DIST)/proxy_linux $(DIST)/keepalive_linux

$(DIST)/proxy_linux: $(PROXY_SRC)
	@mkdir -p $(DIST)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/proxy

$(DIST)/keepalive_linux: $(KEEP_SRC)
	@mkdir -p $(DIST)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' -o $@ ./cmd/keepalive

# Same two binaries for the host OS (Windows/macOS), for a local smoke test.
host:
	@mkdir -p $(DIST)
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/proxy.exe ./cmd/proxy
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/keepalive.exe ./cmd/keepalive

# ./cmd/... is the whole build set: the repository root is not a package, it only
# holds the Makefile, docs and untracked per-machine files.
test:
	go test ./cmd/...

selftest:
	bash scripts/netninja-th-pool.selftest.sh

fmt:
	gofmt -w cmd

vet:
	go vet ./cmd/...

check: fmt vet test

clean:
	rm -rf $(DIST)
