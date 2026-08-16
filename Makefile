APP := afw
MODULE := github.com/SamVale29/agent-firewall
GO ?= go
BUILD_DIR ?= bin

.PHONY: build test vet fmt lint run demo clean

build:
	$(GO) build -trimpath -buildvcs=false -o $(BUILD_DIR)/$(APP) ./cmd/afw

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	test -z "$$($(GO)fmt -l .)"

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else echo "golangci-lint is not installed; run go vet ./... instead"; fi

run:
	$(GO) run ./cmd/afw -- help

demo: build
	AFW_BIN=$(abspath $(BUILD_DIR)/$(APP)) bash scripts/demo.sh

clean:
	rm -rf $(BUILD_DIR)
