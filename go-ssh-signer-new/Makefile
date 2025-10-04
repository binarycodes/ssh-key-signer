SHELL := /usr/bin/bash
SHELLFLAGS := -eu -o pipefail -c
APP_NAME := ssh-keysign
MAIN_PACKAGE_PATH := ./cmd/ssh-keysign
BUILD_DIR := bin
GOFILES := $(shell git ls-files '*.go')
VERSION ?= $(shell git describe --tags --always --dirty)
GO_VERSION ?= $(shell go version | awk '{print $$3}')
GO_OS ?= $(shell go env GOOS)
GO_ARCH ?= $(shell go env GOARCH)
COMMIT := $(shell git rev-parse --short HEAD)

ifdef SOURCE_DATE_EPOCH
BUILD_DATE := $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" +%Y-%m-%dT%H:%M:%SZ)
else
BUILD_DATE := $(shell git show -s --no-show-signature --date=unix --format=%cd | xargs -I{} date -u -d @{} +%Y-%m-%dT%H:%M:%SZ)
endif

PKG := $(shell go list -m)
BINARY_NAME := $(APP_NAME)-$(GO_OS)-$(GO_ARCH)
TEST_DIR := testdata
TEST_KEYFILE := $(TEST_DIR)/id

LDFLAGS := -X '$(PKG)/internal/meta.Version=$(VERSION)' \
           -X '$(PKG)/internal/meta.Commit=$(COMMIT)' \
           -X '$(PKG)/internal/meta.Date=$(BUILD_DATE)' \
           -X '$(PKG)/internal/meta.OS=$(GO_OS)' \
           -X '$(PKG)/internal/meta.Arch=$(GO_ARCH)' \
           -X '$(PKG)/internal/meta.GoVersion=$(GO_VERSION)'

GOFLAGS := -trimpath -mod=readonly
ENVVARS := CGO_ENABLED=0 GOOS=$(GO_OS) GOARCH=$(GO_ARCH)

.ONESHELL:

.PHONY: all build clean run lint fmt tidy test cover getname prep-test tools

all: tools fmt lint test build

tidy:
	go mod tidy

build: tidy $(GOFILES)
	@pkgtype=$$(go list -f '{{.Name}}' $(MAIN_PACKAGE_PATH)); \
	if [ "$$pkgtype" != "main" ]; then \
	  echo "❌ Build target is not package main (got $$pkgtype)"; exit 1; \
	fi

	@mkdir -p $(BUILD_DIR)

	$(ENVVARS) go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE_PATH)

	@file $(BUILD_DIR)/$(BINARY_NAME) | grep -q 'executable' || \
	(echo "❌ Build produced non-executable"; rm -f $(BUILD_DIR)/$(BINARY_NAME); exit 1)

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

fmt:
	go fmt ./...
	golangci-lint fmt

lint:
	golangci-lint config verify
	golangci-lint run

clean:
	rm -rf $(TEST_DIR)
	rm -rf $(BUILD_DIR)

test: prep-test
	go test --race -v ./...

cover:
	go test -cover -coverprofile=$(TEST_DIR)/coverage.out ./...
	go tool cover -html=$(TEST_DIR)/coverage.out

getname:
	@echo $(BINARY_NAME)

prep-test: $(TEST_KEYFILE)

$(TEST_KEYFILE):
	@mkdir -p $(TEST_DIR)
	@ssh-keygen -t ed25519 -f $(TEST_KEYFILE) -C "ssh-keysign-test-key" -N "" -q
	@echo "test keyfile generated"

tools:
	@command -v go >/dev/null || { echo "❌ go not found in PATH"; exit 1; }
	@command -v golangci-lint >/dev/null || { echo "❌ golangci-lint not found in PATH"; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "❌ ssh-keygen not found in PATH"; exit 1; }
