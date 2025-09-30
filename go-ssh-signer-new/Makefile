APP_NAME := ssh-keysign
MAIN_PACKAGE_PATH := ./cmd/ssh-keysign
BUILD_DIR := bin
GOFILES := $(shell find . -type f -name '*.go')
VERSION ?= $(shell git describe --tags --always --dirty)
GO_VERSION ?= $(shell go version | awk '{print $$3}')
GO_OS ?= $(shell go env GOOS)
GO_ARCH ?= $(shell go env GOARCH)
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG := $(shell go list -m)
BINARY_NAME := $(APP_NAME)-$(GO_OS)-$(GO_ARCH)

LDFLAGS := -X '$(PKG)/internal/meta.Version=$(VERSION)' \
           -X '$(PKG)/internal/meta.Commit=$(COMMIT)' \
           -X '$(PKG)/internal/meta.Date=$(BUILD_DATE)' \
           -X '$(PKG)/internal/meta.OS=$(GO_OS)' \
           -X '$(PKG)/internal/meta.Arch=$(GO_ARCH)' \
           -X '$(PKG)/internal/meta.GoVersion=$(GO_VERSION)'

GOFLAGS := -trimpath -mod=readonly
ENVVARS := CGO_ENABLED=0 GOOS=$(GO_OS) GOARCH=$(GO_ARCH)

.PHONY: all build clean run lint fmt tidy test cover getname

all: fmt lint test build

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

lint:
	go vet ./...

clean:
	rm -rf $(BUILD_DIR)

test:
	go test --race -v ./...

cover:
	go test -cover -coverprofile=coverage.out $(MAIN_PACKAGE_PATH)/...
	go tool cover -html=coverage.out

getname:
	@echo $(BINARY_NAME)
