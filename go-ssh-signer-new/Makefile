APP_NAME := ssh-keysign
MAIN_PACKAGE_PATH := .
BUILD_DIR := bin
GOFILES := $(shell find . -type f -name '*.go')
VERSION ?= $(shell git describe --tags --always --dirty)
GO_VERSION ?= $(shell go env GOVERSION | { read v _; echo ${v#go}; })
GO_OS ?= $(shell go env GOOS)
GO_ARCH ?= $(shell go env GOARCH)
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG := $(shell go list -m)
BINARY_NAME :='$(APP_NAME)-$(GO_OS)-$(GO_ARCH)-$(GO_VERSION)'

LDFLAGS := -X '$(PKG)/internal/meta.Version=$(VERSION)' \
           -X '$(PKG)/internal/meta.Commit=$(COMMIT)' \
           -X '$(PKG)/internal/meta.Date=$(BUILD_DATE)' \
           -X '$(PKG)/internal/meta.OS=$(GO_OS)' \
           -X '$(PKG)/internal/meta.Arch=$(GO_ARCH)'

.PHONY: all build clean run lint fmt tidy test cover getname

all: fmt lint test build

tidy:
	go mod tidy

build: tidy $(GOFILES)
	@mkdir -p $(BUILD_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PACKAGE_PATH)

run: build
	$(BUILD_DIR)/$(BINARY_NAME)

fmt:
	go fmt  $(MAIN_PACKAGE_PATH)/...

lint:
	go vet  $(MAIN_PACKAGE_PATH)/...

clean:
	rm -rf $(BUILD_DIR)

test:
	go test -v  $(MAIN_PACKAGE_PATH)/...

cover:
	go test -cover -coverprofile=coverage.out $(MAIN_PACKAGE_PATH)/...
	go tool cover -html=coverage.out

getname:
	@echo $(BINARY_NAME)
