APP_NAME := ssh-keysign
MAIN_PACKAGE_PATH = .
BUILD_DIR := bin
GOFILES := $(shell find . -type f -name '*.go')
VERSION ?= $(shell git describe --always --long --dirty)
GO_VERSION ?= $(shell go list -m -f '{{.GoVersion}}')
GO_OS ?= $(shell go env GOOS)
GO_ARCH ?= $(shell go env GOARCH)

.PHONY: all build clean run lint fmt tidy test cover

all: build

tidy:
	go mod tidy

build: tidy $(GOFILES)
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME)-$(GO_OS)-$(GO_ARCH)-$(GO_VERSION) $(MAIN_PACKAGE_PATH)

run: build
	$(BUILD_DIR)/$(APP_NAME)-$(GO_OS)-$(GO_ARCH)-$(GO_VERSION)

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
