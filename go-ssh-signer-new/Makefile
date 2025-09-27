APP_NAME := app
BUILD_DIR := bin
GOFILES := $(shell find . -type f -name '*.go')

.PHONY: all build clean run lint fmt tidy

all: build

## Fetch dependencies
tidy:
	go mod tidy

## Build the binary (runs tidy first)
build: tidy $(GOFILES)
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(APP_NAME) .

## Run the binary directly
run: build
	$(BUILD_DIR)/$(APP_NAME)

## Run go fmt on all files
fmt:
	go fmt ./...

## Run go vet / linting
lint:
	go vet ./...

## Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

