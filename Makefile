SHELL := /usr/bin/sh

GO ?= go
MODE ?= divert_cgo
PACKAGE ?= ./cmd/tls-mitm
OUTPUT ?= build/tls-mitm.exe
OUTPUT_DIR := $(dir $(OUTPUT))

ifeq ($(MODE),default)
BUILD_TAGS :=
BUILD_ENV :=
else ifeq ($(MODE),divert_cgo)
BUILD_TAGS := divert_cgo
BUILD_ENV := CGO_ENABLED=1
else ifeq ($(MODE),divert_embedded)
BUILD_TAGS := divert_embedded
BUILD_ENV :=
else
$(error 不支持的 MODE: $(MODE)，可选值: default、divert_cgo、divert_embedded)
endif

BUILD_ARGS := build
ifneq ($(strip $(BUILD_TAGS)),)
BUILD_ARGS += -tags $(BUILD_TAGS)
endif
BUILD_ARGS += -o $(OUTPUT) $(PACKAGE)

.PHONY: all help build build-default build-cgo build-embedded test clean

all: build

help:
	@echo "可用目标:"
	@echo "  make build            默认按 MODE=$(MODE) 构建"
	@echo "  make build-default    构建默认 DLL 依赖版本"
	@echo "  make build-cgo        构建 divert_cgo 版本"
	@echo "  make build-embedded   构建 divert_embedded 版本"
	@echo "  make test             运行 go test ./..."
	@echo "  make clean            清理 bin/"
	@echo ""
	@echo "可覆盖变量:"
	@echo "  GO=go"
	@echo "  MODE=default|divert_cgo|divert_embedded"
	@echo "  OUTPUT=build/tls-mitm.exe"
	@echo "  PACKAGE=./cmd/tls-mitm"

build:
	@mkdir -p "$(OUTPUT_DIR)"
	$(BUILD_ENV) $(GO) $(BUILD_ARGS)

build-default:
	@$(MAKE) build MODE=default

build-cgo:
	@$(MAKE) build MODE=divert_cgo

build-embedded:
	@$(MAKE) build MODE=divert_embedded

test:
	$(GO) test ./...

clean:
	rm -rf build
