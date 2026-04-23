.PHONY: build clean test run help

# 变量定义
APP_NAME := gowaf
VERSION := 1.0.0
BUILD_DIR := build
GO := go
GOFLAGS := -v

# 默认目标
.DEFAULT_GOAL := help

## build: 构建应用程序
build:
	@echo "构建 $(APP_NAME)..."
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME) ./cmd/waf

## build-linux: 构建Linux版本
build-linux:
	@echo "构建 Linux AMD64 版本..."
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./cmd/waf
	@echo "构建 Linux ARM64 版本..."
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 ./cmd/waf

## clean: 清理构建产物
clean:
	@echo "清理构建产物..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(APP_NAME) $(APP_NAME)-*
	@rm -f *.db *.log

## test: 运行测试
test:
	@echo "运行测试..."
	$(GO) test -v ./...

## test-cover: 运行测试并生成覆盖率报告
test-cover:
	@echo "运行测试覆盖率..."
	$(GO) test -cover -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

## run: 运行应用程序
run: build
	@echo "运行 $(APP_NAME)..."
	./$(BUILD_DIR)/$(APP_NAME)

## deps: 安装依赖
deps:
	@echo "安装依赖..."
	$(GO) mod download
	$(GO) mod tidy

## lint: 代码检查
lint:
	@echo "运行代码检查..."
	@which golangci-lint > /dev/null || (echo "请先安装 golangci-lint" && exit 1)
	golangci-lint run ./...

## fmt: 格式化代码
fmt:
	@echo "格式化代码..."
	$(GO) fmt ./...

## help: 显示帮助信息
help:
	@echo "可用目标:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
