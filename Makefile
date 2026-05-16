.PHONY: build clean test run help test-cover test-race bench security build-linux build-darwin build-windows build-all

# 变量定义
APP_NAME := gowaf
VERSION := 1.1.12
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

## build-darwin: 构建macOS版本
build-darwin:
	@echo "构建 macOS AMD64 版本..."
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/waf
	@echo "构建 macOS ARM64 版本..."
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/waf

## build-windows: 构建Windows版本
build-windows:
	@echo "构建 Windows AMD64 版本..."
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/waf

## build-all: 构建所有平台
build-all: build-linux build-darwin build-windows
	@echo "所有平台构建完成"

## clean: 清理构建产物
clean:
	@echo "清理构建产物..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(APP_NAME) $(APP_NAME)-*
	@rm -f *.db *.log coverage.out coverage.html

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

## test-race: 运行测试并检测数据竞争
test-race:
	@echo "运行竞态检测..."
	$(GO) test -race -v ./...

## bench: 运行基准测试
bench:
	@echo "运行基准测试..."
	$(GO) test -bench=. -benchmem ./...

## security: 运行安全检查
security:
	@echo "运行安全检查..."
	@which gosec > /dev/null || (echo "请先安装 gosec: go install github.com/securecodewarrior/gosec/v2/gosec@latest" && exit 1)
	gosec -quiet ./...
	@echo "运行漏洞检查..."
	@which govulncheck > /dev/null || (echo "请先安装 govulncheck: go install golang.org/x/vuln/cmd/govulncheck@latest" && exit 1)
	govulncheck ./...

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
