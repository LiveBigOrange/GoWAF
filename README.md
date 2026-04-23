# GoWAF - 高性能 Web 应用防火墙

[![Go Version](https://img.shields.io/badge/Go-1.25.9-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

一个用 Go 语言开发的高性能、易扩展的 Web 应用防火墙（WAF），提供反向代理、攻击检测、规则引擎、限流保护等功能。

## ✨ 核心特性

- 🚀 **高性能反向代理** - 支持多域名、多后端负载均衡
- 🛡️ **攻击检测引擎** - SQL注入、XSS、命令注入等多种攻击检测
- 📝 **灵活规则系统** - 支持自定义规则，正则表达式匹配
- ⚡ **智能限流器** - 基于IP、路径、用户的限流保护
- 🎯 **Web管理后台** - 可视化配置管理，实时监控
- 📊 **监控指标** - 详细的访问日志、拦截统计、性能指标
- 🔒 **证书管理** - 自动HTTPS证书管理
- 🌐 **多协议支持** - HTTP/HTTPS协议支持

## 📦 项目结构

```
gowaf/
├── cmd/waf/              # 程序入口
├── internal/             # 核心功能模块
│   ├── backend/         # 后端服务器管理
│   ├── config/          # 配置管理
│   ├── detector/        # 攻击检测引擎
│   ├── proxy/           # 反向代理
│   ├── rules/           # 规则引擎
│   ├── ratelimiter/     # 限流器
│   ├── web/             # Web管理后台
│   └── ...
├── config.yaml          # 配置文件
└── go.mod               # Go模块定义
```

## 🚀 快速开始

### 前置要求

- Go 1.25.9 或更高版本
- SQLite3（用于数据存储）

### 安装

```bash
# 克隆仓库
git https://github.com/LiveBigOrange/GoWAF.git
cd gowaf

# 安装依赖
go mod download

# 编译
go build -o waf ./cmd/waf
```

### 运行

```bash
# 运行WAF
./waf

# 访问管理后台
# 默认地址: http://127.0.0.1:9090
# 默认账号: admin / admin
```

## ⚙️ 配置说明

主要配置文件为 `config.yaml`，包含以下配置项：

- **管理后台配置** - 监听地址、访问日志、IP白名单
- **数据库配置** - 配置数据库、监控数据库、日志数据库路径
- **代理配置** - 监听地址、协议类型、后端服务器
- **日志配置** - 日志级别、轮转策略、格式配置
- **认证配置** - 管理后台登录凭证

详细配置请参考 [config.yaml](config.yaml) 文件。

## 📖 功能说明

### 1. 反向代理

支持多域名、多后端的反向代理配置，可通过Web管理后台动态配置。

### 2. 攻击检测

内置多种攻击检测规则：
- SQL注入检测
- XSS攻击检测
- 命令注入检测
- 路径遍历检测
- 自定义规则支持

### 3. 限流保护

支持多种限流策略：
- 基于IP的限流
- 基于路径的限流
- 基于用户的限流
- 滑动窗口算法

### 4. Web管理后台

提供可视化的管理界面：
- 代理配置管理
- 规则配置管理
- 限流配置管理
- 实时监控面板
- 日志查询分析

## 🔧 开发指南

### 构建

```bash
# 本地构建
go build -o waf ./cmd/waf

# Linux构建
GOOS=linux GOARCH=amd64 go build -o waf-linux-amd64 ./cmd/waf
```

### 测试

```bash
# 运行测试
go test ./...

# 测试覆盖率
go test -cover ./...
```

## 📝 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 📮 联系方式

如有问题或建议，欢迎提交 [Issue](https://github.com/yourusername/gowaf/issues)。

## 🙏 致谢

感谢以下开源项目的支持：
- [gorilla/websocket](https://github.com/gorilla/websocket)
- [shirou/gopsutil](https://github.com/shirou/gopsutil)
- [modernc.org/sqlite](https://modernc.org/sqlite)
