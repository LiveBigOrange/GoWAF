# GoWAF

基于 Go 语言开发的 Web 应用防火墙（WAF），提供攻击检测、访问控制、流量限制、反向代理等安全防护能力，搭配 Web 管理控制台实现可视化运维。

## 功能特性

### 安全防护
- **IP 黑白名单** — 支持精确/网段匹配，动态增删
- **UA 规则过滤** — 精确/包含/正则匹配，内置常见扫描工具拦截规则
- **路径规则过滤** — 前缀/后缀/精确/包含/正则匹配，内置敏感路径泄露防护规则
- **GeoIP 阻断** — 基于 MaxMind GeoLite2 按地区代码拦截
- **HTTP 方法限制** — 白名单控制允许的请求方法
- **路径限流** — 按路径维度独立限流
- **全局限流** — 令牌桶算法全局限流
- **攻击检测** — SQL 注入、XSS、路径遍历、命令注入等多类型检测，支持自定义正则规则

### 代理与域名管理
- **反向代理** — HTTP/HTTPS 多端口监听，后端负载均衡（轮询）
- **域名配置** — 域名级别关联后端、证书、强制 HTTPS 跳转
- **后端健康检查** — 定时探测后端可用性，自动摘除/恢复

### 运维监控
- **实时仪表盘** — WebSocket 推送拦截统计、系统资源、TOP5 分析
- **趋势分析** — 业务指标（请求/QPS/延迟/流量/拦截率/错误率）与系统指标（CPU/内存/磁盘/GC/Go运行时）多时间范围图表
- **拦截日志** — 按时间/IP/路径/规则多维度检索
- **规则命中分布** — 规则级拦截统计与风险等级标记
- **WebSocket 实时推送** — 仪表盘数据与拦截事件实时更新

### 证书管理
- **SSL 证书管理** — 证书上传/更新/有效期监控，SNI 多域名证书匹配
- **ACME 自动证书** — Let's Encrypt 自动申请与续期，HTTP-01 验证
- **智能续期策略** — 自签名证书强制重新申请、LE 有效证书跳过、即将过期自动续期
- **颁发者友好显示** — CA 缩写自动映射（R3→Let's Encrypt）、自签名/异常提示

## 快速开始

### 环境要求
- Go 1.21+
- MaxMind GeoLite2-City 数据库（GeoIP 功能需要）

### 构建运行

```bash
# 克隆项目
git clone https://github.com/LiveBigOrange/GoWAF.git
cd GoWAF/GoWAF

# 安装依赖
go mod tidy

# 构建
make build

# 运行（默认监听 :80 代理 + :9090 管理后台）
./build/gowaf
```

或直接运行：

```bash
go run ./cmd/waf
```

### 首次登录

启动后访问 `http://127.0.0.1:9090`，默认账号：

| 项目 | 值 |
|------|-----|
| 用户名 | `admin` |
| 密码 | `admin` |

> **生产环境请务必在 `config.yaml` 中修改默认密码。**

### GeoIP 数据库

GeoIP 功能需要 MaxMind GeoLite2-City 数据库文件：

1. 从 [MaxMind 官网](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) 注册并下载 `GeoLite2-City.mmdb`
2. 放置到项目根目录，或在 `config.yaml` 中指定路径：

```yaml
geoip:
    db_path: ./GeoLite2-City.mmdb
```

## 配置说明

主配置文件 `config.yaml`，各配置项均有中文注释说明。核心配置：

```yaml
admin:
    addr: 127.0.0.1:9090    # 管理后台地址

default_proxy:
    listen_addr: :80         # 代理监听端口
    protocol: http           # http 或 https

auth:
    username: admin          # 管理后台用户名
    password: admin          # 管理后台密码

scheduler:
    health_check: 5          # 后端健康检查间隔（秒）
    rule_reload: 5           # 规则热重载间隔（秒）
```

> HTTPS 代理需在 Web 控制台的「代理配置」中添加 443 端口代理，并在「域名管理」中关联 SSL 证书。

## 项目结构

```
GoWAF/
├── cmd/waf/                # 程序入口
├── internal/
│   ├── backend/            # 后端服务管理与健康检查
│   ├── config/             # 配置加载与数据库初始化
│   ├── detector/           # 攻击检测引擎
│   ├── event/              # 拦截事件环形缓冲区
│   ├── limiter/            # IP 限流器
│   ├── logdb/              # 日志数据库与查询缓存
│   ├── logger/             # 异步日志系统
│   ├── metrics/            # 指标监控
│   ├── middleware/         # HTTP 中间件（认证/限流/CORS等）
│   ├── proxy/              # 反向代理与代理服务器管理
│   ├── proxyconfig/        # 代理/域名/证书配置管理
│   ├── rules/              # 规则引擎（IP/UA/路径/GeoIP/方法限制）
│   └── web/
│       ├── handler/        # HTTP 请求处理器
│       ├── static/         # 前端静态资源（CSS/JS/图标）
│       └── templates/      # HTML 模板（Go embed 嵌入）
├── config.yaml             # 主配置文件
├── Makefile                # 构建脚本
└── go.mod                  # Go 模块定义
```

## Makefile 命令

| 命令 | 说明 |
|------|------|
| `make build` | 构建当前平台可执行文件 |
| `make build-linux` | 构建 Linux AMD64 + ARM64 版本 |
| `make run` | 构建并运行 |
| `make test` | 运行测试 |
| `make test-cover` | 生成覆盖率报告 |
| `make lint` | 代码静态检查 |
| `make fmt` | 格式化代码 |
| `make clean` | 清理构建产物 |

## 技术栈

- **语言**: Go 1.21+
- **路由**: gorilla/mux
- **代理**: net/http/httputil.ReverseProxy
- **限流**: golang.org/x/time/rate（令牌桶）
- **GeoIP**: oschwald/geoip2-golang
- **WebSocket**: gorilla/websocket
- **数据库**: SQLite（纯 Go 驱动）
- **前端**: 原生 HTML/CSS/JS（Go embed 嵌入，无需 Node.js）

## 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件。
