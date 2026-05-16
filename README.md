# GoWAF

基于 Go 语言开发的 Web 应用防火墙（WAF），提供攻击检测、访问控制、流量限制、反向代理等安全防护能力，搭配 Web 管理控制台实现可视化运维。

**当前版本**: v1.1.11

## 功能特性

### 安全防护
- **攻击检测引擎** — 13 种检测器（SQL 注入、XSS、命令注入、路径遍历、头部注入、SSRF、XXE、NoSQL 注入、SSTI、敏感数据泄露、恶意文件上传、错误信息泄露、请求走私），支持内置规则 + 自定义正则规则
- **规则热加载** — 规则启用/禁用/新增/删除实时生效，无需重启
- **观察模式** — 检测器可设置为观察模式，仅记录不拦截，便于规则调优
- **智能拦截** — 基于多维度风险评分的智能限流引擎，权重自动归一化
- **IP 黑白名单** — 支持精确/网段匹配，动态增删
- **UA 规则过滤** — 精确/包含/正则匹配，内置常见扫描工具拦截规则
- **路径规则过滤** — 前缀/后缀/精确/包含/正则匹配，内置敏感路径泄露防护规则
- **GeoIP 阻断** — 基于 MaxMind GeoLite2 按地区代码拦截
- **HTTP 方法限制** — 白名单控制允许的请求方法
- **路径限流** — 按路径维度独立限流
- **全局限流** — 令牌桶算法全局限流
- **DLP 数据泄露防护** — 敏感数据检测与脱敏规则
- **合规性检查** — 安全合规基线检查
- **Bot 检测** — 机器人/爬虫识别与拦截
- **拦截页面** — 可自定义拦截响应页面

### 代理与域名管理
- **反向代理** — HTTP/HTTPS 多端口监听，后端负载均衡（轮询）
- **域名配置** — 域名级别关联后端、证书、强制 HTTPS 跳转
- **后端健康检查** — 定时探测后端可用性，自动摘除/恢复
- **X-Forwarded-Host** — 自动添加完整转发头链

### 证书管理
- **SSL 证书管理** — 证书上传/更新/有效期监控，SNI 多域名证书匹配
- **ACME 自动证书** — Let's Encrypt 自动申请与续期，HTTP-01 验证
- **智能续期策略** — 自签名证书强制重新申请、LE 有效证书跳过、即将过期自动续期
- **颁发者友好显示** — CA 缩写自动映射（R3→Let's Encrypt）、自签名/异常提示

### 运维监控
- **实时仪表盘** — WebSocket 推送拦截统计、系统资源、TOP5 分析
- **趋势分析** — 业务指标（请求/QPS/延迟/流量/拦截率/错误率）与系统指标（CPU/内存/磁盘/GC/Go 运行时）多时间范围图表
- **拦截日志** — 按时间/IP/路径/规则多维度检索
- **规则命中分布** — 规则级拦截统计与风险等级标记
- **WebSocket 实时推送** — 仪表盘数据与拦截事件实时更新

### 威胁情报
- **IntelCenter 对接** — 与威胁情报中心集成，支持 IP 黑名单/威胁签名/UA 规则/路径规则/Bot IP/GeoIP 数据同步
- **事件上报** — 拦截事件/误报数据批量上报，支持审核模式与自动审批
- **离线模式** — 网络中断时使用本地缓存，恢复后自动同步
- **敏感数据过滤** — 上报数据脱敏处理，支持自定义过滤规则
- **通知系统** — 连接丢失/同步失败/许可证过期等事件通知

### 其他
- **Session 安全** — crypto/rand 生成 Token，安全会话管理
- **数据脱敏** — 日志与响应中的敏感信息自动脱敏
- **配置版本管理** — 配置变更版本追踪
- **GeoIP 数据库自动更新** — 定期更新 MaxMind 数据库

## 快速开始

### 环境要求
- Go 1.25+
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

> **生产环境请务必在管理后台修改默认密码。**

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
# 管理后台
admin:
    addr: 127.0.0.1:9090          # 监听地址
    allowed_cidrs: []             # 允许访问的 CIDR（空=仅本地）
    admin_log: ./admin.log        # 管理操作日志文件

# 数据库路径（SQLite）
database:
    config_path: ./config.db      # 配置数据库
    metrics_path: ./metrics.db    # 指标数据库
    logs_path: ./logs.db          # 日志数据库

# GeoIP
geoip:
    db_path: ./GeoLite2-City.mmdb

# 默认代理
default_proxy:
    listen_addr: :80              # 代理监听端口
    protocol: http                # http 或 https
    enabled: true

# 日志配置
log:
    file: ./waf.log
    level: info                   # debug/info/warn/error
    rotation:
        maxsize: 100              # 单文件最大 MB
        maxbackups: 10            # 保留备份数
        maxage: 7                 # 保留天数
        compress: true            # 压缩旧日志

# TLS/ACME
tls:
    cert_dir: ./certs             # 证书目录
    acme_email: ""                # Let's Encrypt 邮箱
    domains: []                   # ACME 自动证书域名

# 威胁情报中心
intel:
    enabled: false
    server_url: http://127.0.0.1:8443
    license_key: community_xxx
    sync:
        enabled: false
        interval_secs: 3600
    upload:
        enabled: false
        interval_secs: 300
```

> - 管理后台认证使用 bcrypt 密码哈希，首次登录后在管理后台修改密码
> - HTTPS 代理需在 Web 控制台的「代理配置」中添加 443 端口代理，并在「域名管理」中关联 SSL 证书
> - 威胁情报功能需配合 [IntelCenter](https://github.com/LiveBigOrange/GoWAF/tree/main/IntelCenter) 威胁情报中心使用

## Linux 系统服务

使用 systemd 将 GoWAF 注册为系统服务，实现开机自启和后台运行：

### 1. 构建并安装

```bash
# 构建 Linux 版本
make build-linux

# 安装到系统路径
sudo cp build/gowaf-linux-amd64 /usr/local/bin/gowaf
sudo chmod +x /usr/local/bin/gowaf
```

### 2. 创建配置目录

```bash
sudo mkdir -p /etc/gowaf
sudo cp config.yaml /etc/gowaf/
```

### 3. 创建 systemd 服务文件

```bash
sudo tee /etc/systemd/system/gowaf.service > /dev/null << 'EOF'
[Unit]
Description=GoWAF - Web Application Firewall
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=gowaf
Group=gowaf
WorkingDirectory=/etc/gowaf
ExecStart=/usr/local/bin/gowaf
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/gowaf /var/log/gowaf
PrivateTmp=true

# 环境变量（如需要）
# Environment=GIN_MODE=release

[Install]
WantedBy=multi-user.target
EOF
```

### 4. 创建运行用户和日志目录

```bash
sudo useradd -r -s /usr/sbin/nologin gowaf
sudo mkdir -p /var/log/gowaf
sudo chown -R gowaf:gowaf /etc/gowaf /var/log/gowaf
```

### 5. 启用并启动服务

```bash
# 重新加载 systemd
sudo systemctl daemon-reload

# 启用开机自启
sudo systemctl enable gowaf

# 启动服务
sudo systemctl start gowaf

# 查看状态
sudo systemctl status gowaf

# 查看日志
sudo journalctl -u gowaf -f
```

### 6. 常用管理命令

```bash
sudo systemctl restart gowaf     # 重启
sudo systemctl stop gowaf        # 停止
sudo systemctl disable gowaf     # 禁用开机自启
```

> **注意**: `ProtectSystem=strict` 会将文件系统设为只读，仅 `ReadWritePaths` 中的目录可写。请根据实际配置路径调整 `ReadWritePaths`，确保数据库文件（`.db`）、日志文件和证书目录可写。

## 项目结构

```
GoWAF/
├── cmd/waf/                # 程序入口
├── internal/
│   ├── acme/               # ACME 证书自动管理
│   ├── apischema/          # API 接口定义
│   ├── backend/            # 后端服务管理与健康检查
│   ├── blockpage/          # 拦截页面处理
│   ├── bot/                # 机器人检测
│   ├── compliance/         # 合规性检查
│   ├── config/             # 配置加载与数据库初始化
│   ├── configversion/      # 配置版本管理
│   ├── database/           # 数据库管理器
│   ├── detector/           # 攻击检测引擎（13 种检测器 + 规则热加载）
│   ├── dlprule/            # 数据泄露防护规则
│   ├── event/              # 事件缓冲
│   ├── geoipupdater/       # GeoIP 数据库自动更新
│   ├── intel/              # 威胁情报中心客户端
│   ├── limiter/            # IP 限流器
│   ├── logdb/              # 日志数据库
│   ├── logger/             # 异步日志系统
│   ├── masker/             # 数据脱敏
│   ├── metrics/            # 指标监控
│   ├── netutil/            # 网络工具函数
│   ├── notify/             # 通知系统
│   ├── pathbodylimit/      # 路径请求体限制
│   ├── proxy/              # 反向代理核心
│   ├── proxyconfig/        # 代理/域名/证书配置管理
│   ├── ratelimit/          # 令牌桶限流
│   ├── reqheader/          # 请求头处理
│   ├── respheader/         # 响应头处理
│   ├── rules/              # 规则引擎（IP/UA/路径/GeoIP/方法限制）
│   ├── sessionsafe/        # 安全 Session 管理
│   ├── stats/              # 统计分析
│   ├── timeutil/           # 时间工具函数
│   ├── vpatch/             # 版本补丁
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
| `make build-darwin` | 构建 macOS AMD64 + ARM64 版本 |
| `make build-windows` | 构建 Windows AMD64 版本 |
| `make build-all` | 构建所有平台 |
| `make run` | 构建并运行 |
| `make test` | 运行测试 |
| `make test-cover` | 测试并生成覆盖率报告 |
| `make test-race` | 测试并检测数据竞争 |
| `make bench` | 运行基准测试 |
| `make security` | 安全检查（gosec + govulncheck） |
| `make lint` | 代码静态检查（golangci-lint） |
| `make fmt` | 格式化代码 |
| `make deps` | 安装依赖 |
| `make clean` | 清理构建产物 |
| `make help` | 显示帮助信息 |

## 技术栈

- **语言**: Go 1.25+
- **路由**: gorilla/mux
- **代理**: net/http/httputil.ReverseProxy
- **限流**: golang.org/x/time/rate（令牌桶）
- **GeoIP**: oschwald/geoip2-golang
- **WebSocket**: gorilla/websocket
- **数据库**: SQLite（纯 Go 驱动 modernc.org/sqlite）
- **系统监控**: shirou/gopsutil（CPU/内存/磁盘）
- **配置解析**: gopkg.in/yaml.v3
- **密码哈希**: golang.org/x/crypto/bcrypt
- **前端**: 原生 HTML/CSS/JS（Go embed 嵌入，无需 Node.js）

## 版本历史

| 版本 | 日期 | 主要变更 |
|------|------|----------|
| v1.1.11 | 2026-05-16 | 规则热加载问题修复（空规则清空、拼写迁移、接口补全、API 错误处理） |
| v1.1.10 | 2026-05-16 | 检测器规则数据库驱动与热加载（规则 enabled 生效、自定义规则参与检测） |
| v1.1.9 | 2026-05-16 | 观察模式修复、权重归一化、规则数显示、内置规则自动修复 |
| v1.1.8 | 2026-05-15 | HTTPS 后端 502 修复、ACME 超时修复、修改密码跳转、X-Forwarded-Host |
| v1.1.7 | 2026-05-15 | 登录认证问题修复 |
| v1.1.6 | 2026-05-14 | 趋势分析/仪表盘/证书管理多项修复 |
| v1.1.5 | 2026-04-30 | 数据趋势方案 B 重构与功能优化 |

## 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件。
