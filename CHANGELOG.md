# 更新日志

所有重要的更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

## [1.1.7] - 2025-05-15

### 修复
- **登录认证 - 默认密码无法登录**：`config.yaml` 中 `auth.password` 默认为空字符串，首次启动无法生成密码哈希导致登录验证失败。已在 `BUGFIX_LOG.md` 中说明解决方案：设置 `auth.password` 为实际密码后重启
- **登录认证 - 非 localhost IP 无法登录**：登录成功后设置的 session/csrf_token cookie 硬编码 `Secure: true`，HTTP 连接下浏览器不发送 cookie。已改为 `r.TLS != nil` 动态判断
- **登录认证 - Cookie SameSite 过严**：`SameSite: StrictMode` 在跨站场景下导致问题，已改为 `LaxMode`
- **配置说明 - allowed_cidrs 为空时的行为**：文档明确 `allowed_cidrs` 为空时默认只允许本机访问，非全部允许

### 变更
- Cookie `Secure` 属性改为根据 TLS 状态动态判断（`r.TLS != nil`）
- Cookie `SameSite` 属性从 `StrictMode` 改为 `LaxMode`

## [1.1.6] - 2025-05-14

### 修复
- **趋势分析 - QPS 计算错误**：小时粒度（12h/24h/7d/30d/90d）的 QPS 固定按60秒间隔计算，导致低估60倍。现根据数据粒度动态选择60s/3600s
- **趋势分析 - 拦截率计算基数错误**：`renderBusinessSummary` 中拦截率基数仅用 `total_requests`（不含拦截），导致拦截率偏高。现统一使用 `total_requests + blocked_requests` 作为全量基数
- **趋势分析 - 拦截率图表基数错误**：`renderBusinessChart` 中 blocks 指标图表同样基数不含拦截请求，已修正
- **趋势分析 - 7d 范围标签不显示日期**：7天范围只显示 `HH:MM`，无法区分是哪天。现显示 `MM/DD HH:MM`
- **趋势分析 - 缓存 key 纳秒精度无法命中**：`GetMetricsTrend`/`GetSystemTrend` 缓存 key 包含纳秒精度，2秒 TTL 缓存形同虚设。现 Truncate 到秒
- **趋势分析 - err 变量复用覆盖**：`GetMetricsTrend` 中 start/end 解析共用 err 变量，拆分为 startErr/endErr
- **趋势分析 - 切换指标强制拆分**：切换到 qps/cpu/goruntime/errors 指标时强制设为拆分模式，覆盖用户选择。已移除
- **趋势分析 - 模板冗余 canvas**：`trend.html` 中 `<canvas id="trendChart">` 被 JS 动态创建替代，已删除
- **指标采集 - flushMinuteStats 跳过条件过严**：无请求但有流量/连接数据时完全跳过写入，导致空闲时段流量数据丢失。现判断所有 pending 字段均为0才跳过
- **仪表盘 - GetBlockRate/GetErrorRate 基数错误**：拦截率和错误率基数不含拦截请求，导致两个指标均偏高。现基数改为 `total + blocked`
- **仪表盘 - total 语义不一致**：WebSocket 推送和 `/api/stats` 的 `total` 仅含正常请求，与趋势分析"总请求"含义不一致。现统一为 `total + blocked`
- **证书管理 - 自签名证书颁发者显示域名**：Go `x509.CreateCertificate` 对自签名证书强制 `Issuer=Subject`，导致 issuer 存为域名。`saveCertToDB`/`fillIssuerFromPEM`/`ParseCertificate` 均已增加 issuer==Subject==域名 的识别，修正为 `"GoWAF 自签名"`
- **证书管理 - 颁发者显示不友好**：前端直接显示 CA 缩写（如 `R3`）。新增 `formatIssuer` 函数，映射 `R3→Let's Encrypt (R3)`、`Certum/DigiCert/GlobalSign/Sectigo→品牌名`，自签名灰色样式，异常橙色警告
- **证书管理 - 续期无效**：`APIACMERenew` 调用 `ObtainCertificate`，已有未过期证书时直接返回成功，不重新申请。新增 `RenewCertificate` 方法，智能续期策略：自签名→强制申请、LE有效且>30天→跳过、即将过期/已过期→续期
- **证书管理 - LE失败静默降级**：LE申请失败时静默降级为自签名证书并返回nil，用户误以为LE成功。现降级路径先生成自签名保底再返回error，日志明确区分成功/降级

### 新增
- 初始版本发布
- 核心WAF功能实现
- Web管理后台
- 反向代理支持
- 攻击检测引擎
- 规则系统
- 限流器
- 监控指标

## [1.0.0] - 2024-04-23

### 新增
- 🚀 高性能反向代理，支持多域名、多后端
- 🛡️ 攻击检测引擎（SQL注入、XSS、命令注入等）
- 📝 灵活的规则系统，支持自定义规则
- ⚡ 智能限流器，支持多种限流策略
- 🎯 Web管理后台，可视化配置管理
- 📊 监控指标，详细的访问日志和统计
- 🔒 证书管理，自动HTTPS支持
- 🌐 多协议支持（HTTP/HTTPS）

### 技术栈
- Go 1.25.9
- SQLite3 数据存储
- Gorilla WebSocket
- Gopsutil 系统监控

---

[Unreleased]: https://github.com/yourusername/gowaf/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/yourusername/gowaf/releases/tag/v1.0.0
