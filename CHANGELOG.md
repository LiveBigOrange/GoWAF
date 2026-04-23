# 更新日志

所有重要的更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
并且本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

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
