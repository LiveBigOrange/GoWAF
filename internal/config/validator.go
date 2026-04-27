package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ConfigPriority 配置优先级
type ConfigPriority int

const (
	PriorityDefault ConfigPriority = iota // 默认值（最低优先级）
	PriorityYAML                          // YAML配置文件
	PriorityDatabase                      // 数据库配置（最高优先级）
)

// ConfigValidator 配置验证器
type ConfigValidator struct {
	errors []error
}

// NewConfigValidator 创建配置验证器
func NewConfigValidator() *ConfigValidator {
	return &ConfigValidator{
		errors: make([]error, 0),
	}
}

// Validate 验证配置
func (v *ConfigValidator) Validate(cfg *Config) error {
	v.errors = make([]error, 0)

	// 验证管理后台配置
	v.validateAdminConfig(cfg)

	// 验证数据库配置
	v.validateDatabaseConfig(cfg)

	// 验证日志配置
	v.validateLogConfig(cfg)

	// 验证认证配置
	v.validateAuthConfig(cfg)

	// 验证运行时配置
	v.validateRuntimeConfig(&cfg.RuntimeConfig)

	if len(v.errors) > 0 {
		return fmt.Errorf("配置验证失败: %v", v.errors)
	}
	return nil
}

// validateAdminConfig 验证管理后台配置
func (v *ConfigValidator) validateAdminConfig(cfg *Config) {
	// 验证地址格式
	if cfg.Admin.Addr == "" {
		v.addError("admin.addr", "地址不能为空")
	} else if !isValidAddr(cfg.Admin.Addr) {
		v.addError("admin.addr", "地址格式无效，应为 host:port 格式")
	}

	// 验证IP白名单
	for _, cidr := range cfg.Admin.AllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			// 尝试解析为单个IP
			if ip := net.ParseIP(cidr); ip == nil {
				v.addError("admin.allowed_cidrs", fmt.Sprintf("无效的CIDR或IP: %s", cidr))
			}
		}
	}

	// 验证日志路径
	if cfg.Admin.AdminLog == "" {
		v.addError("admin.admin_log", "日志路径不能为空")
	}
}

// validateDatabaseConfig 验证数据库配置
func (v *ConfigValidator) validateDatabaseConfig(cfg *Config) {
	if cfg.Database.ConfigPath == "" {
		v.addError("database.config_path", "配置数据库路径不能为空")
	}
	if cfg.Database.MetricsPath == "" {
		v.addError("database.metrics_path", "指标数据库路径不能为空")
	}
	if cfg.Database.LogsPath == "" {
		v.addError("database.logs_path", "日志数据库路径不能为空")
	}
}

// validateLogConfig 验证日志配置
func (v *ConfigValidator) validateLogConfig(cfg *Config) {
	if cfg.Log.File == "" {
		v.addError("log.file", "日志文件路径不能为空")
	}

	// 验证日志级别
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if cfg.Log.Level != "" && !validLevels[strings.ToLower(cfg.Log.Level)] {
		v.addError("log.level", fmt.Sprintf("无效的日志级别: %s", cfg.Log.Level))
	}
}

// validateAuthConfig 验证认证配置
func (v *ConfigValidator) validateAuthConfig(cfg *Config) {
	if cfg.Auth.Username == "" {
		v.addError("auth.username", "用户名不能为空")
	}
	// 密码可以为空（可能已经使用哈希密码）
	// 只在有明文密码时才检查长度（最小4位，允许"admin"等常见默认密码）
	if cfg.Auth.Password != "" && len(cfg.Auth.Password) < 4 {
		v.addError("auth.password", "密码长度不能少于4位")
	}
}

// validateRuntimeConfig 验证运行时配置
func (v *ConfigValidator) validateRuntimeConfig(rc *RuntimeConfig) {
	// 运行时配置通常从数据库加载，可能还没有初始化
	// 只验证已设置的值，不强制要求必须设置

	// 验证安全配置（只在值已设置时验证）
	if rc.Security.Login.MaxAttempts < 0 {
		v.addError("security.login.max_attempts", "登录尝试次数不能为负数")
	}
	if rc.Security.Login.BlockDuration < 0 {
		v.addError("security.login.block_duration", "锁定时长不能为负数")
	}
	if rc.Security.Session.TTL < 0 {
		v.addError("security.session.ttl", "Session有效期不能为负数")
	}

	// 验证性能配置（只在值已设置时验证）
	if rc.Performance.LogChannelSize < 0 {
		v.addError("performance.log_channel_size", "日志通道大小不能为负数")
	}
	if rc.Performance.CacheSize < 0 {
		v.addError("performance.cache_size", "缓存大小不能为负数")
	}
	if rc.Performance.MaxRequestBody < 0 {
		v.addError("performance.max_request_body", "请求体最大值不能为负数")
	}

	// 验证定时任务配置（只在值已设置时验证）
	if rc.Scheduler.HealthCheck < 0 {
		v.addError("scheduler.health_check", "健康检查间隔不能为负数")
	}
}

// addError 添加错误
func (v *ConfigValidator) addError(field, message string) {
	v.errors = append(v.errors, fmt.Errorf("%s: %s", field, message))
}

// isValidAddr 验证地址格式
func isValidAddr(addr string) bool {
	// 匹配 :port 或 host:port 格式
	pattern := `^(\[[^\]]+\]|[^\[:]+)?:\d+$`
	matched, _ := regexp.MatchString(pattern, addr)
	return matched
}

// MergeConfig 合并配置（按优先级）
// 优先级：Database > YAML > Default
func MergeConfig(defaultCfg, yamlCfg, dbCfg *RuntimeConfig) *RuntimeConfig {
	result := *defaultCfg // 从默认值开始

	// 应用YAML配置（如果存在）
	if yamlCfg != nil {
		result = mergeRuntimeConfig(&result, yamlCfg)
	}

	// 应用数据库配置（如果存在）
	if dbCfg != nil {
		result = mergeRuntimeConfig(&result, dbCfg)
	}

	return &result
}

// mergeRuntimeConfig 合并运行时配置
func mergeRuntimeConfig(base, override *RuntimeConfig) RuntimeConfig {
	result := *base

	// 合并安全配置
	if override.Security.Login.MaxAttempts != 0 {
		result.Security.Login.MaxAttempts = override.Security.Login.MaxAttempts
	}
	if override.Security.Login.BlockDuration != 0 {
		result.Security.Login.BlockDuration = override.Security.Login.BlockDuration
	}
	if override.Security.Session.TTL != 0 {
		result.Security.Session.TTL = override.Security.Session.TTL
	}
	if override.Security.Session.CleanupInterval != 0 {
		result.Security.Session.CleanupInterval = override.Security.Session.CleanupInterval
	}
	if override.Security.Captcha.TTL != 0 {
		result.Security.Captcha.TTL = override.Security.Captcha.TTL
	}
	if override.Security.RateLimit.APILimit != 0 {
		result.Security.RateLimit.APILimit = override.Security.RateLimit.APILimit
	}
	if override.Security.RateLimit.APIWindow != 0 {
		result.Security.RateLimit.APIWindow = override.Security.RateLimit.APIWindow
	}

	// 合并性能配置
	if override.Performance.LogChannelSize != 0 {
		result.Performance.LogChannelSize = override.Performance.LogChannelSize
	}
	if override.Performance.CacheSize != 0 {
		result.Performance.CacheSize = override.Performance.CacheSize
	}
	if override.Performance.CacheTTL != 0 {
		result.Performance.CacheTTL = override.Performance.CacheTTL
	}
	if override.Performance.MaxRequestBody != 0 {
		result.Performance.MaxRequestBody = override.Performance.MaxRequestBody
	}
	if override.Performance.ScanBuffer != 0 {
		result.Performance.ScanBuffer = override.Performance.ScanBuffer
	}

	// 合并定时任务配置
	if override.Scheduler.HealthCheck != 0 {
		result.Scheduler.HealthCheck = override.Scheduler.HealthCheck
	}
	if override.Scheduler.LogFlush != 0 {
		result.Scheduler.LogFlush = override.Scheduler.LogFlush
	}
	if override.Scheduler.LogCleanup != 0 {
		result.Scheduler.LogCleanup = override.Scheduler.LogCleanup
	}
	if override.Scheduler.MetricsCleanup != 0 {
		result.Scheduler.MetricsCleanup = override.Scheduler.MetricsCleanup
	}
	if override.Scheduler.RuleReload != 0 {
		result.Scheduler.RuleReload = override.Scheduler.RuleReload
	}

	// 合并WebSocket配置
	if override.WebSocket.DashboardPush != 0 {
		result.WebSocket.DashboardPush = override.WebSocket.DashboardPush
	}
	if override.WebSocket.LogHeartbeat != 0 {
		result.WebSocket.LogHeartbeat = override.WebSocket.LogHeartbeat
	}
	if override.WebSocket.BufferSize != 0 {
		result.WebSocket.BufferSize = override.WebSocket.BufferSize
	}
	if override.WebSocket.BroadcastChannel != 0 {
		result.WebSocket.BroadcastChannel = override.WebSocket.BroadcastChannel
	}

	return result
}

// ValidateConfig 验证配置的便捷函数
func ValidateConfig(cfg *Config) error {
	validator := NewConfigValidator()
	return validator.Validate(cfg)
}

// GetConfigPriority 获取配置来源说明
func GetConfigPriority() string {
	return `配置优先级（从高到低）:
1. 数据库配置 (system_config表) - 最高优先级
2. YAML配置文件 (config.yaml) - 中等优先级
3. 默认值 (代码中定义) - 最低优先级

说明：
- 数据库配置可通过Web管理界面修改，实时生效
- YAML配置文件用于初始化和无法通过Web修改的基础配置
- 默认值作为兜底，确保配置完整性`
}
