package config

import (
	"fmt"
	"os"
	"sync"

	intelconfig "gowaf/internal/intel/config"
	"gowaf/internal/logger"

	"gopkg.in/yaml.v3"
)

var (
	configPath string
	configMu   sync.RWMutex
)

type Config struct {
	Admin struct {
		// Addr 管理后台监听地址
		Addr string `yaml:"addr"`
		// AllowedCIDRs 管理后台IP白名单(CIDR格式)
		AllowedCIDRs []string `yaml:"allowed_cidrs"`
		// AdminLog 管理后台访问日志路径
		AdminLog string `yaml:"admin_log"`
		// Username 运行时使用的管理员用户名
		Username string
		// PasswordHash 运行时使用的管理员密码哈希
		PasswordHash string
	} `yaml:"admin"`
	Database struct {
		// ConfigPath 配置数据库路径
		ConfigPath string `yaml:"config_path"`
		// MetricsPath 监控数据库路径
		MetricsPath string `yaml:"metrics_path"`
		// LogsPath 日志数据库路径
		LogsPath string `yaml:"logs_path"`
	} `yaml:"database"`
	// GeoIP 地理位置数据库配置
	GeoIP struct {
		// DBPath GeoLite2-City.mmdb 文件路径
		DBPath string `yaml:"db_path"`
	} `yaml:"geoip"`
	// DefaultProxy 默认代理配置（仅用于初始化，Web页面配置后以Web页面数据为准）
	DefaultProxy *DefaultProxyConfig `yaml:"default_proxy"`
	// TrustedProxies 信任代理列表（从数据库读取，不在配置文件中）
	TrustedProxies []string
	Log            struct {
		// File 日志文件路径
		File string `yaml:"file"`
		// Level 日志级别
		Level string `yaml:"level"`
		// Rotation 日志轮转配置
		Rotation logger.RotationConfig `yaml:"rotation"`
		// Format 日志格式配置
		Format logger.LogFormatConfig `yaml:"format"`
	} `yaml:"log"`
	Auth struct {
		// Username 认证用户名
		Username string `yaml:"username"`
		// Password 认证密码
		Password string `yaml:"password"`
	} `yaml:"auth"`
	TLS struct {
		CertDir   string   `yaml:"cert_dir"`
		ACMEEmail string   `yaml:"acme_email"`
		Domains   []string `yaml:"domains"`
	} `yaml:"tls"`
	// RuntimeConfig 运行时配置（从数据库加载）
	RuntimeConfig `yaml:"-" json:"-"` // 嵌入RuntimeConfig，不存入yaml
	// Intel 情报中心配置
	Intel *intelconfig.IntelConfig `yaml:"intel" json:"intel,omitempty"`
}

// GetDefaultRuntimeConfig 获取运行时默认配置（当数据库无记录时使用）
func GetDefaultRuntimeConfig() *RuntimeConfig {
	return &RuntimeConfig{
		Security: SecurityConfig{
			Login:     LoginSecurityConfig{MaxAttempts: 5, BlockDuration: 15},
			Session:   SessionSecurityConfig{TTL: 8, AbsoluteTTL: 24, CleanupInterval: 5},
			Captcha:   CaptchaSecurityConfig{TTL: 5},
			RateLimit: RateLimitConfig{APILimit: 300, APIWindow: 1},
		},
		Performance: PerformanceConfig{
			LogChannelSize: 10000, CacheSize: 1000, CacheTTL: 5,
			MaxRequestBody: 10, ScanBuffer: 1024,
			DisableCompression: true,
		},
		Scheduler: SchedulerConfig{
			HealthCheck: 5, LogFlush: 2, LogCleanup: 24,
			MetricsCleanup: 1, RuleReload: 5,
		},
		WebSocket: WebSocketConfig{
			DashboardPush: 2, LogHeartbeat: 30,
			BufferSize: 1024, BroadcastChannel: 1000,
		},
		Log: LogConfig{
			Level:      "info",
			MaxSize:    100,
			MaxBackups: 10,
			MaxAge:     7,
			Compress:   true,
		},
		Retention: RetentionConfig{
			LogRetentionDays:      30,
			MetricsRetentionDays:  30,
			AdminLogRetentionDays: 90,
		},
		SessionSafe: SessionSafeConfig{
			IPMutationThreshold: 3,
			UADetectionEnabled:  true,
		},
	}
}

// RuntimeConfig 运行时配置（由数据库管理，不存入 yaml）
type RuntimeConfig struct {
	Security    SecurityConfig    `json:"security"`
	Performance PerformanceConfig `json:"performance"`
	Scheduler   SchedulerConfig   `json:"scheduler"`
	WebSocket   WebSocketConfig   `json:"websocket"`
	Log         LogConfig         `json:"log"`
	Retention   RetentionConfig   `json:"retention"`
	SessionSafe SessionSafeConfig `json:"session_safe"`
}

// LogConfig 日志运行时配置
type LogConfig struct {
	Level      string `json:"level"`       // debug/info/warn/error
	MaxSize    int    `json:"max_size"`    // 单文件最大MB
	MaxBackups int    `json:"max_backups"` // 保留旧文件数
	MaxAge     int    `json:"max_age"`     // 保留天数
	Compress   bool   `json:"compress"`    // 是否压缩
	Fields     struct {
		Host        bool `json:"host"`
		Query       bool `json:"query"`
		Referer     bool `json:"referer"`
		ContentType bool `json:"content_type"`
		BodySize    bool `json:"body_size"`
		LatencyUs   bool `json:"latency_us"`
	} `json:"fields"`
}

// RetentionConfig 数据保留配置
type RetentionConfig struct {
	LogRetentionDays      int `json:"log_retention_days"`       // 访问日志保留天数
	MetricsRetentionDays  int `json:"metrics_retention_days"`   // 指标数据保留天数
	AdminLogRetentionDays int `json:"admin_log_retention_days"` // 管理日志保留天数
}

// SessionSafeConfig 会话安全配置
type SessionSafeConfig struct {
	IPMutationThreshold int  `json:"ip_mutation_threshold"` // IP变化触发告警次数（默认3）
	UADetectionEnabled  bool `json:"ua_detection_enabled"`  // UA变化检测开关（默认true）
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	Login     LoginSecurityConfig   `json:"login"`
	Session   SessionSecurityConfig `json:"session"`
	Captcha   CaptchaSecurityConfig `json:"captcha"`
	RateLimit RateLimitConfig       `json:"rate_limit"`
}

// LoginSecurityConfig 登录安全配置
type LoginSecurityConfig struct {
	MaxAttempts   int `json:"max_attempts"`   // 登录失败次数限制
	BlockDuration int `json:"block_duration"` // 锁定时长(分钟)
}

// SessionSecurityConfig Session安全配置
type SessionSecurityConfig struct {
	TTL             int `json:"ttl"`              // Session滑动有效期(小时)
	AbsoluteTTL     int `json:"absolute_ttl"`     // Session绝对有效期(小时), 0表示不限制
	CleanupInterval int `json:"cleanup_interval"` // 清理间隔(分钟)
}

// CaptchaSecurityConfig 验证码配置
type CaptchaSecurityConfig struct {
	TTL int `json:"ttl"` // 验证码有效期(分钟)
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	APILimit  int `json:"api_limit"`  // API限流阈值(次/分钟)
	APIWindow int `json:"api_window"` // 限流窗口(分钟)
}

// PerformanceConfig 性能配置
type PerformanceConfig struct {
	LogChannelSize     int  `json:"log_channel_size"`    // 日志通道大小
	CacheSize          int  `json:"cache_size"`          // 查询缓存大小
	CacheTTL           int  `json:"cache_ttl"`           // 缓存TTL(分钟)
	MaxRequestBody     int  `json:"max_request_body"`    // 请求体最大值(MB)
	ScanBuffer         int  `json:"scan_buffer"`         // 扫描缓冲区(KB)
	DisableCompression bool `json:"disable_compression"` // 禁用上游响应压缩（默认启用压缩）
}

// SchedulerConfig 定时任务配置
type SchedulerConfig struct {
	HealthCheck    int `json:"health_check"`    // 健康检查间隔(秒)
	LogFlush       int `json:"log_flush"`       // 日志刷新间隔(秒)
	LogCleanup     int `json:"log_cleanup"`     // 日志清理检查(小时)
	MetricsCleanup int `json:"metrics_cleanup"` // 指标清理间隔(小时)
	RuleReload     int `json:"rule_reload"`     // 规则重载间隔(秒)
}

// WebSocketConfig WebSocket配置
type WebSocketConfig struct {
	DashboardPush    int `json:"dashboard_push"`
	LogHeartbeat     int `json:"log_heartbeat"`
	BufferSize       int `json:"buffer_size"`
	BroadcastChannel int `json:"broadcast_channel"`
}

// DefaultProxyConfig 默认代理配置（用于初始化）
type DefaultProxyConfig struct {
	ListenAddr string `yaml:"listen_addr"` // 监听地址，如 ":80", ":443"
	Protocol   string `yaml:"protocol"`    // 协议: http, https
	Enabled    bool   `yaml:"enabled"`     // 是否启用
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 保存配置文件路径
	configMu.Lock()
	configPath = path
	configMu.Unlock()

	// 设置默认值
	if cfg.Log.Format.TimeFormat == "" {
		cfg.Log.Format.TimeFormat = "2006-01-02T15:04:05.000Z07:00"
	}

	// 设置轮转默认值
	if cfg.Log.Rotation.MaxSize == 0 {
		cfg.Log.Rotation.MaxSize = 100 // 默认100MB
	}
	if cfg.Log.Rotation.MaxBackups == 0 {
		cfg.Log.Rotation.MaxBackups = 10 // 默认保留10个
	}
	if cfg.Log.Rotation.MaxAge == 0 {
		cfg.Log.Rotation.MaxAge = 7 // 默认保留7天
	}

	// 设置管理后台日志默认值
	if cfg.Admin.AdminLog == "" {
		cfg.Admin.AdminLog = "./admin.log" // 默认管理后台日志路径
	}

	// 验证配置
	if err := ValidateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	// 初始化 Intel 默认值并验证
	if cfg.Intel == nil {
		cfg.Intel = intelconfig.DefaultIntelConfig()
	} else {
		cfg.Intel = intelconfig.MergeIntelConfig(intelconfig.DefaultIntelConfig(), cfg.Intel)
	}
	if err := intelconfig.ValidateIntelConfig(cfg.Intel); err != nil {
		return nil, fmt.Errorf("情报中心配置验证失败: %w", err)
	}

	return &cfg, nil
}

// Save 保存配置到文件
func (c *Config) Save() error {
	configMu.Lock()
	defer configMu.Unlock()

	if configPath == "" {
		return os.ErrNotExist
	}

	// 序列化配置为YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	// 写入文件
	return os.WriteFile(configPath, data, 0600)
}
