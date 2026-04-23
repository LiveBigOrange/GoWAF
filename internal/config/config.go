package config

import (
	"os"

	"gowaf-demo/internal/logger"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Admin struct {
		Addr         string   `yaml:"addr"`
		AllowedCIDRs []string `yaml:"allowed_cidrs"` // 管理后台IP白名单(CIDR格式)
		AdminLog     string   `yaml:"admin_log"`     // 管理后台访问日志路径
	} `yaml:"admin"`
	Database struct {
		ConfigPath  string `yaml:"config_path"`  // 配置数据库路径
		MetricsPath string `yaml:"metrics_path"` // 监控数据库路径
		LogsPath    string `yaml:"logs_path"`    // 日志数据库路径
	} `yaml:"database"`
	// 默认代理配置（仅用于初始化，Web页面配置后以Web页面数据为准）
	DefaultProxy *DefaultProxyConfig `yaml:"default_proxy"`
	TrustedProxies []string // 从数据库读取，不在配置文件中
	Log struct {
		File     string                  `yaml:"file"`
		Level    string                  `yaml:"level"`
		Rotation logger.RotationConfig   `yaml:"rotation"` // 日志轮转配置
		Format   logger.LogFormatConfig  `yaml:"format"`   // 日志格式配置
	} `yaml:"log"`
	Auth struct {
		Username string `yaml:"username"`
		Password string `yaml:"password"`
	} `yaml:"auth"`
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

	return &cfg, nil
}
