package config

import (
	"fmt"
	"strings"
)

type IntelConfig struct {
	Enabled         bool                  `yaml:"enabled" json:"enabled"`
	ServerURL       string                `yaml:"server_url" json:"server_url"`
	LicenseKey      string                `yaml:"license_key,omitempty" json:"-"`
	InstanceID      string                `yaml:"instance_id" json:"instance_id"`
	TLS             TLSConfig             `yaml:"tls" json:"tls"`
	ConnectTimeout  int                   `yaml:"connect_timeout_secs" json:"connect_timeout_secs"`
	RequestTimeout  int                   `yaml:"request_timeout_secs" json:"request_timeout_secs"`
	Sync            SyncConfig            `yaml:"sync" json:"sync"`
	Upload          UploadConfig          `yaml:"upload" json:"upload"`
	Rule            RuleConfig            `yaml:"rule" json:"rule"`
	SensitiveFilter SensitiveFilterConfig `yaml:"sensitive_filter" json:"sensitive_filter"`
	Offline         OfflineConfig         `yaml:"offline" json:"offline"`
	Alerts          AlertConfig           `yaml:"alerts" json:"alerts"`
}

type TLSConfig struct {
	CACertPath         string `yaml:"ca_cert_path" json:"ca_cert_path"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
}

type SyncConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	IntervalSecs int      `yaml:"interval_secs" json:"interval_secs"`
	DataTypes    []string `yaml:"data_types" json:"data_types"`
	FullOnDesync bool     `yaml:"full_sync_on_desync" json:"full_sync_on_desync"`
}

type UploadConfig struct {
	Enabled          bool            `yaml:"enabled" json:"enabled"`
	BatchSize        int             `yaml:"batch_size" json:"batch_size"`
	IntervalSecs     int             `yaml:"interval_secs" json:"interval_secs"`
	DataTypes        []string        `yaml:"data_types" json:"data_types"`
	AuditMode        bool            `yaml:"audit_mode" json:"audit_mode"`
	AutoApprovePaths []string        `yaml:"auto_approve_patterns" json:"auto_approve_patterns"`
	MaxBodyLength    int             `yaml:"max_body_length" json:"max_body_length"`
	Exclusions       ExclusionConfig `yaml:"exclusions" json:"exclusions"`
}

type RuleConfig struct {
	Priority        string `yaml:"priority" json:"priority"`
	IntelRulePrefix string `yaml:"intel_rule_prefix" json:"intel_rule_prefix"`
	OverrideEnabled bool   `yaml:"override_enabled" json:"override_enabled"`
}

type SensitiveFilterConfig struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Action         string   `yaml:"action" json:"action"`
	CustomPatterns []string `yaml:"custom_patterns" json:"custom_patterns"`
}

type OfflineConfig struct {
	AllowOffline       bool `yaml:"allow_offline" json:"allow_offline"`
	CacheRetentionDays int  `yaml:"cache_retention_days" json:"cache_retention_days"`
	MaxCacheAgeHours   int  `yaml:"max_cache_age_hours" json:"max_cache_age_hours"`
}

type AlertConfig struct {
	OnConnectionLost  bool `yaml:"on_connection_lost" json:"on_connection_lost"`
	OnSyncFailure     bool `yaml:"on_sync_failure" json:"on_sync_failure"`
	OnLicenseExpiring bool `yaml:"on_license_expiring" json:"on_license_expiring"`
	OnUploadFailure   bool `yaml:"on_upload_failure" json:"on_upload_failure"`
	OnEmergencyRule   bool `yaml:"on_emergency_rule" json:"on_emergency_rule"`
	FailureThreshold  int  `yaml:"failure_threshold" json:"failure_threshold"`
}

type ExclusionConfig struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Paths   []string `yaml:"paths" json:"paths"`
	IPs     []string `yaml:"ips" json:"ips"`
	Hosts   []string `yaml:"hosts" json:"hosts"`
}

func DefaultIntelConfig() *IntelConfig {
	return &IntelConfig{
		Enabled:        false,
		ServerURL:      "",
		ConnectTimeout: 10,
		RequestTimeout: 30,
		TLS: TLSConfig{
			InsecureSkipVerify: false,
		},
		Sync: SyncConfig{
			Enabled:      true,
			IntervalSecs: 3600,
			DataTypes:    []string{"ip_blacklist", "threat_signatures", "ua_rules", "path_rules", "bot_ips", "geoip"},
			FullOnDesync: true,
		},
		Upload: UploadConfig{
			Enabled:          true,
			BatchSize:        50,
			IntervalSecs:     300,
			DataTypes:        []string{"intercept_events", "false_positives"},
			AuditMode:        false,
			AutoApprovePaths: []string{},
			MaxBodyLength:    4096,
			Exclusions: ExclusionConfig{
				Enabled: false,
			},
		},
		Rule: RuleConfig{
			Priority:        "local_first",
			IntelRulePrefix: "intel-",
			OverrideEnabled: true,
		},
		SensitiveFilter: SensitiveFilterConfig{
			Enabled: true,
			Action:  "mask",
		},
		Offline: OfflineConfig{
			AllowOffline:       true,
			CacheRetentionDays: 7,
			MaxCacheAgeHours:   24,
		},
		Alerts: AlertConfig{
			OnConnectionLost:  true,
			OnSyncFailure:     true,
			OnLicenseExpiring: true,
			OnUploadFailure:   true,
			OnEmergencyRule:   true,
			FailureThreshold:  3,
		},
	}
}

func MergeIntelConfig(base, override *IntelConfig) *IntelConfig {
	if override == nil {
		return base
	}
	if base == nil {
		return override
	}
	merged := *base
	merged.Enabled = override.Enabled
	if override.ServerURL != "" {
		merged.ServerURL = override.ServerURL
	}
	if override.LicenseKey != "" {
		merged.LicenseKey = override.LicenseKey
	}
	if override.InstanceID != "" {
		merged.InstanceID = override.InstanceID
	}
	if override.ConnectTimeout != 0 {
		merged.ConnectTimeout = override.ConnectTimeout
	}
	if override.RequestTimeout != 0 {
		merged.RequestTimeout = override.RequestTimeout
	}
	if override.TLS.CACertPath != "" {
		merged.TLS.CACertPath = override.TLS.CACertPath
	}
	merged.TLS.InsecureSkipVerify = override.TLS.InsecureSkipVerify
	if override.Sync.IntervalSecs != 0 {
		merged.Sync.IntervalSecs = override.Sync.IntervalSecs
	}
	if len(override.Sync.DataTypes) > 0 {
		merged.Sync.DataTypes = override.Sync.DataTypes
	}
	merged.Sync.Enabled = override.Sync.Enabled
	merged.Sync.FullOnDesync = override.Sync.FullOnDesync
	merged.Upload.Enabled = override.Upload.Enabled
	merged.Upload.AuditMode = override.Upload.AuditMode
	if override.Upload.BatchSize != 0 {
		merged.Upload.BatchSize = override.Upload.BatchSize
	}
	if override.Upload.IntervalSecs != 0 {
		merged.Upload.IntervalSecs = override.Upload.IntervalSecs
	}
	if len(override.Upload.DataTypes) > 0 {
		merged.Upload.DataTypes = override.Upload.DataTypes
	}
	if len(override.Upload.AutoApprovePaths) > 0 {
		merged.Upload.AutoApprovePaths = override.Upload.AutoApprovePaths
	}
	if override.Upload.MaxBodyLength != 0 {
		merged.Upload.MaxBodyLength = override.Upload.MaxBodyLength
	}
	merged.Upload.Exclusions.Enabled = override.Upload.Exclusions.Enabled
	if len(override.Upload.Exclusions.Paths) > 0 {
		merged.Upload.Exclusions.Paths = override.Upload.Exclusions.Paths
	}
	if len(override.Upload.Exclusions.IPs) > 0 {
		merged.Upload.Exclusions.IPs = override.Upload.Exclusions.IPs
	}
	if len(override.Upload.Exclusions.Hosts) > 0 {
		merged.Upload.Exclusions.Hosts = override.Upload.Exclusions.Hosts
	}
	if override.Rule.Priority != "" {
		merged.Rule.Priority = override.Rule.Priority
	}
	if override.Rule.IntelRulePrefix != "" {
		merged.Rule.IntelRulePrefix = override.Rule.IntelRulePrefix
	}
	merged.Rule.OverrideEnabled = override.Rule.OverrideEnabled
	merged.SensitiveFilter.Enabled = override.SensitiveFilter.Enabled
	if override.SensitiveFilter.Action != "" {
		merged.SensitiveFilter.Action = override.SensitiveFilter.Action
	}
	if len(override.SensitiveFilter.CustomPatterns) > 0 {
		merged.SensitiveFilter.CustomPatterns = override.SensitiveFilter.CustomPatterns
	}
	merged.Offline.AllowOffline = override.Offline.AllowOffline
	if override.Offline.CacheRetentionDays != 0 {
		merged.Offline.CacheRetentionDays = override.Offline.CacheRetentionDays
	}
	if override.Offline.MaxCacheAgeHours != 0 {
		merged.Offline.MaxCacheAgeHours = override.Offline.MaxCacheAgeHours
	}
	merged.Alerts.OnConnectionLost = override.Alerts.OnConnectionLost
	merged.Alerts.OnSyncFailure = override.Alerts.OnSyncFailure
	merged.Alerts.OnLicenseExpiring = override.Alerts.OnLicenseExpiring
	merged.Alerts.OnUploadFailure = override.Alerts.OnUploadFailure
	merged.Alerts.OnEmergencyRule = override.Alerts.OnEmergencyRule
	if override.Alerts.FailureThreshold != 0 {
		merged.Alerts.FailureThreshold = override.Alerts.FailureThreshold
	}
	return &merged
}

var validPriorities = map[string]bool{
	"local_first": true,
	"intel_first": true,
	"merge":       true,
}

var validFilterActions = map[string]bool{
	"mask":   true,
	"reject": true,
	"warn":   true,
}

var validSyncDataTypes = map[string]bool{
	"ip_blacklist":      true,
	"threat_signatures": true,
	"ua_rules":          true,
	"path_rules":        true,
	"bot_ips":           true,
	"geoip":             true,
}

var validUploadDataTypes = map[string]bool{
	"intercept_events": true,
	"false_positives":  true,
}

func ValidateIntelConfig(cfg *IntelConfig) error {
	if !cfg.Enabled {
		return nil
	}

	if cfg.ServerURL == "" {
		return fmt.Errorf("intel.server_url is required when intel is enabled")
	}

	if !strings.HasPrefix(cfg.ServerURL, "https://") && !strings.HasPrefix(cfg.ServerURL, "http://") {
		return fmt.Errorf("intel.server_url must start with http:// or https://")
	}

	if !validPriorities[cfg.Rule.Priority] {
		return fmt.Errorf("intel.rule.priority must be one of: local_first, intel_first, merge")
	}

	if cfg.SensitiveFilter.Enabled && !validFilterActions[cfg.SensitiveFilter.Action] {
		return fmt.Errorf("intel.sensitive_filter.action must be one of: mask, reject, warn")
	}

	if cfg.ConnectTimeout <= 0 {
		return fmt.Errorf("intel.connect_timeout_secs must be positive")
	}

	if cfg.RequestTimeout <= 0 {
		return fmt.Errorf("intel.request_timeout_secs must be positive")
	}

	if cfg.Sync.IntervalSecs <= 0 {
		return fmt.Errorf("intel.sync.interval_secs must be positive")
	}

	if cfg.Upload.IntervalSecs <= 0 {
		return fmt.Errorf("intel.upload.interval_secs must be positive")
	}

	if cfg.Upload.BatchSize <= 0 {
		return fmt.Errorf("intel.upload.batch_size must be positive")
	}

	for _, dt := range cfg.Sync.DataTypes {
		if !validSyncDataTypes[dt] {
			return fmt.Errorf("intel.sync.data_types contains invalid type: %s", dt)
		}
	}

	for _, dt := range cfg.Upload.DataTypes {
		if !validUploadDataTypes[dt] {
			return fmt.Errorf("intel.upload.data_types contains invalid type: %s", dt)
		}
	}

	if cfg.Offline.CacheRetentionDays <= 0 {
		return fmt.Errorf("intel.offline.cache_retention_days must be positive")
	}

	if cfg.Alerts.FailureThreshold <= 0 {
		return fmt.Errorf("intel.alerts.failure_threshold must be positive")
	}

	return nil
}
