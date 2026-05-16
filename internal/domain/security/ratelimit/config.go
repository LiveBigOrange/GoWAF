package ratelimit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Config struct {
	mu sync.RWMutex

	Enabled            bool   `json:"enabled"`
	Mode               string `json:"mode"`
	WindowSize         int    `json:"window_size"`
	SubIntervalMs      int64  `json:"sub_interval_ms"`
	MaxSamples         int    `json:"max_samples"`
	ProfileMaxAgeSec   int64  `json:"profile_max_age_sec"`
	CleanupIntervalSec int64  `json:"cleanup_interval_sec"`

	IPRequestThreshold     int64 `json:"ip_request_threshold"`
	IPBlockThreshold       int64 `json:"ip_block_threshold"`
	PathDivMax             int   `json:"path_div_max"`
	UADivMax               int   `json:"ua_div_max"`
	RuleDivMax             int   `json:"rule_div_max"`
	SensitivePathThreshold int64 `json:"sensitive_path_threshold"`
	GlobalQPSThreshold     int64 `json:"global_qps_threshold"`

	W_RequestRate    float64 `json:"w_request_rate"`
	W_BlockRate      float64 `json:"w_block_rate"`
	W_ErrorRatio     float64 `json:"w_error_ratio"`
	W_PathDiv        float64 `json:"w_path_div"`
	W_RuleDiv        float64 `json:"w_rule_div"`
	W_UADiv          float64 `json:"w_ua_div"`
	W_IntervalVar    float64 `json:"w_interval_var"`
	W_SensitivePath  float64 `json:"w_sensitive_path"`
	W_GeoAnomaly     float64 `json:"w_geo_anomaly"`
	W_CookieAnomaly  float64 `json:"w_cookie_anomaly"`
	W_MethodAnomaly  float64 `json:"w_method_anomaly"`
	W_RefererAnomaly float64 `json:"w_referer_anomaly"`
	W_BodyAnomaly    float64 `json:"w_body_anomaly"`

	BlockThreshold     float64 `json:"block_threshold"`
	ChallengeThreshold float64 `json:"challenge_threshold"`
	ThrottleThreshold  float64 `json:"throttle_threshold"`

	ErrorRatioThreshold     float64 `json:"error_ratio_threshold"`
	PathDivThreshold        int     `json:"path_div_threshold"`
	UADivThreshold          int     `json:"ua_div_threshold"`
	RuleDivThreshold        int     `json:"rule_div_threshold"`
	IntervalVarMin          float64 `json:"interval_var_min"`
	SensitivePathHitLimit   int64   `json:"sensitive_path_hit_limit"`
	MethodDivThreshold      int     `json:"method_div_threshold"`
	NoCookieRatioThreshold  float64 `json:"no_cookie_ratio_threshold"`
	NoRefererRatioThreshold float64 `json:"no_referer_ratio_threshold"`
	BodySizeThreshold       int64   `json:"body_size_threshold"`
	ASNChangeThreshold      int     `json:"asn_change_threshold"`

	AdaptiveEnabled bool    `json:"adaptive_enabled"`
	Sensitivity     float64 `json:"sensitivity"`
	BaselineWindow  int     `json:"baseline_window"`

	AutoWeightEnabled  bool    `json:"auto_weight_enabled"`
	WeightLearningRate float64 `json:"weight_learning_rate"`
	DynamicBaselinePct float64 `json:"dynamic_baseline_pct"`

	FingerprintEnabled          bool `json:"fingerprint_enabled"`
	FingerprintSuspectThreshold int  `json:"fingerprint_suspect_threshold"`

	AttackChainEnabled bool    `json:"attack_chain_enabled"`
	AttackChainWeight  float64 `json:"attack_chain_weight"`

	FalsePositiveRepair bool `json:"false_positive_repair"`
	AutoPardonEnabled   bool `json:"auto_pardon_enabled"`

	HourProfileEnabled bool    `json:"hour_profile_enabled"`
	HourAnomalyWeight  float64 `json:"hour_anomaly_weight"`

	AutoBlockEnabled     bool  `json:"auto_block_enabled"`
	AutoBlockThreshold   int   `json:"auto_block_threshold"`
	AutoBlockDurationSec int64 `json:"auto_block_duration_sec"`

	WhitelistIPs []string `json:"whitelist_ips"`

	PersistPath string `json:"-"`

	persistSaver func() error `json:"-"`
}

func (c *Config) SubInterval() time.Duration {
	return time.Duration(c.SubIntervalMs) * time.Millisecond
}
func (c *Config) ProfileMaxAge() time.Duration {
	return time.Duration(c.ProfileMaxAgeSec) * time.Second
}
func (c *Config) CleanupInterval() time.Duration {
	return time.Duration(c.CleanupIntervalSec) * time.Second
}
func (c *Config) AutoBlockDuration() time.Duration {
	return time.Duration(c.AutoBlockDurationSec) * time.Second
}

func DefaultConfig() *Config {
	return &Config{
		Enabled:                     true,
		Mode:                        "intercept",
		WindowSize:                  60,
		SubIntervalMs:               1000,
		MaxSamples:                  100,
		ProfileMaxAgeSec:            1800,
		CleanupIntervalSec:          300,
		IPRequestThreshold:          100,
		IPBlockThreshold:            10,
		PathDivMax:                  100,
		UADivMax:                    20,
		RuleDivMax:                  30,
		SensitivePathThreshold:      5,
		GlobalQPSThreshold:          5000,
		W_RequestRate:               0.20,
		W_BlockRate:                 0.15,
		W_ErrorRatio:                0.12,
		W_PathDiv:                   0.12,
		W_RuleDiv:                   0.08,
		W_UADiv:                     0.06,
		W_IntervalVar:               0.03,
		W_SensitivePath:             0.04,
		W_GeoAnomaly:                0.05,
		W_CookieAnomaly:             0.04,
		W_MethodAnomaly:             0.03,
		W_RefererAnomaly:            0.03,
		W_BodyAnomaly:               0.05,
		BlockThreshold:              0.8,
		ChallengeThreshold:          0.5,
		ThrottleThreshold:           0.3,
		ErrorRatioThreshold:         0.5,
		PathDivThreshold:            50,
		UADivThreshold:              3,
		RuleDivThreshold:            5,
		IntervalVarMin:              0.001,
		SensitivePathHitLimit:       3,
		MethodDivThreshold:          4,
		NoCookieRatioThreshold:      0.8,
		NoRefererRatioThreshold:     0.8,
		BodySizeThreshold:           1048576,
		ASNChangeThreshold:          2,
		AdaptiveEnabled:             true,
		Sensitivity:                 2.0,
		BaselineWindow:              7,
		AutoWeightEnabled:           true,
		WeightLearningRate:          0.05,
		DynamicBaselinePct:          95.0,
		FingerprintEnabled:          true,
		FingerprintSuspectThreshold: 20,
		AttackChainEnabled:          true,
		AttackChainWeight:           0.08,
		FalsePositiveRepair:         true,
		AutoPardonEnabled:           true,
		HourProfileEnabled:          true,
		HourAnomalyWeight:           0.04,
		AutoBlockEnabled:            true,
		AutoBlockThreshold:          3,
		AutoBlockDurationSec:        600,
	}
}

func (c *Config) GetEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Enabled
}

func (c *Config) GetMode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.Mode == "" {
		return "intercept"
	}
	return c.Mode
}

func (c *Config) Clone() *Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return &Config{
		Enabled:                     c.Enabled,
		Mode:                        c.Mode,
		WindowSize:                  c.WindowSize,
		SubIntervalMs:               c.SubIntervalMs,
		MaxSamples:                  c.MaxSamples,
		ProfileMaxAgeSec:            c.ProfileMaxAgeSec,
		CleanupIntervalSec:          c.CleanupIntervalSec,
		IPRequestThreshold:          c.IPRequestThreshold,
		IPBlockThreshold:            c.IPBlockThreshold,
		PathDivMax:                  c.PathDivMax,
		UADivMax:                    c.UADivMax,
		RuleDivMax:                  c.RuleDivMax,
		SensitivePathThreshold:      c.SensitivePathThreshold,
		GlobalQPSThreshold:          c.GlobalQPSThreshold,
		W_RequestRate:               c.W_RequestRate,
		W_BlockRate:                 c.W_BlockRate,
		W_ErrorRatio:                c.W_ErrorRatio,
		W_PathDiv:                   c.W_PathDiv,
		W_RuleDiv:                   c.W_RuleDiv,
		W_UADiv:                     c.W_UADiv,
		W_IntervalVar:               c.W_IntervalVar,
		W_SensitivePath:             c.W_SensitivePath,
		W_GeoAnomaly:                c.W_GeoAnomaly,
		W_CookieAnomaly:             c.W_CookieAnomaly,
		W_MethodAnomaly:             c.W_MethodAnomaly,
		W_RefererAnomaly:            c.W_RefererAnomaly,
		W_BodyAnomaly:               c.W_BodyAnomaly,
		BlockThreshold:              c.BlockThreshold,
		ChallengeThreshold:          c.ChallengeThreshold,
		ThrottleThreshold:           c.ThrottleThreshold,
		ErrorRatioThreshold:         c.ErrorRatioThreshold,
		PathDivThreshold:            c.PathDivThreshold,
		UADivThreshold:              c.UADivThreshold,
		RuleDivThreshold:            c.RuleDivThreshold,
		IntervalVarMin:              c.IntervalVarMin,
		SensitivePathHitLimit:       c.SensitivePathHitLimit,
		MethodDivThreshold:          c.MethodDivThreshold,
		NoCookieRatioThreshold:      c.NoCookieRatioThreshold,
		NoRefererRatioThreshold:     c.NoRefererRatioThreshold,
		BodySizeThreshold:           c.BodySizeThreshold,
		ASNChangeThreshold:          c.ASNChangeThreshold,
		AdaptiveEnabled:             c.AdaptiveEnabled,
		Sensitivity:                 c.Sensitivity,
		BaselineWindow:              c.BaselineWindow,
		AutoWeightEnabled:           c.AutoWeightEnabled,
		WeightLearningRate:          c.WeightLearningRate,
		DynamicBaselinePct:          c.DynamicBaselinePct,
		FingerprintEnabled:          c.FingerprintEnabled,
		FingerprintSuspectThreshold: c.FingerprintSuspectThreshold,
		AttackChainEnabled:          c.AttackChainEnabled,
		AttackChainWeight:           c.AttackChainWeight,
		FalsePositiveRepair:         c.FalsePositiveRepair,
		AutoPardonEnabled:           c.AutoPardonEnabled,
		HourProfileEnabled:          c.HourProfileEnabled,
		HourAnomalyWeight:           c.HourAnomalyWeight,
		AutoBlockEnabled:            c.AutoBlockEnabled,
		AutoBlockThreshold:          c.AutoBlockThreshold,
		AutoBlockDurationSec:        c.AutoBlockDurationSec,
		WhitelistIPs:                append([]string(nil), c.WhitelistIPs...),
		PersistPath:                 c.PersistPath,
	}
}

func (c *Config) SaveToFile() error {
	if c.persistSaver != nil {
		if err := c.persistSaver(); err != nil {
			return err
		}
	}
	if c.PersistPath == "" {
		return nil
	}
	c.mu.RLock()
	data, err := json.MarshalIndent(c, "", "  ")
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(c.PersistPath, data, 0600)
}

// SetPersistSaver 设置持久化保存回调，用于将配置保存到数据库
func (c *Config) SetPersistSaver(saver func() error) {
	c.persistSaver = saver
}

// MarshalJSONSafe 线程安全地序列化配置为 JSON
func (c *Config) MarshalJSONSafe() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(c)
}

func LoadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.PersistPath = path
	return &cfg, nil
}
