package config

import (
	"testing"
)

func TestMergeConfig(t *testing.T) {
	defaultCfg := GetDefaultRuntimeConfig()
	yamlCfg := &RuntimeConfig{}
	dbCfg := &RuntimeConfig{}

	merged := MergeConfig(defaultCfg, yamlCfg, dbCfg)
	if merged == nil {
		t.Fatal("MergeConfig should not return nil")
	}

	defaultSecurity := defaultCfg.Security
	mergedSecurity := merged.Security

	if mergedSecurity.Login.MaxAttempts != defaultSecurity.Login.MaxAttempts {
		t.Error("Default values should be preserved when no overrides")
	}
}

func TestMergeConfig_DatabaseOverrides(t *testing.T) {
	defaultCfg := GetDefaultRuntimeConfig()
	yamlCfg := &RuntimeConfig{}
	dbCfg := &RuntimeConfig{
		Security: SecurityConfig{
			Login: LoginSecurityConfig{
				MaxAttempts:   10,
				BlockDuration: 30,
			},
		},
	}

	merged := MergeConfig(defaultCfg, yamlCfg, dbCfg)
	if merged.Security.Login.MaxAttempts != 10 {
		t.Errorf("DB MaxAttempts should be 10, got %d", merged.Security.Login.MaxAttempts)
	}
	if merged.Security.Login.BlockDuration != 30 {
		t.Errorf("DB BlockDuration should be 30, got %d", merged.Security.Login.BlockDuration)
	}
}

func TestMergeConfig_YAMLOverrides(t *testing.T) {
	defaultCfg := GetDefaultRuntimeConfig()
	yamlCfg := &RuntimeConfig{
		Performance: PerformanceConfig{
			MaxRequestBody: 20,
		},
	}
	dbCfg := &RuntimeConfig{
		Performance: PerformanceConfig{
			MaxRequestBody: 50,
		},
	}

	merged := MergeConfig(defaultCfg, yamlCfg, dbCfg)
	if merged.Performance.MaxRequestBody != 50 {
		t.Errorf("DB config should take highest priority (50), got %d", merged.Performance.MaxRequestBody)
	}
}

func TestGetDefaultRuntimeConfig(t *testing.T) {
	cfg := GetDefaultRuntimeConfig()
	if cfg == nil {
		t.Fatal("GetDefaultRuntimeConfig should not return nil")
	}
	if cfg.Security.Login.MaxAttempts <= 0 {
		t.Error("Default MaxAttempts should be positive")
	}
	if cfg.Security.Login.BlockDuration <= 0 {
		t.Error("Default BlockDuration should be positive")
	}
	if cfg.Security.Session.TTL <= 0 {
		t.Error("Default Session TTL should be positive")
	}
	if cfg.Security.Session.AbsoluteTTL <= 0 {
		t.Error("Default AbsoluteTTL should be positive")
	}
}

func TestGetConfigPriority(t *testing.T) {
	priority := GetConfigPriority()
	if priority == "" {
		t.Error("GetConfigPriority should return non-empty string")
	}
}
