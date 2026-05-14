package config

import (
	"testing"
)

func TestDefaultIntelConfig(t *testing.T) {
	cfg := DefaultIntelConfig()
	if cfg.Enabled {
		t.Error("default Enabled should be false")
	}
	if cfg.ConnectTimeout != 10 {
		t.Errorf("default ConnectTimeout should be 10, got %d", cfg.ConnectTimeout)
	}
	if cfg.RequestTimeout != 30 {
		t.Errorf("default RequestTimeout should be 30, got %d", cfg.RequestTimeout)
	}
	if cfg.Rule.Priority != "local_first" {
		t.Errorf("default Rule.Priority should be local_first, got %s", cfg.Rule.Priority)
	}
	if cfg.Sync.IntervalSecs != 3600 {
		t.Errorf("default Sync.IntervalSecs should be 3600, got %d", cfg.Sync.IntervalSecs)
	}
	if cfg.Upload.BatchSize != 50 {
		t.Errorf("default Upload.BatchSize should be 50, got %d", cfg.Upload.BatchSize)
	}
	if cfg.SensitiveFilter.Action != "mask" {
		t.Errorf("default SensitiveFilter.Action should be mask, got %s", cfg.SensitiveFilter.Action)
	}
	if cfg.Offline.AllowOffline != true {
		t.Error("default Offline.AllowOffline should be true")
	}
}

func TestValidateIntelConfig_Disabled(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = false
	if err := ValidateIntelConfig(cfg); err != nil {
		t.Errorf("disabled config should not error, got: %v", err)
	}
}

func TestValidateIntelConfig_EnabledValid(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "https://intel.example.com"
	cfg.LicenseKey = "community_test-key"
	if err := ValidateIntelConfig(cfg); err != nil {
		t.Errorf("valid config should not error, got: %v", err)
	}
}

func TestValidateIntelConfig_MissingServerURL(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = ""
	cfg.LicenseKey = "community_test-key"
	if err := ValidateIntelConfig(cfg); err == nil {
		t.Error("should error when server_url is empty")
	}
}

func TestValidateIntelConfig_EmptyLicenseKeyAllowed(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "https://intel.example.com"
	cfg.LicenseKey = ""
	if err := ValidateIntelConfig(cfg); err != nil {
		t.Errorf("empty license_key should be allowed (loaded from db), got: %v", err)
	}
}

func TestValidateIntelConfig_InvalidServerURL(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "ftp://invalid"
	if err := ValidateIntelConfig(cfg); err == nil {
		t.Error("should error when server_url has invalid scheme")
	}
}

func TestValidateIntelConfig_InvalidPriority(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "https://intel.example.com"
	cfg.Rule.Priority = "invalid"
	if err := ValidateIntelConfig(cfg); err == nil {
		t.Error("should error when priority is invalid")
	}
}

func TestValidateIntelConfig_InvalidFilterAction(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "https://intel.example.com"
	cfg.SensitiveFilter.Enabled = true
	cfg.SensitiveFilter.Action = "delete"
	if err := ValidateIntelConfig(cfg); err == nil {
		t.Error("should error when filter action is invalid")
	}
}

func TestValidateIntelConfig_InvalidSyncDataType(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "https://intel.example.com"
	cfg.Sync.DataTypes = []string{"invalid_type"}
	if err := ValidateIntelConfig(cfg); err == nil {
		t.Error("should error when sync data type is invalid")
	}
}

func TestValidateIntelConfig_InvalidUploadDataType(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "https://intel.example.com"
	cfg.Upload.DataTypes = []string{"invalid_type"}
	if err := ValidateIntelConfig(cfg); err == nil {
		t.Error("should error when upload data type is invalid")
	}
}

func TestValidateIntelConfig_InvalidTimeouts(t *testing.T) {
	cfg := DefaultIntelConfig()
	cfg.Enabled = true
	cfg.ServerURL = "https://intel.example.com"
	cfg.LicenseKey = "community_test-key"
	cfg.ConnectTimeout = 0
	if err := ValidateIntelConfig(cfg); err == nil {
		t.Error("should error when connect_timeout is 0")
	}
}

func TestValidateIntelConfig_AllPriorities(t *testing.T) {
	for _, priority := range []string{"local_first", "intel_first", "merge"} {
		cfg := DefaultIntelConfig()
		cfg.Enabled = true
		cfg.ServerURL = "https://intel.example.com"
		cfg.LicenseKey = "community_test-key"
		cfg.Rule.Priority = priority
		if err := ValidateIntelConfig(cfg); err != nil {
			t.Errorf("priority %s should be valid, got: %v", priority, err)
		}
	}
}
