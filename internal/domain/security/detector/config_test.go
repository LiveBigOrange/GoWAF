package detector

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("打开内存数据库失败: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func newTestConfigManager(t *testing.T) *ConfigManager {
	t.Helper()
	db := newTestDB(t)
	cm, err := NewConfigManager(db)
	if err != nil {
		t.Fatalf("创建ConfigManager失败: %v", err)
	}
	return cm
}

func TestConfigManager_UpdateConfig_ObservationMode(t *testing.T) {
	cm := newTestConfigManager(t)

	err := cm.UpdateConfig("xss", true, true, "", "", "medium")
	if err != nil {
		t.Fatalf("UpdateConfig失败: %v", err)
	}

	cfg, err := cm.GetConfig("xss")
	if err != nil {
		t.Fatalf("GetConfig失败: %v", err)
	}

	if !cfg.ObservationMode {
		t.Error("observation_mode 应为 true")
	}
	if !cfg.Enabled {
		t.Error("enabled 应为 true")
	}
}

func TestConfigManager_UpdateConfig_ObservationModeFalse(t *testing.T) {
	cm := newTestConfigManager(t)

	err := cm.UpdateConfig("xss", true, true, "", "", "medium")
	if err != nil {
		t.Fatalf("UpdateConfig失败: %v", err)
	}

	err = cm.UpdateConfig("xss", true, false, "", "", "medium")
	if err != nil {
		t.Fatalf("UpdateConfig失败: %v", err)
	}

	cfg, err := cm.GetConfig("xss")
	if err != nil {
		t.Fatalf("GetConfig失败: %v", err)
	}

	if cfg.ObservationMode {
		t.Error("observation_mode 应为 false")
	}
}

func TestConfigManager_UpdateConfig_AllFields(t *testing.T) {
	cm := newTestConfigManager(t)

	err := cm.UpdateConfig("sql_injection", false, true, "1.2.3.4,5.6.7.8", "/api/,/health", "high")
	if err != nil {
		t.Fatalf("UpdateConfig失败: %v", err)
	}

	cfg, err := cm.GetConfig("sql_injection")
	if err != nil {
		t.Fatalf("GetConfig失败: %v", err)
	}

	if cfg.Enabled {
		t.Error("enabled 应为 false")
	}
	if !cfg.ObservationMode {
		t.Error("observation_mode 应为 true")
	}
	if cfg.WhitelistIPs != "1.2.3.4,5.6.7.8" {
		t.Errorf("whitelist_ips 不匹配: got %q", cfg.WhitelistIPs)
	}
	if cfg.WhitelistPaths != "/api/,/health" {
		t.Errorf("whitelist_paths 不匹配: got %q", cfg.WhitelistPaths)
	}
	if cfg.SensitivityLevel != "high" {
		t.Errorf("sensitivity_level 不匹配: got %q", cfg.SensitivityLevel)
	}
}

func TestConfigManager_GetConfig_ObservationModeDefault(t *testing.T) {
	cm := newTestConfigManager(t)

	cfg, err := cm.GetConfig("sql_injection")
	if err != nil {
		t.Fatalf("GetConfig失败: %v", err)
	}

	if cfg.ObservationMode {
		t.Error("新建配置的 observation_mode 应默认为 false")
	}
}

func TestConfigManager_ListConfigs_ObservationMode(t *testing.T) {
	cm := newTestConfigManager(t)

	err := cm.UpdateConfig("xss", true, true, "", "", "medium")
	if err != nil {
		t.Fatalf("UpdateConfig失败: %v", err)
	}

	configs, err := cm.ListConfigs()
	if err != nil {
		t.Fatalf("ListConfigs失败: %v", err)
	}

	xssFound := false
	for _, cfg := range configs {
		if cfg.DetectorType == "xss" {
			xssFound = true
			if !cfg.ObservationMode {
				t.Error("xss 的 observation_mode 应为 true")
			}
		}
	}
	if !xssFound {
		t.Error("ListConfigs 应包含 xss 配置")
	}
}

func TestConfigManager_SetEnabled_NoAffectObservationMode(t *testing.T) {
	cm := newTestConfigManager(t)

	err := cm.UpdateConfig("xss", true, true, "", "", "medium")
	if err != nil {
		t.Fatalf("UpdateConfig失败: %v", err)
	}

	err = cm.SetEnabled("xss", false)
	if err != nil {
		t.Fatalf("SetEnabled失败: %v", err)
	}

	cfg, err := cm.GetConfig("xss")
	if err != nil {
		t.Fatalf("GetConfig失败: %v", err)
	}

	if cfg.Enabled {
		t.Error("enabled 应为 false")
	}
	if !cfg.ObservationMode {
		t.Error("SetEnabled 不应修改 observation_mode，应为 true")
	}
}
