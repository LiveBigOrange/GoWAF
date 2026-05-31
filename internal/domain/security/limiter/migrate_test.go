package limiter

import (
	"testing"

	"gowaf/internal/domain/security/ratelimit"
)

func TestMigrateToSmartLimit_NilInputs(t *testing.T) {
	t.Helper()
	err := MigrateToSmartLimit(nil, nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestMigrateToSmartLimit_DefaultConfig(t *testing.T) {
	t.Helper()
	l := NewIPRateLimiter(0, 0)
	cfg := ratelimit.DefaultConfig()
	smartEngine := ratelimit.NewEngine(cfg)

	err := MigrateToSmartLimit(l, smartEngine)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestMigrateToSmartLimit_NormalConfig(t *testing.T) {
	t.Helper()
	l := NewIPRateLimiter(100, 200)
	cfg := ratelimit.DefaultConfig()
	smartEngine := ratelimit.NewEngine(cfg)

	err := MigrateToSmartLimit(l, smartEngine)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	migratedCfg := smartEngine.GetConfig()
	if migratedCfg.IPRequestThreshold != 100 {
		t.Errorf("IPRequestThreshold = %d, want 100", migratedCfg.IPRequestThreshold)
	}
	expectedBlock := int64(float64(200) / float64(100) * 2)
	if migratedCfg.IPBlockThreshold != expectedBlock {
		t.Errorf("IPBlockThreshold = %d, want %d", migratedCfg.IPBlockThreshold, expectedBlock)
	}
}

func TestMigrateToSmartLimit_NilSmartEngine(t *testing.T) {
	t.Helper()
	l := NewIPRateLimiter(100, 200)
	err := MigrateToSmartLimit(l, nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}
