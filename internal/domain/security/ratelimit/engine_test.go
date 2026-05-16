package ratelimit

import "testing"

func TestEngine_New(t *testing.T) {
	cfg := &Config{
		Enabled:            true,
		Mode:               "intercept",
		WindowSize:         60,
		SubIntervalMs:      1000,
		IPRequestThreshold: 100,
		IPBlockThreshold:   10,
		BlockThreshold:     0.8,
		ChallengeThreshold: 0.5,
		ThrottleThreshold:  0.3,
		WhitelistIPs:       []string{},
	}

	engine := NewEngine(cfg)
	if engine == nil {
		t.Fatal("NewEngine should return a valid engine")
	}
	if engine.GetConfig() == nil {
		t.Fatal("Engine should have config")
	}
}

func TestEngine_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	engine := NewEngine(cfg)

	req := RequestInfo{
		IP:     "192.168.1.1",
		Method: "GET",
		Path:   "/api/test",
	}
	decision := engine.Evaluate(req)
	if decision.Action == Block {
		t.Error("Disabled engine should not block")
	}
}

func TestEngine_BasicProfile(t *testing.T) {
	cfg := &Config{
		Enabled:            true,
		Mode:               "observe",
		WindowSize:         60,
		SubIntervalMs:      1000,
		IPRequestThreshold: 1000,
		IPBlockThreshold:   100,
		BlockThreshold:     0.99,
		ChallengeThreshold: 0.99,
		ThrottleThreshold:  0.99,
	}
	engine := NewEngine(cfg)

	req := RequestInfo{
		IP:        "10.0.0.1",
		Method:    "GET",
		Path:      "/api/health",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36",
	}
	for i := 0; i < 50; i++ {
		_ = engine.Evaluate(req)
	}
}

func TestEngine_WhitelistIP(t *testing.T) {
	cfg := &Config{
		Enabled:            true,
		Mode:               "intercept",
		WindowSize:         60,
		IPRequestThreshold: 1,
		BlockThreshold:     0.01,
		WhitelistIPs:       []string{"10.0.0.99"},
	}
	engine := NewEngine(cfg)

	req := RequestInfo{
		IP:     "10.0.0.99",
		Method: "GET",
		Path:   "/api/test",
	}
	decision := engine.Evaluate(req)
	if decision.Action == Block {
		t.Error("Whitelisted IP should not be blocked")
	}
}

func TestEngine_WhitelistCIDR(t *testing.T) {
	cfg := &Config{
		Enabled:            true,
		Mode:               "intercept",
		WindowSize:         60,
		IPRequestThreshold: 1,
		BlockThreshold:     0.01,
		WhitelistIPs:       []string{"192.168.0.0/16"},
	}
	engine := NewEngine(cfg)

	req := RequestInfo{
		IP:     "192.168.1.100",
		Method: "GET",
		Path:   "/api/test",
	}
	decision := engine.Evaluate(req)
	if decision.Action == Block {
		t.Error("CIDR whitelisted IP should not be blocked")
	}
}

func TestBuildFingerprintFromRequest(t *testing.T) {
	fp := BuildFingerprintFromRequest(
		"Mozilla/5.0 (Windows NT 10.0)",
		"en-US,en;q=0.9",
		"gzip, deflate",
		"Chrome",
		"Windows",
		"?1",
	)
	if fp == "" {
		t.Error("Fingerprint should not be empty")
	}
}
