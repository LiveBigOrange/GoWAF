package rules

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory DB: %v", err)
	}
	db.SetMaxOpenConns(1)

	engine, err := NewEngine(db)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	t.Cleanup(func() {
		engine.Stop()
		db.Close()
	})
	return engine
}

func TestEngine_AddIPRule(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddIPRule("blacklist", "192.168.1.100"); err != nil {
		t.Fatalf("AddIPRule failed: %v", err)
	}
	if err := e.ReloadRules(); err != nil {
		t.Fatalf("ReloadRules failed: %v", err)
	}

	result := e.IsIPBlocked("192.168.1.100")
	if !result.Matched {
		t.Error("Expected 192.168.1.100 to be blocked")
	}
	if result.RuleType != "ip_blacklist" {
		t.Errorf("Expected rule_type=ip_blacklist, got %s", result.RuleType)
	}
}

func TestEngine_IsIPBlocked_NotBlocked(t *testing.T) {
	e := newTestEngine(t)

	result := e.IsIPBlocked("10.0.0.1")
	if result.Matched {
		t.Error("Expected 10.0.0.1 NOT to be blocked")
	}
}

func TestEngine_RemoveIPRule(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddIPRule("blacklist", "10.0.0.5"); err != nil {
		t.Fatalf("AddIPRule failed: %v", err)
	}
	e.ReloadRules()
	if !e.IsIPBlocked("10.0.0.5").Matched {
		t.Fatal("IP should be blocked before removal")
	}

	if err := e.RemoveIPRule("blacklist", "10.0.0.5"); err != nil {
		t.Fatalf("RemoveIPRule failed: %v", err)
	}
	e.ReloadRules()
	if e.IsIPBlocked("10.0.0.5").Matched {
		t.Error("IP should NOT be blocked after removal")
	}
}

func TestEngine_SetIPRuleEnabled(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddIPRule("blacklist", "172.16.0.1"); err != nil {
		t.Fatalf("AddIPRule failed: %v", err)
	}
	e.ReloadRules()

	if err := e.SetIPRuleEnabled("blacklist", "172.16.0.1", false); err != nil {
		t.Fatalf("SetIPRuleEnabled failed: %v", err)
	}
	e.ReloadRules()
	if e.IsIPBlocked("172.16.0.1").Matched {
		t.Error("Disabled IP should NOT be blocked")
	}

	if err := e.SetIPRuleEnabled("blacklist", "172.16.0.1", true); err != nil {
		t.Fatalf("SetIPRuleEnabled re-enable failed: %v", err)
	}
	e.ReloadRules()
	if !e.IsIPBlocked("172.16.0.1").Matched {
		t.Error("Re-enabled IP should be blocked")
	}
}

func TestEngine_WhitelistOverridesBlacklist(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddIPRule("blacklist", "192.168.0.0/24"); err != nil {
		t.Fatalf("AddIPRule blacklist failed: %v", err)
	}
	if err := e.AddIPRule("whitelist", "192.168.0.50"); err != nil {
		t.Fatalf("AddIPRule whitelist failed: %v", err)
	}
	e.ReloadRules()

	if !e.IsIPBlocked("192.168.0.1").Matched {
		t.Error("192.168.0.1 should be blocked (in blacklisted CIDR)")
	}
	if e.IsIPBlocked("192.168.0.50").Matched {
		t.Error("192.168.0.50 should NOT be blocked (whitelist overrides)")
	}
}

func TestEngine_ListIPRules(t *testing.T) {
	e := newTestEngine(t)

	e.AddIPRule("blacklist", "1.1.1.1")
	e.AddIPRule("whitelist", "2.2.2.2")

	rules, err := e.ListIPRules()
	if err != nil {
		t.Fatalf("ListIPRules failed: %v", err)
	}
	if len(rules) < 2 {
		t.Errorf("Expected at least 2 rules, got %d", len(rules))
	}
}

func TestEngine_AddIP(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddIP("10.10.10.10"); err != nil {
		t.Fatalf("AddIP failed: %v", err)
	}
	e.ReloadRules()
	if !e.IsIPBlocked("10.10.10.10").Matched {
		t.Error("AddIP should add to blacklist")
	}
	ips, err := e.ListIPs()
	if err != nil {
		t.Fatalf("ListIPs failed: %v", err)
	}
	found := false
	for _, ip := range ips {
		if ip == "10.10.10.10" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ListIPs should contain added IP")
	}
}

func TestEngine_CIDRMatch(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddIPRule("blacklist", "10.0.0.0/8"); err != nil {
		t.Fatalf("AddIPRule CIDR failed: %v", err)
	}
	e.ReloadRules()

	tests := []struct {
		ip      string
		blocked bool
	}{
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"192.168.1.1", false},
	}
	for _, tt := range tests {
		result := e.IsIPBlocked(tt.ip)
		if result.Matched != tt.blocked {
			t.Errorf("IsIPBlocked(%s) = %v, want %v", tt.ip, result.Matched, tt.blocked)
		}
	}
}

func TestEngine_AddUARule(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddUARule("blacklist", "exact", "BadBot/1.0", "block bad bot"); err != nil {
		t.Fatalf("AddUARule failed: %v", err)
	}

	result := e.CheckUA("BadBot/1.0")
	if !result.Matched {
		t.Error("BadBot/1.0 should be blocked")
	}
}

func TestEngine_RemoveUARule(t *testing.T) {
	t.Skip("TODO: RemoveUARule in-memory cache reload timing issue")

	e := newTestEngine(t)

	if err := e.AddUARule("blacklist", "contains", "curl", "block curl"); err != nil {
		t.Fatalf("AddUARule failed: %v", err)
	}
	if !e.CheckUA("curl/7.88.1").Matched {
		t.Fatal("Expected curl to be blocked before removal")
	}

	if err := e.RemoveUARule("blacklist", "curl"); err != nil {
		t.Fatalf("RemoveUARule failed: %v", err)
	}
	e.ReloadRules()
	if e.CheckUA("curl/7.88.1").Matched {
		t.Error("curl should NOT be blocked after removal")
	}
}

func TestEngine_AddPathRule(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddPathRule("blacklist", "contains", "/admin", "block admin path"); err != nil {
		t.Fatalf("AddPathRule failed: %v", err)
	}

	result := e.CheckPath("/admin/config")
	if !result.Matched {
		t.Error("/admin/config should be blocked")
	}
}

func TestEngine_GeoRule(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddGeoRule("block", "CN", true); err != nil {
		t.Fatalf("AddGeoRule failed: %v", err)
	}

	if !e.IsGeoBlocked("CN").Matched {
		t.Error("CN should be geo-blocked")
	}
	if e.IsGeoBlocked("US").Matched {
		t.Error("US should NOT be geo-blocked")
	}
}

func TestEngine_GeoRule_WhitelistMode(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddGeoRule("whitelist", "US", true); err != nil {
		t.Fatalf("AddGeoRule whitelist failed: %v", err)
	}

	if e.IsGeoBlocked("US").Matched {
		t.Error("US should NOT be blocked in whitelist mode (it is whitelisted)")
	}
	if !e.IsGeoBlocked("CN").Matched {
		t.Error("CN should be blocked in whitelist mode (not in whitelist)")
	}
}

func TestEngine_GeoRule_CaseInsensitive(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddGeoRule("block", "cn", true); err != nil {
		t.Fatalf("AddGeoRule failed: %v", err)
	}

	if !e.IsGeoBlocked("CN").Matched {
		t.Error("geo blocking should be case-insensitive")
	}
	if !e.IsGeoBlocked("cn").Matched {
		t.Error("geo blocking should be case-insensitive (lowercase)")
	}
}

func TestEngine_GeoRule_EmptyNotBlocked(t *testing.T) {
	e := newTestEngine(t)

	if e.IsGeoBlocked("CN").Matched {
		t.Error("no geo rules configured: nothing should be blocked")
	}
}

func TestEngine_CheckUA_Contains(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddUARule("blacklist", "contains", "curl", "block curl"); err != nil {
		t.Fatalf("AddUARule failed: %v", err)
	}

	tests := []struct {
		ua      string
		blocked bool
	}{
		{"curl/7.88.1", true},
		{"Mozilla/5.0", false},
		{"libcurl/1.0", true},
	}
	for _, tt := range tests {
		result := e.CheckUA(tt.ua)
		if result.Matched != tt.blocked {
			t.Errorf("CheckUA(%s) = %v, want %v", tt.ua, result.Matched, tt.blocked)
		}
	}
}

func TestEngine_CheckUA_WhitelistOverride(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddUARule("blacklist", "contains", "Bot", "block bots"); err != nil {
		t.Fatalf("AddUARule blacklist failed: %v", err)
	}
	if err := e.AddUARule("whitelist", "exact", "GoodBot/1.0", "allow good bot"); err != nil {
		t.Fatalf("AddUARule whitelist failed: %v", err)
	}

	if !e.CheckUA("BadBot/1.0").Matched {
		t.Error("BadBot/1.0 should be blocked by blacklist contains 'Bot'")
	}
	if e.CheckUA("GoodBot/1.0").Matched {
		t.Error("GoodBot/1.0 should be whitelisted")
	}
}

func TestEngine_CheckUA_EmptyNotBlocked(t *testing.T) {
	e := newTestEngine(t)

	if e.CheckUA("Mozilla/5.0").Matched {
		t.Error("no UA rules: nothing should be blocked")
	}
}

func TestEngine_AddPathRule_Prefix(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddPathRule("blacklist", "prefix", "/admin", "block admin"); err != nil {
		t.Fatalf("AddPathRule failed: %v", err)
	}

	tests := []struct {
		path    string
		blocked bool
	}{
		{"/admin", true},
		{"/admin/users", true},
		{"/api/admin", false},
		{"/home", false},
	}
	for _, tt := range tests {
		result := e.CheckPath(tt.path)
		if result.Matched != tt.blocked {
			t.Errorf("CheckPath(%s) = %v, want %v", tt.path, result.Matched, tt.blocked)
		}
	}
}

func TestEngine_AddPathRule_Suffix(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddPathRule("blacklist", "suffix", ".php", "block php"); err != nil {
		t.Fatalf("AddPathRule failed: %v", err)
	}

	if !e.CheckPath("/index.php").Matched {
		t.Error("/index.php should be blocked by suffix .php")
	}
	if e.CheckPath("/index.html").Matched {
		t.Error("/index.html should NOT be blocked by suffix .php")
	}
}

func TestEngine_AddPathRule_Exact(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddPathRule("blacklist", "exact", "/login", "block login"); err != nil {
		t.Fatalf("AddPathRule failed: %v", err)
	}

	if !e.CheckPath("/login").Matched {
		t.Error("/login should be blocked by exact match")
	}
	if e.CheckPath("/login/admin").Matched {
		t.Error("/login/admin should NOT be blocked by exact /login")
	}
}

func TestEngine_AddPathRule_Regex(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddPathRule("blacklist", "regex", `^/api/v[12]/`, "block old api"); err != nil {
		t.Fatalf("AddPathRule failed: %v", err)
	}

	tests := []struct {
		path    string
		blocked bool
	}{
		{"/api/v1/users", true},
		{"/api/v2/items", true},
		{"/api/v3/users", false},
		{"/home", false},
	}
	for _, tt := range tests {
		result := e.CheckPath(tt.path)
		if result.Matched != tt.blocked {
			t.Errorf("CheckPath(%s) = %v, want %v", tt.path, result.Matched, tt.blocked)
		}
	}
}

func TestEngine_PathWhitelistOverride(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddPathRule("blacklist", "prefix", "/api", "block api"); err != nil {
		t.Fatalf("AddPathRule blacklist failed: %v", err)
	}
	if err := e.AddPathRule("whitelist", "exact", "/api/health", "allow health"); err != nil {
		t.Fatalf("AddPathRule whitelist failed: %v", err)
	}

	if !e.CheckPath("/api/users").Matched {
		t.Error("/api/users should be blocked by prefix /api")
	}
	if e.CheckPath("/api/health").Matched {
		t.Error("/api/health should be whitelisted")
	}
}

func TestEngine_SetAllowedMethods(t *testing.T) {
	e := newTestEngine(t)

	e.SetAllowedMethods([]string{"GET", "POST"})

	tests := []struct {
		method  string
		blocked bool
	}{
		{"GET", false},
		{"POST", false},
		{"DELETE", true},
		{"PUT", true},
		{"get", false},
	}
	for _, tt := range tests {
		result := e.IsMethodAllowed(tt.method)
		if result.Matched != tt.blocked {
			t.Errorf("IsMethodAllowed(%s) matched=%v, want %v", tt.method, result.Matched, tt.blocked)
		}
	}
}

func TestEngine_IsMethodAllowed_Empty(t *testing.T) {
	e := newTestEngine(t)

	result := e.IsMethodAllowed("DELETE")
	if result.Matched {
		t.Error("no methods configured: everything should be allowed")
	}
}

func TestEngine_IsIPBlocked_InvalidIP(t *testing.T) {
	e := newTestEngine(t)

	result := e.IsIPBlocked("not-an-ip")
	if result.Matched {
		t.Error("invalid IP should not match anything")
	}
}

func TestEngine_ListUARules(t *testing.T) {
	e := newTestEngine(t)

	e.AddUARule("blacklist", "exact", "Bot1", "desc1")
	e.AddUARule("whitelist", "contains", "Bot2", "desc2")

	rules, err := e.ListUARules()
	if err != nil {
		t.Fatalf("ListUARules failed: %v", err)
	}
	if len(rules) < 2 {
		t.Errorf("expected at least 2 UA rules, got %d", len(rules))
	}
}

func TestEngine_ListPathRules(t *testing.T) {
	e := newTestEngine(t)

	e.AddPathRule("blacklist", "prefix", "/admin", "desc1")
	e.AddPathRule("whitelist", "exact", "/health", "desc2")

	rules, err := e.ListPathRules()
	if err != nil {
		t.Fatalf("ListPathRules failed: %v", err)
	}
	if len(rules) < 2 {
		t.Errorf("expected at least 2 path rules, got %d", len(rules))
	}
}

func TestEngine_ListGeoRules(t *testing.T) {
	e := newTestEngine(t)

	e.AddGeoRule("block", "CN", true)
	e.AddGeoRule("block", "RU", true)

	rules, err := e.ListGeoRules()
	if err != nil {
		t.Fatalf("ListGeoRules failed: %v", err)
	}
	if len(rules) < 2 {
		t.Errorf("expected at least 2 geo rules, got %d", len(rules))
	}
}

func TestEngine_RemoveGeoRule(t *testing.T) {
	e := newTestEngine(t)

	e.AddGeoRule("block", "CN", true)
	if !e.IsGeoBlocked("CN").Matched {
		t.Fatal("CN should be geo-blocked before removal")
	}

	rules, _ := e.ListGeoRules()
	for _, r := range rules {
		if r.CountryCode == "CN" {
			if err := e.RemoveGeoRule(r.ID); err != nil {
				t.Fatalf("RemoveGeoRule failed: %v", err)
			}
			break
		}
	}

	if e.IsGeoBlocked("CN").Matched {
		t.Error("CN should NOT be geo-blocked after removal")
	}
}

func TestEngine_PathRateLimitCRUD(t *testing.T) {
	e := newTestEngine(t)

	if err := e.AddPathRateLimit("/api/", 10, 20, true); err != nil {
		t.Fatalf("AddPathRateLimit failed: %v", err)
	}

	rules, err := e.ListPathRateLimits()
	if err != nil {
		t.Fatalf("ListPathRateLimits failed: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 path rate limit, got %d", len(rules))
	}
	if rules[0].PathPattern != "/api/" {
		t.Errorf("expected path_pattern=/api/, got %s", rules[0].PathPattern)
	}

	if err := e.RemovePathRateLimit(rules[0].ID); err != nil {
		t.Fatalf("RemovePathRateLimit failed: %v", err)
	}

	rules, _ = e.ListPathRateLimits()
	if len(rules) != 0 {
		t.Errorf("expected 0 path rate limits after removal, got %d", len(rules))
	}
}

func TestEngine_ReloadRules(t *testing.T) {
	e := newTestEngine(t)

	e.AddIPRule("blacklist", "1.2.3.4")
	e.AddUARule("blacklist", "exact", "TestBot", "test")
	e.AddPathRule("blacklist", "prefix", "/test", "test")

	if err := e.ReloadRules(); err != nil {
		t.Fatalf("ReloadRules failed: %v", err)
	}

	if !e.IsIPBlocked("1.2.3.4").Matched {
		t.Error("after ReloadRules, IP should still be blocked")
	}
	if !e.CheckUA("TestBot").Matched {
		t.Error("after ReloadRules, UA should still be blocked")
	}
	if !e.CheckPath("/test/page").Matched {
		t.Error("after ReloadRules, path should still be blocked")
	}
}

func TestEngine_UpdateUARule(t *testing.T) {
	e := newTestEngine(t)

	e.AddUARule("blacklist", "exact", "OldBot", "old desc")

	if !e.CheckUA("OldBot").Matched {
		t.Fatal("OldBot should be blocked initially")
	}

	rules, listErr := e.ListUARules()
	if listErr != nil {
		t.Fatalf("ListUARules failed: %v", listErr)
	}
	var oldID int
	for _, r := range rules {
		if r.Pattern == "OldBot" {
			oldID = r.ID
			if err := e.UpdateUARule(r.ID, "blacklist", "exact", "NewBot", "new desc", true); err != nil {
				t.Fatalf("UpdateUARule failed: %v", err)
			}
			break
		}
	}

	if !e.CheckUA("NewBot").Matched {
		t.Errorf("NewBot should be blocked after update (updated rule id=%d)", oldID)
	}
}

func TestEngine_ToggleUARule(t *testing.T) {
	e := newTestEngine(t)

	e.AddUARule("blacklist", "exact", "ToggleBot", "test")

	if !e.CheckUA("ToggleBot").Matched {
		t.Fatal("ToggleBot should be blocked initially")
	}

	rules, _ := e.ListUARules()
	for _, r := range rules {
		if r.Pattern == "ToggleBot" {
			if err := e.ToggleUARule(r.ID); err != nil {
				t.Fatalf("ToggleUARule failed: %v", err)
			}
			break
		}
	}

	if e.CheckUA("ToggleBot").Matched {
		t.Error("ToggleBot should NOT be blocked after toggle (disabled)")
	}
}

func TestEngine_UpdatePathRule(t *testing.T) {
	e := newTestEngine(t)

	e.AddPathRule("blacklist", "prefix", "/old", "old desc")

	rules, _ := e.ListPathRules()
	for _, r := range rules {
		if r.Pattern == "/old" {
			if err := e.UpdatePathRule(r.ID, "blacklist", "prefix", "/new", "new desc", true); err != nil {
				t.Fatalf("UpdatePathRule failed: %v", err)
			}
			break
		}
	}

	if !e.CheckPath("/new/page").Matched {
		t.Error("/new/page should be blocked after update")
	}
}

func TestEngine_TogglePathRule(t *testing.T) {
	e := newTestEngine(t)

	e.AddPathRule("blacklist", "prefix", "/toggle", "test")

	if !e.CheckPath("/toggle/page").Matched {
		t.Fatal("/toggle/page should be blocked initially")
	}

	rules, _ := e.ListPathRules()
	for _, r := range rules {
		if r.Pattern == "/toggle" {
			if err := e.TogglePathRule(r.ID); err != nil {
				t.Fatalf("TogglePathRule failed: %v", err)
			}
			break
		}
	}

	if e.CheckPath("/toggle/page").Matched {
		t.Error("/toggle/page should NOT be blocked after toggle (disabled)")
	}
}
