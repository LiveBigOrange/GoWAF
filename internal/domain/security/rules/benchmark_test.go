package rules

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func newBenchEngine(b *testing.B) *Engine {
	b.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		b.Fatalf("Failed to open in-memory DB: %v", err)
	}
	db.SetMaxOpenConns(1)

	engine, err := NewEngine(db)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}
	b.Cleanup(func() {
		engine.Stop()
		db.Close()
	})
	return engine
}

// ==================== IP 规则匹配 ====================

func BenchmarkRuleEngineMatchIP_ExactHit(b *testing.B) {
	e := newBenchEngine(b)
	for i := 0; i < 100; i++ {
		e.AddIPRule("blacklist", "192.168.1."+itoa(i))
	}
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsIPBlocked("192.168.1.50")
	}
}

func BenchmarkRuleEngineMatchIP_ExactMiss(b *testing.B) {
	e := newBenchEngine(b)
	for i := 0; i < 100; i++ {
		e.AddIPRule("blacklist", "10.0.0."+itoa(i))
	}
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsIPBlocked("192.168.1.1")
	}
}

func BenchmarkRuleEngineMatchIP_CIDRHit(b *testing.B) {
	e := newBenchEngine(b)
	e.AddIPRule("blacklist", "10.0.0.0/8")
	e.AddIPRule("blacklist", "172.16.0.0/12")
	e.AddIPRule("blacklist", "192.168.0.0/16")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsIPBlocked("10.1.2.3")
	}
}

func BenchmarkRuleEngineMatchIP_CIDRMiss(b *testing.B) {
	e := newBenchEngine(b)
	e.AddIPRule("blacklist", "10.0.0.0/8")
	e.AddIPRule("blacklist", "172.16.0.0/12")
	e.AddIPRule("blacklist", "192.168.0.0/16")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsIPBlocked("8.8.8.8")
	}
}

func BenchmarkRuleEngineMatchIP_WhitelistOverride(b *testing.B) {
	e := newBenchEngine(b)
	e.AddIPRule("blacklist", "192.168.0.0/24")
	e.AddIPRule("whitelist", "192.168.0.50")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsIPBlocked("192.168.0.50")
	}
}

func BenchmarkRuleEngineMatchIP_LargeBlacklist(b *testing.B) {
	e := newBenchEngine(b)
	for i := 0; i < 1000; i++ {
		e.AddIPRule("blacklist", "10.0."+itoa(i/256)+"."+itoa(i%256))
	}
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsIPBlocked("10.0.3.232")
	}
}

func BenchmarkRuleEngineMatchIP_InvalidIP(b *testing.B) {
	e := newBenchEngine(b)
	e.AddIPRule("blacklist", "192.168.1.1")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.IsIPBlocked("not-an-ip")
	}
}

// ==================== 路径规则匹配 ====================

func BenchmarkRuleEngineMatchPath_PrefixHit(b *testing.B) {
	e := newBenchEngine(b)
	e.AddPathRule("blacklist", "prefix", "/admin", "block admin")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckPath("/admin/users")
	}
}

func BenchmarkRuleEngineMatchPath_PrefixMiss(b *testing.B) {
	e := newBenchEngine(b)
	e.AddPathRule("blacklist", "prefix", "/admin", "block admin")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckPath("/api/users")
	}
}

func BenchmarkRuleEngineMatchPath_ExactHit(b *testing.B) {
	e := newBenchEngine(b)
	e.AddPathRule("blacklist", "exact", "/login", "block login")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckPath("/login")
	}
}

func BenchmarkRuleEngineMatchPath_ContainsHit(b *testing.B) {
	e := newBenchEngine(b)
	e.AddPathRule("blacklist", "contains", "/admin", "block admin")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckPath("/api/admin/config")
	}
}

func BenchmarkRuleEngineMatchPath_RegexHit(b *testing.B) {
	e := newBenchEngine(b)
	e.AddPathRule("blacklist", "regex", `^/api/v[12]/`, "block old api")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckPath("/api/v1/users")
	}
}

func BenchmarkRuleEngineMatchPath_MultipleRules(b *testing.B) {
	e := newBenchEngine(b)
	e.AddPathRule("blacklist", "prefix", "/admin", "block admin")
	e.AddPathRule("blacklist", "prefix", "/debug", "block debug")
	e.AddPathRule("blacklist", "exact", "/login", "block login")
	e.AddPathRule("blacklist", "regex", `^/api/v[12]/`, "block old api")
	e.AddPathRule("whitelist", "exact", "/admin/health", "allow health")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckPath("/api/v1/users")
	}
}

// ==================== UA 规则匹配 ====================

func BenchmarkRuleEngineMatchUA_ExactHit(b *testing.B) {
	e := newBenchEngine(b)
	e.AddUARule("blacklist", "exact", "BadBot/1.0", "block bad bot")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckUA("BadBot/1.0")
	}
}

func BenchmarkRuleEngineMatchUA_ContainsHit(b *testing.B) {
	e := newBenchEngine(b)
	e.AddUARule("blacklist", "contains", "curl", "block curl")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckUA("curl/7.88.1")
	}
}

func BenchmarkRuleEngineMatchUA_Miss(b *testing.B) {
	e := newBenchEngine(b)
	e.AddUARule("blacklist", "contains", "curl", "block curl")
	e.AddUARule("blacklist", "exact", "BadBot/1.0", "block bad bot")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckUA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	}
}

func BenchmarkRuleEngineMatchUA_MultipleRules(b *testing.B) {
	e := newBenchEngine(b)
	e.AddUARule("blacklist", "contains", "curl", "block curl")
	e.AddUARule("blacklist", "contains", "wget", "block wget")
	e.AddUARule("blacklist", "exact", "BadBot/1.0", "block bad bot")
	e.AddUARule("blacklist", "exact", "SQLMap/1.0", "block sqlmap")
	e.AddUARule("whitelist", "exact", "GoogleBot/2.1", "allow google")
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.CheckUA("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	}
}

// ==================== 快照加载 ====================

func BenchmarkRuleEngineSnapshotLoad(b *testing.B) {
	e := newBenchEngine(b)
	for i := 0; i < 50; i++ {
		e.AddIPRule("blacklist", "10.0.0."+itoa(i))
	}
	for i := 0; i < 20; i++ {
		e.AddUARule("blacklist", "contains", "bot"+itoa(i), "block bot")
	}
	for i := 0; i < 20; i++ {
		e.AddPathRule("blacklist", "prefix", "/path"+itoa(i), "block path")
	}
	e.ReloadRules()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		snap := e.loadSnapshot()
		_ = snap.blackIPExact
		_ = snap.uaBlacklist
		_ = snap.pathBlacklist
	}
}

// ==================== itoa 辅助函数 ====================

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	s := ""
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	return s
}
