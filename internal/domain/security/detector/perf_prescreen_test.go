package detector

import (
	"strings"
	"testing"
)

func TestPreScreenRiskChars_Equivalence(t *testing.T) {
	inputs := []string{
		"",
		"hello world",
		"1' OR 1=1--",
		"<script>alert(1)</script>",
		"|cat /etc/passwd",
		"../../../etc/passwd",
		"foo\r\nbar",
		"'; <script>|`cat`",
		"'",
		"..",
		"javascript:alert(1)",
		"normal text without special chars",
		"SELECT * FROM users WHERE id=1",
		"$(whoami)",
		"abc\rdef",
		"abc\ndef",
		"\\windows\\system32",
		"/etc/shadow",
		"&lt;img&gt;",
		";rm -rf /",
		"onmouseover=alert(1)",
		"`id`",
		"$HOME",
		"test\ntest",
		"User-Agent: test\r\nHost: evil",
		"....//....//etc/passwd",
	}

	for _, input := range inputs {
		lower := strings.ToLower(input)

		origSQL := strings.ContainsAny(input, "'\";()-=*/\\")
		origXSS := strings.ContainsAny(input, "<>&\"'") || strings.ContainsAny(lower, "javascript:on")
		origCMD := strings.ContainsAny(input, ";|`$&><\n")
		origPath := strings.Contains(input, "..") || strings.ContainsAny(lower, "/etc\\windows")
		origHeader := strings.ContainsAny(input, "\r\n")

		got := preScreenRiskChars(input, lower)

		if got.hasRisk(riskSQL) != origSQL {
			t.Errorf("input=%q: riskSQL got=%v want=%v", input, got.hasRisk(riskSQL), origSQL)
		}
		if got.hasRisk(riskXSS) != origXSS {
			t.Errorf("input=%q: riskXSS got=%v want=%v", input, got.hasRisk(riskXSS), origXSS)
		}
		if got.hasRisk(riskCMD) != origCMD {
			t.Errorf("input=%q: riskCMD got=%v want=%v", input, got.hasRisk(riskCMD), origCMD)
		}
		if got.hasRisk(riskPath) != origPath {
			t.Errorf("input=%q: riskPath got=%v want=%v", input, got.hasRisk(riskPath), origPath)
		}
		if got.hasRisk(riskHeader) != origHeader {
			t.Errorf("input=%q: riskHeader got=%v want=%v", input, got.hasRisk(riskHeader), origHeader)
		}
	}
}

func TestPreScreenRiskChars_Empty(t *testing.T) {
	got := preScreenRiskChars("", "")
	if got.hasAnyRisk() {
		t.Errorf("expected no risk for empty, got flags=%05b", got)
	}
}

func TestPreScreenRiskChars_AllFlagsSet(t *testing.T) {
	input := "'; <script>|`cat`\r\n.."
	lower := strings.ToLower(input)
	got := preScreenRiskChars(input, lower)
	if !got.hasRisk(riskSQL) {
		t.Error("expected riskSQL")
	}
	if !got.hasRisk(riskXSS) {
		t.Error("expected riskXSS")
	}
	if !got.hasRisk(riskCMD) {
		t.Error("expected riskCMD")
	}
	if !got.hasRisk(riskPath) {
		t.Error("expected riskPath")
	}
	if !got.hasRisk(riskHeader) {
		t.Error("expected riskHeader")
	}
}

func TestPreScreenRiskChars_EarlyExit(t *testing.T) {
	input := "'; <script>|`cat`\r\n..aaaaaaaaaaaaaaaaaaaa"
	lower := strings.ToLower(input)
	got := preScreenRiskChars(input, lower)
	if got != riskAll {
		t.Errorf("expected all flags set, got %05b", got)
	}
}

func TestPreScreenRiskChars_SingleChars(t *testing.T) {
	tests := []struct {
		char byte
		sql  bool
		xss  bool
		cmd  bool
		path bool
		hdr  bool
	}{
		{'\'', true, true, false, false, false},
		{'"', true, true, false, false, false},
		{';', true, false, true, false, false},
		{'(', true, false, false, false, false},
		{')', true, false, false, false, false},
		{'-', true, false, false, false, false},
		{'=', true, false, false, false, false},
		{'*', true, false, false, false, false},
		{'/', true, false, false, true, false},
		{'\\', true, false, false, true, false},
		{'<', false, true, true, false, false},
		{'>', false, true, true, false, false},
		{'&', false, true, true, false, false},
		{'|', false, false, true, false, false},
		{'`', false, false, true, false, false},
		{'$', false, false, true, false, false},
		{'\n', false, false, true, false, true},
		{'\r', false, false, false, false, true},
	}
	for _, tt := range tests {
		input := string([]byte{tt.char})
		lower := strings.ToLower(input)
		got := preScreenRiskChars(input, lower)
		if got.hasRisk(riskSQL) != tt.sql {
			t.Errorf("char=%q: riskSQL got=%v want=%v", tt.char, got.hasRisk(riskSQL), tt.sql)
		}
		if got.hasRisk(riskXSS) != tt.xss {
			t.Errorf("char=%q: riskXSS got=%v want=%v", tt.char, got.hasRisk(riskXSS), tt.xss)
		}
		if got.hasRisk(riskCMD) != tt.cmd {
			t.Errorf("char=%q: riskCMD got=%v want=%v", tt.char, got.hasRisk(riskCMD), tt.cmd)
		}
		if got.hasRisk(riskPath) != tt.path {
			t.Errorf("char=%q: riskPath got=%v want=%v", tt.char, got.hasRisk(riskPath), tt.path)
		}
		if got.hasRisk(riskHeader) != tt.hdr {
			t.Errorf("char=%q: riskHeader got=%v want=%v", tt.char, got.hasRisk(riskHeader), tt.hdr)
		}
	}
}

func TestPreScreenRiskChars_DotDot(t *testing.T) {
	input := ".."
	lower := strings.ToLower(input)
	got := preScreenRiskChars(input, lower)
	if !got.hasRisk(riskPath) {
		t.Errorf("expected riskPath for '..', got flags=%05b", got)
	}
}

func BenchmarkPreScreenRiskChars(b *testing.B) {
	input := "GET /api/users?id=1'+OR+1=1--&name=<script>alert(1)</script>|`cat` HTTP/1.1\r\nHost: example.com"
	lower := strings.ToLower(input)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		preScreenRiskChars(input, lower)
	}
}

func BenchmarkOriginalContainsAny(b *testing.B) {
	input := "GET /api/users?id=1'+OR+1=1--&name=<script>alert(1)</script>|`cat` HTTP/1.1\r\nHost: example.com"
	lower := strings.ToLower(input)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = strings.ContainsAny(input, "'\";()-=*/\\")
		_ = strings.ContainsAny(input, "<>&\"'") || strings.ContainsAny(lower, "javascript:on")
		_ = strings.ContainsAny(input, ";|`$&><\n")
		_ = strings.Contains(input, "..") || strings.ContainsAny(lower, "/etc\\windows")
		_ = strings.ContainsAny(input, "\r\n")
	}
}
